package access

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"

	"github.com/cloudflare/cloudflared/carrier"
	"github.com/cloudflare/cloudflared/logger"
	"github.com/cloudflare/cloudflared/token"
)

const (
	httpProxyTimeout = 30 * time.Second
)

// Variable to allow mocking in tests
var getOrRefreshToken = func(options *carrier.StartOptions, log *zerolog.Logger) (string, error) {
	// Try to get the existing token
	tok, err := token.GetAppTokenIfExists(options.AppInfo)
	if err != nil || tok == "" {
		// If no token exists or there was an error, fetch a new one
		originURL, err := url.Parse(options.OriginURL)
		if err != nil {
			return "", errors.Wrap(err, "failed to parse origin URL")
		}
		tok, err = token.FetchTokenWithRedirect(originURL, options.AppInfo, log)
		if err != nil {
			return "", errors.Wrap(err, "failed to fetch token")
		}
	}
	return tok, nil
}

// httpsProxyHandler implements both HTTP reverse proxy and HTTPS tunneling
type httpsProxyHandler struct {
	httpProxy  *httputil.ReverseProxy
	transport  *http.Transport
	log        *zerolog.Logger
	options    *carrier.StartOptions
}

func (h *httpsProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleTunneling(w, r)
	} else {
		h.httpProxy.ServeHTTP(w, r)
	}
}

func (h *httpsProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	// Parse the destination host from the CONNECT request
	destConn, err := h.transport.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		h.log.Err(err).Str("host", r.Host).Msg("Failed to connect to destination")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Get the token for authentication
	token, err := getOrRefreshToken(h.options, h.log)
	if err != nil {
		h.log.Err(err).Msg("Failed to get access token")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Add the token to the destination connection
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		// For TCP connections, we can set the token as a header
		if err := tcpConn.SetKeepAlive(true); err != nil {
			h.log.Err(err).Msg("Failed to set keepalive")
		}
		if err := tcpConn.SetKeepAlivePeriod(3 * time.Minute); err != nil {
			h.log.Err(err).Msg("Failed to set keepalive period")
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.log.Error().Msg("HTTP server does not support hijacking")
		http.Error(w, "HTTP server does not support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.log.Err(err).Msg("Failed to hijack connection")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send the token in the initial CONNECT response headers
	_, err = clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 Connection Established\r\n"+
		"Cf-Access-Token: %s\r\n"+
		"\r\n", token)))
	if err != nil {
		h.log.Err(err).Msg("Failed to write response headers")
		clientConn.Close()
		return
	}

	go transfer(destConn, clientConn, h.log)
	go transfer(clientConn, destConn, h.log)
}

func transfer(destination io.WriteCloser, source io.ReadCloser, log *zerolog.Logger) {
	defer func() {
		destination.Close()
		source.Close()
	}()

	_, err := io.Copy(destination, source)
	if err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Err(err).Msg("Error copying data between connections")
		}
	}
}

// httpProxy starts an HTTP proxy server that adds authentication tokens to requests
func httpProxy(c *cli.Context) error {
	log := logger.CreateLoggerFromContext(c, logger.EnableTerminalLog)

	// Get the hostname from the cmdline and error out if it's not provided
	rawHostName := c.String(sshHostnameFlag)
	if rawHostName == "" {
		log.Error().Msg("Please provide the hostname of the Access application using --hostname")
		return cli.ShowCommandHelp(c, "http")
	}

	// Parse the destination URL
	originURL, err := parseURL(rawHostName)
	if err != nil {
		log.Err(err).Msg("Invalid hostname provided")
		return err
	}

	// Get the local URL to listen on
	localURLStr := c.String(sshURLFlag)
	if localURLStr == "" {
		log.Error().Msg("Please provide the local URL to listen on using --url")
		return cli.ShowCommandHelp(c, "http")
	}

	localURL, err := url.Parse(localURLStr)
	if err != nil {
		log.Err(err).Msg("Invalid local URL provided")
		return err
	}

	// Ensure the local URL has a host component
	if localURL.Host == "" {
		log.Error().Msg("Local URL must include a host and port (e.g., localhost:8080)")
		return errors.New("invalid local URL")
	}

	// Get the app info for token retrieval
	appInfo, err := token.GetAppInfo(originURL)
	if err != nil {
		log.Err(err).Msg("Failed to get application info")
		return err
	}

	// Parse request headers from command line
	headers := parseRequestHeaders(c.StringSlice(sshHeaderFlag))
	if c.IsSet(sshTokenIDFlag) {
		headers.Set(cfAccessClientIDHeader, c.String(sshTokenIDFlag))
	}
	if c.IsSet(sshTokenSecretFlag) {
		headers.Set(cfAccessClientSecretHeader, c.String(sshTokenSecretFlag))
	}
	headers.Set("User-Agent", userAgent)

	// Set up the proxy options
	options := &carrier.StartOptions{
		AppInfo:   appInfo,
		OriginURL: originURL.String(),
		Headers:   headers,
		Host:      originURL.Host,
	}

	// Create the proxy server
	proxy := createHTTPProxy(options, log)

	// Start the proxy server
	log.Info().
		Str("local_url", localURL.Host).
		Str("remote_url", originURL.String()).
		Msg("Starting HTTP proxy server")

	server := &http.Server{
		Addr:         localURL.Host,
		Handler:      proxy,
		ReadTimeout:  httpProxyTimeout,
		WriteTimeout: httpProxyTimeout,
	}

	// Listen for shutdown signal
	go func() {
		<-shutdownC
		log.Info().Msg("Shutting down HTTP proxy server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	// Start the server
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Err(err).Msg("HTTP proxy server failed")
		return err
	}

	return nil
}

// createHTTPProxy creates a reverse proxy that adds authentication tokens to requests
func createHTTPProxy(options *carrier.StartOptions, log *zerolog.Logger) http.Handler {
	director := func(req *http.Request) {
		// Get the token for the application
		token, err := getOrRefreshToken(options, log)
		if err != nil {
			log.Err(err).Msg("Failed to get access token")
			return
		}

		// Parse the target URL
		targetURL, err := url.Parse(options.OriginURL)
		if err != nil {
			log.Err(err).Msg("Failed to parse origin URL")
			return
		}

		// Update the request to be forwarded to the target
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host

		// Preserve the path and query from the original request
		if targetURL.Path != "" && targetURL.Path != "/" {
			// If the target URL has a path, prepend it to the request path
			if !strings.HasSuffix(targetURL.Path, "/") {
				req.URL.Path = targetURL.Path + req.URL.Path
			} else {
				// Handle case where target path ends with / and request path starts with /
				if strings.HasPrefix(req.URL.Path, "/") {
					req.URL.Path = targetURL.Path + req.URL.Path[1:]
				} else {
					req.URL.Path = targetURL.Path + req.URL.Path
				}
			}
		}

		// Add the authentication token to the request
		req.Header.Set(carrier.CFAccessTokenHeader, token)

		// Add any custom headers
		for k, v := range options.Headers {
			if len(v) >= 1 {
				req.Header.Set(k, v[0])
			}
		}

		// Log the proxied request
		log.Debug().
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Msg("Proxying request")
	}

	// Create a custom transport with reasonable timeouts
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create a handler that can handle both CONNECT tunnels and HTTP requests
	return &httpsProxyHandler{
		httpProxy: &httputil.ReverseProxy{
			Director:  director,
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Err(err).
					Str("method", r.Method).
					Str("url", r.URL.String()).
					Msg("Proxy error")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, fmt.Sprintf("Proxy error: %v", err))
			},
		},
		transport: transport,
		log:       log,
		options:   options,
	}
}
