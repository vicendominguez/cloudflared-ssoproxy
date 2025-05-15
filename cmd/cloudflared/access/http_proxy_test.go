package access

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/cloudflare/cloudflared/carrier"
	"github.com/cloudflare/cloudflared/token"
)

// Mock function for token retrieval
var originalGetOrRefreshToken func(options *carrier.StartOptions, log *zerolog.Logger) (string, error)

func init() {
	originalGetOrRefreshToken = getOrRefreshToken
}

func TestCreateHTTPProxy(t *testing.T) {
	// Create a test logger
	log := zerolog.Nop()

	// Create a mock origin server
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the request has the access token header
		token := r.Header.Get(carrier.CFAccessTokenHeader)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		// Check if custom headers were passed through
		customHeader := r.Header.Get("X-Custom-Header")
		if customHeader != "test-value" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer originServer.Close()

	// Parse the origin URL
	originURL, err := url.Parse(originServer.URL)
	assert.NoError(t, err)

	// Create mock app info
	appInfo := &token.AppInfo{
		AuthDomain: originURL.Host,
		AppDomain: originURL.Host,
		AppAUD: originURL.Host,
	}

	// Set up headers
	headers := http.Header{}
	headers.Set("X-Custom-Header", "test-value")

	// Create options for the proxy
	options := &carrier.StartOptions{
		AppInfo:   appInfo,
		OriginURL: originURL.String(),
		Headers:   headers,
		Host:      originURL.Host,
	}

	// Mock the token retrieval function
	getOrRefreshToken = func(options *carrier.StartOptions, log *zerolog.Logger) (string, error) {
		return "mock-token", nil
	}
	defer func() {
		getOrRefreshToken = originalGetOrRefreshToken
	}()

	// Create the HTTP proxy
	proxy := createHTTPProxy(options, &log)
	assert.NotNil(t, proxy)

	// Create a test request
	req := httptest.NewRequest("GET", "http://localhost:8080/test", nil)
	
	// Create a recorder to capture the response
	recorder := httptest.NewRecorder()
	
	// Process the request through the proxy
	proxy.ServeHTTP(recorder, req)
	
	// Check the response
	resp := recorder.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestGetOrRefreshToken(t *testing.T) {
	// This test would require mocking the token package functions
	// which is beyond the scope of this implementation
	t.Skip("Skipping token refresh test as it requires mocking token package")
}
