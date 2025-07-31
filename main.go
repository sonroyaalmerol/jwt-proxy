package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTProxy struct {
	target    *url.URL
	proxy     *httputil.ReverseProxy
	jwtSecret []byte
}

type Claims struct {
	Username string `json:"username,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Email    string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

func NewJWTProxy(target string, jwtSecret string) (*JWTProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	proxy := &JWTProxy{
		target:    url,
		jwtSecret: []byte(jwtSecret),
	}

	proxy.proxy = httputil.NewSingleHostReverseProxy(url)
	proxy.proxy.Director = proxy.director
	proxy.proxy.ModifyResponse = proxy.modifyResponse
	proxy.proxy.ErrorHandler = proxy.errorHandler

	return proxy, nil
}

func (p *JWTProxy) director(req *http.Request) {
	// Extract JWT from Authorization header
	authHeader := req.Header.Get("Authorization")
	username := ""

	if authHeader != "" {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			tokenString = authHeader
		}

		var err error
		username, err = p.extractUsernameFromJWT(tokenString)
		if err != nil {
			log.Printf("JWT validation failed for %s: %v", req.URL.Path, err)
			// Don't return here - let the request continue without REMOTE_USER
		}
	}

	// Preserve the original request URL path and query parameters
	originalPath := req.URL.Path
	originalRawQuery := req.URL.RawQuery
	originalFragment := req.URL.Fragment

	// Set target URL
	req.URL.Scheme = p.target.Scheme
	req.URL.Host = p.target.Host
	req.Host = p.target.Host

	// Preserve original path and query
	req.URL.Path = originalPath
	req.URL.RawQuery = originalRawQuery
	req.URL.Fragment = originalFragment

	// Add REMOTE_USER headers only if we successfully extracted username
	if username != "" {
		req.Header.Set("X-Remote-User", username)
		req.Header.Set("Remote-User", username)
		log.Printf("Forwarding request for user: %s to %s%s",
			username, req.URL.Host, req.URL.Path)
	} else {
		log.Printf("Forwarding request (no valid user) to %s%s",
			req.URL.Host, req.URL.Path)
	}

	// Preserve all original headers (they're already copied by ReverseProxy)
	// Just ensure we don't override any existing headers except our auth ones

	// Preserve original request method, body, etc. (handled automatically by ReverseProxy)

	// Log all forwarded headers for debugging (remove in production)
	if os.Getenv("DEBUG") == "true" {
		log.Printf("Forwarding headers:")
		for name, values := range req.Header {
			for _, value := range values {
				log.Printf("  %s: %s", name, value)
			}
		}
	}
}

func (p *JWTProxy) modifyResponse(resp *http.Response) error {
	// Forward all response headers transparently
	// This is already handled by ReverseProxy, but we can add custom logic here if needed

	if os.Getenv("DEBUG") == "true" {
		log.Printf("Response status: %d", resp.StatusCode)
		log.Printf("Response headers:")
		for name, values := range resp.Header {
			for _, value := range values {
				log.Printf("  %s: %s", name, value)
			}
		}
	}

	return nil
}

func (p *JWTProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("Proxy error for %s: %v", r.URL.Path, err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func (p *JWTProxy) extractUsernameFromJWT(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v",
					token.Header["alg"])
			}
			return p.jwtSecret, nil
		})

	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", fmt.Errorf("invalid claims type")
	}

	username := ""
	if claims.Username != "" {
		username = claims.Username
	} else if claims.Sub != "" {
		username = claims.Sub
	} else if claims.Email != "" {
		username = claims.Email
	} else {
		return "", fmt.Errorf("no username found in JWT claims")
	}

	return username, nil
}

func (p *JWTProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Don't require Authorization header - make it optional
	// This allows the proxy to be truly transparent for non-authenticated requests

	if os.Getenv("DEBUG") == "true" {
		log.Printf("Incoming request: %s %s", r.Method, r.URL.Path)
		log.Printf("Incoming headers:")
		for name, values := range r.Header {
			for _, value := range values {
				log.Printf("  %s: %s", name, value)
			}
		}
	}

	p.proxy.ServeHTTP(w, r)
}

// Health check endpoint
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://localhost:8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":3000"
	}

	proxy, err := NewJWTProxy(targetURL, jwtSecret)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Create a custom handler that checks for health endpoint first
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthCheck(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("JWT Proxy server starting on %s", listenAddr)
	log.Printf("Forwarding to: %s", targetURL)
	log.Printf("Debug mode: %s", os.Getenv("DEBUG"))
	log.Fatal(server.ListenAndServe())
}
