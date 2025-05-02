// Package jwt provides JWT authentication functionality that can be used as middleware
// in different web frameworks or as a standalone token validator.
package jwt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OpenIDConfig represents the OpenID Connect configuration
type OpenIDConfig struct {
	JWKSURI string `json:"jwks_uri"`
}

// JWK represents JSON Web Key structure
type JWK struct {
	Keys []struct {
		Kid string   `json:"kid"`
		X5c []string `json:"x5c"`
	} `json:"keys"`
}

// Authenticator handles JWT authentication with caching and configurable options
type Authenticator struct {
	openIDConfigURL   string
	jwksCache         *JWK
	jwksURI           string
	cacheExpiresAt    time.Time
	cacheDuration     time.Duration
	tokenHeaderName   string
	tokenHeaderPrefix []string
	userClaimField    string
	mutex             sync.RWMutex
	httpClient        *http.Client
}

// Options contains configuration options for the JWT authenticator
type Options struct {
	OpenIDConfigURL   string
	CacheDuration     time.Duration
	TokenHeaderName   string
	TokenHeaderPrefix []string
	UserClaimField    string
	HTTPClient        *http.Client
}

// DefaultOptions returns sensible default options
func DefaultOptions() Options {
	return Options{
		CacheDuration:     time.Minute * 30,
		TokenHeaderName:   "Authorization",
		TokenHeaderPrefix: []string{"Bearer", "Token"},
		UserClaimField:    "unique_name",
		HTTPClient:        &http.Client{Timeout: time.Second * 10},
	}
}

// NewAuthenticator creates a new Authenticator with the given options
func NewAuthenticator(options Options) (*Authenticator, error) {
	if options.OpenIDConfigURL == "" {
		return nil, errors.New("OpenIDConfigURL is required")
	}

	if options.CacheDuration == 0 {
		options.CacheDuration = DefaultOptions().CacheDuration
	}

	if options.TokenHeaderName == "" {
		options.TokenHeaderName = DefaultOptions().TokenHeaderName
	}

	if len(options.TokenHeaderPrefix) == 0 {
		options.TokenHeaderPrefix = DefaultOptions().TokenHeaderPrefix
	}

	if options.UserClaimField == "" {
		options.UserClaimField = DefaultOptions().UserClaimField
	}

	if options.HTTPClient == nil {
		options.HTTPClient = DefaultOptions().HTTPClient
	}

	return &Authenticator{
		openIDConfigURL:   options.OpenIDConfigURL,
		cacheDuration:     options.CacheDuration,
		tokenHeaderName:   options.TokenHeaderName,
		tokenHeaderPrefix: options.TokenHeaderPrefix,
		userClaimField:    options.UserClaimField,
		httpClient:        options.HTTPClient,
	}, nil
}

// ExtractUserFromToken extracts the user identifier from a JWT token without middleware
func (a *Authenticator) ExtractUserFromToken(tokenString string) (string, error) {
	claims, err := a.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	if userID, ok := claims[a.userClaimField]; ok {
		if userStr, ok := userID.(string); ok {
			return userStr, nil
		}
		return "", errors.New("user claim is not a string")
	}
	return "", errors.New("user claim not found in token")
}

// HandleAuthentication is a generic HTTP middleware handler that can be adapted to different frameworks
func (a *Authenticator) HandleAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from header
		tokenString, err := a.extractTokenFromHeader(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Validate token and extract claims
		claims, err := a.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Token verification failed: "+err.Error(), http.StatusForbidden)
			return
		}

		// Set user identity in context
		if userID, ok := claims[a.userClaimField]; ok {
			ctx := r.Context()
			ctx = WithUserID(ctx, fmt.Sprintf("%v", userID))
			ctx = WithClaims(ctx, claims)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateToken validates a JWT token and returns its claims
func (a *Authenticator) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Get JWKS (with caching)
	jwkSet, err := a.getJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Try to validate with any of the keys
	var lastErr error
	for _, key := range jwkSet.Keys {
		if len(key.X5c) == 0 {
			continue
		}
		pemCert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", key.X5c[0])
		parsedKey, err := parsePublicKeyFromCert(pemCert)
		if err != nil {
			lastErr = err
			continue
		}

		parsedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return parsedKey, nil
		})

		if err == nil && parsedToken.Valid {
			return parsedToken.Claims.(jwt.MapClaims), nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no valid keys found in JWKS")
}

// extractTokenFromHeader extracts the token from the authorization header
func (a *Authenticator) extractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get(a.tokenHeaderName)
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}

	for _, prefix := range a.tokenHeaderPrefix {
		prefixWithSpace := prefix + " "
		if strings.HasPrefix(authHeader, prefixWithSpace) {
			return strings.TrimPrefix(authHeader, prefixWithSpace), nil
		}
	}

	return "", errors.New("invalid authorization header format")
}

// getJWKS retrieves the JSON Web Key Set, using cache if available
func (a *Authenticator) getJWKS() (*JWK, error) {
	a.mutex.RLock()
	if a.jwksCache != nil && time.Now().Before(a.cacheExpiresAt) {
		jwks := a.jwksCache
		a.mutex.RUnlock()
		return jwks, nil
	}
	a.mutex.RUnlock()

	// Cache expired or not initialized, need to fetch
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Double-check if another goroutine updated the cache
	if a.jwksCache != nil && time.Now().Before(a.cacheExpiresAt) {
		return a.jwksCache, nil
	}

	// Fetch JWKS URI if needed
	if a.jwksURI == "" {
		uri, err := a.fetchJWKSURI()
		if err != nil {
			return nil, err
		}
		a.jwksURI = uri
	}

	// Fetch JWKS
	jwks, err := a.fetchJWKS()
	if err != nil {
		return nil, err
	}

	// Update cache
	a.jwksCache = jwks
	a.cacheExpiresAt = time.Now().Add(a.cacheDuration)
	return jwks, nil
}

// fetchJWKSURI fetches the JWKS URI from the OpenID config
func (a *Authenticator) fetchJWKSURI() (string, error) {
	resp, err := a.httpClient.Get(a.openIDConfigURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OpenID config: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OpenID config response: %w", err)
	}

	var config OpenIDConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to parse OpenID config: %w", err)
	}

	if config.JWKSURI == "" {
		return "", errors.New("JWKS URI not found in OpenID config")
	}

	return config.JWKSURI, nil
}

// fetchJWKS fetches the JWKS from the JWKS URI
func (a *Authenticator) fetchJWKS() (*JWK, error) {
	resp, err := a.httpClient.Get(a.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwk JWK
	if err := json.Unmarshal(body, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwk, nil
}

// parsePublicKeyFromCert parses a public key from a PEM certificate
func parsePublicKeyFromCert(certPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}
