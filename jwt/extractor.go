package jwt

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// TokenExtractor is a function that extracts a JWT token from an HTTP request.
type TokenExtractor func() (string, error)

// AuthHeaderTokenExtractor extracts a JWT token from the Authorization header.
// It expects the header format to be "Bearer {token}".
// Returns an empty string if no Authorization header is present (not an error).
func AuthHeaderTokenExtractor(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no JWT.
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// CookieTokenExtractor extracts a JWT token from a named cookie.
// Returns the cookie value if found, or an error if the cookie doesn't exist.
func CookieTokenExtractor(cookieName string, r *http.Request) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", err
	}

	if cookie != nil {
		return cookie.Value, nil
	}

	return "", nil
}
