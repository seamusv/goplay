package jwt

import (
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

type TokenExtractor func() (string, error)

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
