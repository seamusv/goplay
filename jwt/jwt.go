// Package jwt implements a stateful JWT authentication system with separate access and refresh tokens.
//
// This package provides a dual-token authentication system:
//   - Short-lived access tokens (15min default) with embedded user claims
//   - Long-lived refresh tokens (30 days default) with random NanoID keys
//
// Refresh tokens are stateful and stored via the ReadWriter interface, linking to a claim key
// used to rebuild user claims. This allows revoking refresh tokens without invalidating
// the underlying user session.
package jwt

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/pkg/errors"
)

// ClaimFunc is a function that retrieves user claims based on a claim key.
// It's used to build claims when creating tokens and to rebuild claims when exchanging refresh tokens.
type ClaimFunc = func(ctx context.Context, key string) (Claims, error)

// Authoriser manages JWT token creation, parsing, exchange, verification, and revocation.
// It uses HMAC-SHA512 for token signing and supports configurable expiry times.
type Authoriser struct {
	rw            ReadWriter
	secretHmac    []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewAuthoriser creates a new JWT authoriser with the given ReadWriter and HMAC secret.
// Default expiry times are 15 minutes for access tokens and 30 days for refresh tokens.
// These can be customized using the WithAccessExpiry and WithRefreshExpiry options.
//
// The secretHmac must be non-empty and should be at least 32 bytes for adequate security.
// Returns an error if validation fails.
func NewAuthoriser(rw ReadWriter, secretHmac []byte, options ...Option) (*Authoriser, error) {
	if rw == nil {
		return nil, errors.New("ReadWriter cannot be nil")
	}

	if len(secretHmac) == 0 {
		return nil, errors.New("secretHmac cannot be empty")
	}

	if len(secretHmac) < 32 {
		return nil, errors.New("secretHmac should be at least 32 bytes for adequate security")
	}

	a := &Authoriser{
		rw:            rw,
		secretHmac:    secretHmac,
		accessExpiry:  15 * time.Minute,
		refreshExpiry: 30 * 24 * time.Hour,
	}

	for _, option := range options {
		option(a)
	}

	return a, nil
}

// CreateParams contains parameters for token creation.
type CreateParams struct {
	AccessExpiry    time.Duration
	RefreshExpiry   time.Duration
	GenerateRefresh bool
}

// CreateOption configures token creation parameters.
type CreateOption func(*CreateParams)

// Create generates a new token pair (access and refresh tokens) for the given claim key.
// The claimFunc is used to retrieve user claims that will be embedded in the access token.
// By default, both access and refresh tokens are generated, but this can be customized
// using CreateOption parameters.
func (a *Authoriser) Create(ctx context.Context, claimKey string, claimFunc ClaimFunc, opt ...CreateOption) (*Token, error) {
	params := &CreateParams{
		AccessExpiry:    a.accessExpiry,
		RefreshExpiry:   a.refreshExpiry,
		GenerateRefresh: true,
	}

	for _, o := range opt {
		o(params)
	}

	res := &Token{}

	if params.GenerateRefresh {
		refresh, err := a.generateRefreshToken(ctx, claimKey, params.RefreshExpiry)
		if err != nil {
			return nil, err
		}
		res.Refresh = *refresh
	}

	userClaims, err := claimFunc(ctx, claimKey)
	if err != nil {
		return nil, errors.Wrap(err, "building user claims")
	}

	access, err := a.generateAccessToken(userClaims, params.AccessExpiry)
	if err != nil {
		return nil, err
	}
	res.Access = *access

	return res, nil
}

// Parse extracts and validates user claims from an access token.
// Returns the Data field containing user claims, not the full JWT claims.
func (a *Authoriser) Parse(tokenStr string) (Claims, error) {
	token, err := a.parse(tokenStr)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.Errorf("unexpected claims type, got=%T", token.Claims)
	}

	// Extract the Data field which contains the actual user claims
	data, ok := claims["Data"]
	if !ok {
		return nil, errors.New("missing 'Data' field in token claims")
	}

	userClaims, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.Errorf("'Data' field must be map[string]interface{}, got=%T", data)
	}

	return userClaims, nil
}

// Exchange swaps a valid refresh token for a new token pair.
// The old refresh token is revoked and a new refresh token is issued.
// The claimFunc is used to rebuild user claims for the new access token.
func (a *Authoriser) Exchange(ctx context.Context, tokenStr string, claimFunc ClaimFunc) (*Token, error) {
	refreshKey, err := a.extractSubject(tokenStr)
	if err != nil {
		return nil, err
	}

	claimValue, err := a.rw.ReadToken(ctx, refreshKey)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve refresh token")
	}

	authClaims, err := claimFunc(ctx, claimValue)
	if err != nil {
		return nil, errors.Wrap(err, "unable to rebuild claims")
	}

	if err := a.rw.RevokeToken(ctx, refreshKey); err != nil {
		return nil, errors.Wrap(err, "unable to revoke refresh token")
	}

	res := &Token{}

	refresh, err := a.generateRefreshToken(ctx, claimValue, a.refreshExpiry)
	if err != nil {
		return nil, err
	}
	res.Refresh = *refresh

	access, err := a.generateAccessToken(authClaims, a.accessExpiry)
	if err != nil {
		return nil, err
	}
	res.Access = *access

	return res, nil
}

// Revoke invalidates a refresh token and calls the provided callback function with the claim value.
// The callback function can be used to perform additional cleanup operations (e.g., logging, audit trail).
// The refresh token is removed from storage after the callback executes successfully.
func (a *Authoriser) Revoke(ctx context.Context, tokenStr string, fn func(claimValue string) error) error {
	refreshKey, err := a.extractSubject(tokenStr)
	if err != nil {
		return err
	}

	claimValue, err := a.rw.ReadToken(ctx, refreshKey)
	if err != nil {
		return errors.Wrap(err, "unable to retrieve refresh token")
	}

	if err := fn(claimValue); err != nil {
		return errors.Wrap(err, "unable to revoke refresh token")
	}

	return a.rw.RevokeToken(ctx, refreshKey)
}

// Verify validates a refresh token by checking it exists in storage and can retrieve valid claims.
// The claimFunc is called with the claim key to verify the user still exists and is valid.
func (a *Authoriser) Verify(ctx context.Context, tokenStr string, claimFunc ClaimFunc) error {
	key, err := a.extractSubject(tokenStr)
	if err != nil {
		return err
	}

	claimKey, err := a.rw.ReadToken(ctx, key)
	if err != nil {
		return errors.Wrap(err, "unable to retrieve refresh token")
	}

	_, err = claimFunc(ctx, claimKey)
	return err
}

func (a *Authoriser) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(a.secretHmac)
}

func (a *Authoriser) parse(value string) (*jwt.Token, error) {
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected token signing method: %v", token.Header["alg"])
		}
		return a.secretHmac, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

// generateRefreshToken creates a new refresh token with a random NanoID key
func (a *Authoriser) generateRefreshToken(ctx context.Context, claimKey string, expiry time.Duration) (*Authorisation, error) {
	key, err := gonanoid.New(12)
	if err != nil {
		return nil, errors.Wrap(err, "generating refresh token")
	}

	tokenExpiry := time.Now().Add(expiry)
	claims := jwt.RegisteredClaims{
		Subject:   key,
		ExpiresAt: jwt.NewNumericDate(tokenExpiry),
	}

	signed, err := a.sign(claims)
	if err != nil {
		return nil, errors.Wrap(err, "signing refresh token")
	}

	if err := a.rw.WriteToken(ctx, key, claimKey, tokenExpiry.Sub(time.Now())); err != nil {
		return nil, errors.Wrap(err, "storing refresh token")
	}

	return &Authorisation{
		Token:  signed,
		Expiry: tokenExpiry,
	}, nil
}

// generateAccessToken creates a new access token with embedded user claims
func (a *Authoriser) generateAccessToken(userClaims Claims, expiry time.Duration) (*Authorisation, error) {
	tokenExpiry := time.Now().Add(expiry)
	claims := jwtClaims{
		Data: userClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(tokenExpiry),
		},
	}

	signed, err := a.sign(claims)
	if err != nil {
		return nil, errors.Wrap(err, "signing access token")
	}

	return &Authorisation{
		Token:  signed,
		Expiry: tokenExpiry,
	}, nil
}

// extractSubject extracts and validates the 'sub' claim from a token
func (a *Authoriser) extractSubject(tokenStr string) (string, error) {
	token, err := a.parse(tokenStr)
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.Errorf("unexpected claims type, got=%T", claims)
	}

	sub, ok := claims["sub"]
	if !ok {
		return "", errors.New("missing 'sub' claim in token")
	}

	subStr, ok := sub.(string)
	if !ok {
		return "", errors.Errorf("'sub' claim must be string, got=%T", sub)
	}

	return subStr, nil
}

// Claims represents user claims stored in the access token.
type Claims = map[string]interface{}

// jwtClaims wraps user claims with JWT registered claims.
type jwtClaims struct {
	Data Claims
	jwt.RegisteredClaims
}

// Authorisation contains a signed JWT token and its expiry time.
type Authorisation struct {
	Token  string
	Expiry time.Time
}

// Token contains both access and refresh token authorisations.
type Token struct {
	Access  Authorisation
	Refresh Authorisation
}

// ReadWriter provides storage operations for refresh tokens.
// Implementations should store the mapping between refresh token keys (NanoID)
// and claim keys (user identifiers), with appropriate expiry handling.
type ReadWriter interface {
	// ReadToken retrieves the claim key associated with a refresh token key.
	ReadToken(ctx context.Context, key string) (string, error)

	// RevokeToken removes a refresh token from storage.
	RevokeToken(ctx context.Context, key string) error

	// WriteToken stores a refresh token with its claim key and expiry duration.
	WriteToken(ctx context.Context, key, value string, expiry time.Duration) error
}
