package jwt

import "time"

// Option configures an Authoriser instance.
type Option func(*Authoriser)

// WithAccessExpiry sets the expiry duration for access tokens.
// Default is 15 minutes if not specified.
func WithAccessExpiry(expiry time.Duration) Option {
	return func(a *Authoriser) {
		a.accessExpiry = expiry
	}
}

// WithRefreshExpiry sets the expiry duration for refresh tokens.
// Default is 30 days if not specified.
func WithRefreshExpiry(expiry time.Duration) Option {
	return func(a *Authoriser) {
		a.refreshExpiry = expiry
	}
}
