package jwt

import "time"

type Option func(*Authoriser)

func WithAccessExpiry(expiry time.Duration) Option {
	return func(a *Authoriser) {
		a.accessExpiry = expiry
	}
}

func WithRefreshExpiry(expiry time.Duration) Option {
	return func(a *Authoriser) {
		a.refreshExpiry = expiry
	}
}
