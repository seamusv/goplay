package jwt

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/pkg/errors"
	"time"
)

type ClaimFunc = func(ctx context.Context, key string) (Claims, error)

type Authoriser struct {
	rw            ReadWriter
	secretHmac    []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func NewAuthoriser(rw ReadWriter, secretHmac []byte, options ...Option) *Authoriser {
	a := &Authoriser{
		rw:            rw,
		secretHmac:    secretHmac,
		accessExpiry:  15 * time.Minute,
		refreshExpiry: 30 * 24 * time.Hour,
	}

	for _, option := range options {
		option(a)
	}

	return a
}

func (a *Authoriser) Create(ctx context.Context, claimKey string, claimFunc ClaimFunc) (*Token, error) {
	res := &Token{}

	{
		var key string
		{
			var err error
			key, err = gonanoid.New(12)
			if err != nil {
				return nil, errors.Wrap(err, "generating refresh token")
			}
		}
		expiry := time.Now().Add(a.refreshExpiry)
		claims := jwt.RegisteredClaims{
			Subject:   key,
			ExpiresAt: jwt.NewNumericDate(expiry),
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing refresh token")
		}
		res.Refresh = Authorisation{
			Token:  signed,
			Expiry: expiry,
		}

		if err := a.rw.WriteToken(ctx, key, claimKey, expiry.Sub(time.Now())); err != nil {
			return nil, errors.Wrap(err, "storing refresh token")
		}
	}

	{
		userClaims, err := claimFunc(ctx, claimKey)
		expiry := time.Now().Add(a.accessExpiry)
		claims := jwtClaims{
			Data: userClaims,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiry),
			},
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing auth token")
		}
		res.Access = Authorisation{
			Token:  signed,
			Expiry: expiry,
		}
	}

	return res, nil
}

func (a *Authoriser) Parse(tokenStr string) (Claims, error) {
	token, err := a.parse(tokenStr)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.Errorf("unexpected claims type, got=%T", token.Claims)
	}

	return claims, nil
}

func (a *Authoriser) Exchange(ctx context.Context, tokenStr string, claimFunc ClaimFunc) (*Token, error) {
	var refreshKey string
	{
		token, err := a.parse(tokenStr)
		if err != nil {
			return nil, err
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.Errorf("unexpected jwt.RegisteredClaims type, got=%T", claims)
		}
		refreshKey = claims["sub"].(string)
	}

	var claimValue string
	var authClaims Claims
	{
		var err error
		claimValue, err = a.rw.ReadToken(ctx, refreshKey)
		if err != nil {
			return nil, errors.Wrap(err, "unable to retrieve refresh token")
		}
		authClaims, err = claimFunc(ctx, claimValue)
		if err != nil {
			return nil, errors.Wrap(err, "unable to rebuild claims")
		}
		if err := a.rw.RevokeToken(ctx, refreshKey); err != nil {
			return nil, errors.Wrap(err, "unable to revoke refresh token")
		}
	}

	res := &Token{}
	{
		var key string
		{
			var err error
			key, err = gonanoid.New(12)
			if err != nil {
				return nil, errors.Wrap(err, "generating refresh token")
			}
		}
		expiry := time.Now().Add(a.refreshExpiry)
		claims := jwt.RegisteredClaims{
			Subject:   key,
			ExpiresAt: jwt.NewNumericDate(expiry),
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing refresh token")
		}
		res.Refresh = Authorisation{
			Token:  signed,
			Expiry: expiry,
		}

		if err := a.rw.WriteToken(ctx, key, claimValue, expiry.Sub(time.Now())); err != nil {
			return nil, errors.Wrap(err, "storing refresh token")
		}
	}

	{
		expiry := time.Now().Add(a.accessExpiry)
		claims := jwtClaims{
			Data: authClaims,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiry),
			},
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing auth token")
		}
		res.Access = Authorisation{
			Token:  signed,
			Expiry: expiry,
		}
	}

	return res, nil
}

func (a *Authoriser) Revoke(ctx context.Context, tokenStr string, fn func(claimValue string) error) error {
	var refreshKey string
	{
		token, err := a.parse(tokenStr)
		if err != nil {
			return err
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return errors.Errorf("unexpected jwt.RegisteredClaims type, got=%T", claims)
		}
		refreshKey = claims["sub"].(string)
	}

	{
		claimValue, err := a.rw.ReadToken(ctx, refreshKey)
		if err != nil {
			return errors.Wrap(err, "unable to retrieve refresh token")
		}

		if err := fn(claimValue); err != nil {
			return errors.Wrap(err, "unable to revoke refresh token")
		}
	}

	return a.rw.RevokeToken(ctx, refreshKey)
}

func (a *Authoriser) Verify(ctx context.Context, tokenStr string, claimFunc ClaimFunc) error {
	var key string
	{
		token, err := a.parse(tokenStr)
		if err != nil {
			return err
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return errors.Errorf("unexpected jwt.RegisteredClaims type, got=%T", claims)
		}
		key = claims["sub"].(string)
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

type Claims = map[string]interface{}

type jwtClaims struct {
	Data Claims
	jwt.RegisteredClaims
}

type Authorisation struct {
	Token  string
	Expiry time.Time
}

type Token struct {
	Access  Authorisation
	Refresh Authorisation
}

type ReadWriter interface {
	ReadToken(ctx context.Context, key string) (string, error)
	RevokeToken(ctx context.Context, key string) error
	WriteToken(ctx context.Context, key, value string, expiry time.Duration) error
}
