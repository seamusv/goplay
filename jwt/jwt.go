package jwt

import (
	"context"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/rs/xid"
	"time"
)

var TimeFunc = time.Now

type ClaimFunc = func(key string) (Claims, error)

type Authoriser struct {
	rw         ReadWriter
	secretHmac []byte
}

func NewAuthoriser(rw ReadWriter, secretHmac []byte) *Authoriser {
	return &Authoriser{rw: rw, secretHmac: secretHmac}
}

func (a *Authoriser) Create(ctx context.Context, claimKey string, claimFunc ClaimFunc) (*Token, error) {
	res := &Token{}

	{
		key := xid.New().String()
		expiry := TimeFunc().AddDate(0, 1, 0)
		claims := jwt.StandardClaims{
			Subject:   key,
			ExpiresAt: expiry.Unix(),
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing refresh token")
		}
		res.Refresh = Authorisation{
			Token:  signed,
			Expiry: expiry,
		}

		if err := a.rw.WriteToken(ctx, key, claimKey, expiry.Sub(TimeFunc())); err != nil {
			return nil, errors.Wrap(err, "storing refresh token")
		}
	}

	{
		userClaims, err := claimFunc(claimKey)
		expiry := TimeFunc().Add(5 * time.Minute)
		claims := jwtClaims{
			Data: userClaims,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiry.Unix(),
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

func (a *Authoriser) Exchange(ctx context.Context, tokenStr string, claimFunc ClaimFunc) (*Authorisation, error) {
	var key string
	{
		token, err := a.parse(tokenStr)
		if err != nil {
			return nil, err
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.Errorf("unexpected jwt.StandardClaims type, got=%T", claims)
		}
		key = claims["sub"].(string)
	}

	var authClaims Claims
	{
		claimKey, err := a.rw.ReadToken(ctx, key)
		if err != nil {
			return nil, errors.Wrap(err, "unable to retrieve refresh token")
		}
		authClaims, err = claimFunc(claimKey)
		if err != nil {
			return nil, errors.Wrap(err, "unable to rebuild claims")
		}
	}

	var auth *Authorisation
	{
		expiry := TimeFunc().Add(5 * time.Minute)
		claims := jwtClaims{
			Data: authClaims,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiry.Unix(),
			},
		}
		signed, err := a.sign(claims)
		if err != nil {
			return nil, errors.Wrap(err, "signing auth token")
		}
		auth = &Authorisation{
			Token:  signed,
			Expiry: expiry,
		}
	}

	return auth, nil
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
			return errors.Errorf("unexpected jwt.StandardClaims type, got=%T", claims)
		}
		key = claims["sub"].(string)
	}

	claimKey, err := a.rw.ReadToken(ctx, key)
	if err != nil {
		return errors.Wrap(err, "unable to retrieve refresh token")
	}
	_, err = claimFunc(claimKey)
	return err
}

func (a *Authoriser) sign(claims jwt.Claims) (string, error) {
	jwt.TimeFunc = TimeFunc
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(a.secretHmac)
}

func (a *Authoriser) parse(value string) (*jwt.Token, error) {
	jwt.TimeFunc = TimeFunc
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected token signing method: %v", token.Header["alg"])
		}
		return a.secretHmac, nil
	})
	if err != nil {
		return nil, err
	}

	if err := token.Claims.Valid(); err != nil {
		return nil, err
	}
	return token, nil
}

type Claims = map[string]interface{}

type Claimer interface {
	Builder(key string) (Claims, error)
}

type jwtClaims struct {
	Data Claims
	jwt.StandardClaims
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
	WriteToken(ctx context.Context, key, value string, expiry time.Duration) error
}
