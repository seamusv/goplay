package jwt

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAuthoriser_Create(t *testing.T) {
	tests := []struct {
		name     string
		claimKey string
		claims   Claims
		expect   func(t *testing.T, token *Token)
	}{
		{
			name:     "create token",
			claimKey: "Bobby",
			claims: Claims{
				"userId": "Bobby",
				"age":    4,
			},
			expect: func(t *testing.T, token *Token) {
				require.NotNil(t, token)
				{
					require.NotEmpty(t, token.Access.Token, "expect token to be satisfied")
					claims := testExtractClaims(t, token.Access.Token)
					require.Contains(t, claims, "exp")
					require.IsType(t, float64(0), claims["exp"])
					exp := time.Unix(int64(claims["exp"].(float64)), 0)
					require.LessOrEqual(t, exp.Sub(time.Now()), 15*time.Minute)
				}
				{
					require.NotEmpty(t, token.Refresh.Token, "expect token to be satisfied")
					claims := testExtractClaims(t, token.Refresh.Token)
					require.Contains(t, claims, "exp")
					require.IsType(t, float64(0), claims["exp"])
					exp := time.Unix(int64(claims["exp"].(float64)), 0)
					require.Greater(t, exp.Sub(time.Now()), 24*time.Hour)
				}
			},
		},
	}
	for _, tt := range tests {
		rw := newMockReadWrite()
		t.Run(tt.name, func(t *testing.T) {
			a := &Authoriser{
				rw:         rw,
				secretHmac: []byte("Welcome to the Jungle!"),
			}
			got, err := a.Create(context.Background(), tt.claimKey, func(key string) (Claims, error) {
				return tt.claims, nil
			})
			require.NoError(t, err)
			tt.expect(t, got)
		})
	}
}

func TestAuthoriser_Parse(t *testing.T) {
	a := NewAuthoriser(newMockReadWrite(), []byte("Welcome to the Jungle!"))
	token, err := a.Create(context.Background(), "foo", func(key string) (Claims, error) {
		return map[string]interface{}{
			"name": "Bobby",
		}, nil
	})
	require.NoError(t, err)
	claims, err := a.Parse(token.Access.Token)
	require.NoError(t, err)
	require.Contains(t, claims, "Data")
	data := claims["Data"].(Claims)
	require.Contains(t, data, "name")
	require.Equal(t, "Bobby", data["name"])
}

func testExtractClaims(t *testing.T, tokenStr string) jwt.MapClaims {
	token, _ := jwt.Parse(tokenStr, nil)
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok, "expected claims to be (jwt.MapClaims), got=%T", token.Claims)
	return claims
}

type mockReadWrite struct {
	store map[string]string
}

func newMockReadWrite() *mockReadWrite {
	return &mockReadWrite{store: make(map[string]string)}
}

func (m *mockReadWrite) ReadToken(ctx context.Context, key string) (string, error) {
	res, ok := m.store[key]
	if !ok {
		return "", errors.Errorf("missing key")
	}
	return res, nil
}

func (m *mockReadWrite) WriteToken(ctx context.Context, key, value string, expiry time.Duration) error {
	m.store[key] = value
	return nil
}

func (m *mockReadWrite) RevokeToken(ctx context.Context, key string) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockReadWrite) RevokeValue(ctx context.Context, value string) error {
	//TODO implement me
	panic("implement me")
}
