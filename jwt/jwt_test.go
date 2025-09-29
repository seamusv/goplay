package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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
			a, err := NewAuthoriser(rw, []byte("Welcome to the Jungle!Welcome to the Jungle!"))
			require.NoError(t, err)
			got, err := a.Create(context.Background(), tt.claimKey, func(ctx context.Context, key string) (Claims, error) {
				return tt.claims, nil
			})
			require.NoError(t, err)
			tt.expect(t, got)
		})
	}
}

func TestAuthoriser_Parse(t *testing.T) {
	a, err := NewAuthoriser(newMockReadWrite(), []byte("Welcome to the Jungle!Welcome to the Jungle!"))
	require.NoError(t, err)
	token, err := a.Create(context.Background(), "foo", func(ctx context.Context, key string) (Claims, error) {
		return map[string]interface{}{
			"name": "Bobby",
		}, nil
	})
	require.NoError(t, err)
	claims, err := a.Parse(token.Access.Token)
	require.NoError(t, err)
	require.Contains(t, claims, "name")
	require.Equal(t, "Bobby", claims["name"])
}

func TestAuthoriser_Exchange(t *testing.T) {
	tests := []struct {
		name      string
		claimKey  string
		claims    Claims
		expectErr bool
	}{
		{
			name:     "successful exchange",
			claimKey: "user123",
			claims: Claims{
				"userId": "user123",
				"role":   "admin",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := newMockReadWrite()
			a, err := NewAuthoriser(rw, []byte("Welcome to the Jungle!Welcome to the Jungle!"))
			require.NoError(t, err)

			// Create initial token
			initialToken, err := a.Create(context.Background(), tt.claimKey, func(ctx context.Context, key string) (Claims, error) {
				return tt.claims, nil
			})
			require.NoError(t, err)

			// Exchange refresh token for new token pair
			newToken, err := a.Exchange(context.Background(), initialToken.Refresh.Token, func(ctx context.Context, key string) (Claims, error) {
				require.Equal(t, tt.claimKey, key)
				return tt.claims, nil
			})

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, newToken)
			require.NotEmpty(t, newToken.Access.Token)
			require.NotEmpty(t, newToken.Refresh.Token)
			require.NotEqual(t, initialToken.Refresh.Token, newToken.Refresh.Token, "refresh token should be different")

			// Verify new access token contains correct claims
			claims, err := a.Parse(newToken.Access.Token)
			require.NoError(t, err)
			require.Equal(t, tt.claims["userId"], claims["userId"])
			require.Equal(t, tt.claims["role"], claims["role"])
		})
	}
}

func TestAuthoriser_Verify(t *testing.T) {
	tests := []struct {
		name      string
		claimKey  string
		claims    Claims
		expectErr bool
	}{
		{
			name:     "successful verification",
			claimKey: "user123",
			claims: Claims{
				"userId": "user123",
				"role":   "admin",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := newMockReadWrite()
			a, err := NewAuthoriser(rw, []byte("Welcome to the Jungle!Welcome to the Jungle!"))
			require.NoError(t, err)

			// Create token
			token, err := a.Create(context.Background(), tt.claimKey, func(ctx context.Context, key string) (Claims, error) {
				return tt.claims, nil
			})
			require.NoError(t, err)

			// Verify refresh token
			err = a.Verify(context.Background(), token.Refresh.Token, func(ctx context.Context, key string) (Claims, error) {
				require.Equal(t, tt.claimKey, key)
				return tt.claims, nil
			})

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestAuthoriser_Revoke(t *testing.T) {
	tests := []struct {
		name      string
		claimKey  string
		claims    Claims
		expectErr bool
	}{
		{
			name:     "successful revocation",
			claimKey: "user123",
			claims: Claims{
				"userId": "user123",
				"role":   "admin",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := newMockReadWrite()
			a, err := NewAuthoriser(rw, []byte("Welcome to the Jungle!Welcome to the Jungle!"))
			require.NoError(t, err)

			// Create token
			token, err := a.Create(context.Background(), tt.claimKey, func(ctx context.Context, key string) (Claims, error) {
				return tt.claims, nil
			})
			require.NoError(t, err)

			// Revoke refresh token
			callbackCalled := false
			err = a.Revoke(context.Background(), token.Refresh.Token, func(claimValue string) error {
				callbackCalled = true
				require.Equal(t, tt.claimKey, claimValue)
				return nil
			})

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.True(t, callbackCalled, "callback should be called")

			// Verify token is actually revoked by attempting to verify it
			err = a.Verify(context.Background(), token.Refresh.Token, func(ctx context.Context, key string) (Claims, error) {
				return tt.claims, nil
			})
			require.Error(t, err, "token should be invalid after revocation")
		})
	}
}

func TestAuthoriser_ErrorCases(t *testing.T) {
	secret := []byte("Welcome to the Jungle!Welcome to the Jungle!")

	t.Run("NewAuthoriser with nil ReadWriter", func(t *testing.T) {
		_, err := NewAuthoriser(nil, secret)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ReadWriter cannot be nil")
	})

	t.Run("NewAuthoriser with empty secret", func(t *testing.T) {
		_, err := NewAuthoriser(newMockReadWrite(), []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "secretHmac cannot be empty")
	})

	t.Run("NewAuthoriser with short secret", func(t *testing.T) {
		_, err := NewAuthoriser(newMockReadWrite(), []byte("short"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least 32 bytes")
	})

	t.Run("Parse with invalid token", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		_, err = a.Parse("invalid.token.string")
		require.Error(t, err)
	})

	t.Run("Parse with token missing Data field", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		// Create a token without Data field
		claims := jwt.MapClaims{
			"sub": "test",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenStr, err := token.SignedString(secret)
		require.NoError(t, err)

		_, err = a.Parse(tokenStr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'Data' field")
	})

	t.Run("Exchange with token missing sub claim", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		claims := jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenStr, err := token.SignedString(secret)
		require.NoError(t, err)

		_, err = a.Exchange(context.Background(), tokenStr, func(ctx context.Context, key string) (Claims, error) {
			return Claims{}, nil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'sub' claim")
	})

	t.Run("Exchange with non-existent refresh token", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		claims := jwt.RegisteredClaims{
			Subject:   "nonexistent",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenStr, err := token.SignedString(secret)
		require.NoError(t, err)

		_, err = a.Exchange(context.Background(), tokenStr, func(ctx context.Context, key string) (Claims, error) {
			return Claims{}, nil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to retrieve refresh token")
	})

	t.Run("Create with claimFunc returning error", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		_, err = a.Create(context.Background(), "user123", func(ctx context.Context, key string) (Claims, error) {
			return nil, errors.New("claim error")
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "building user claims")
	})

	t.Run("Verify with invalid token", func(t *testing.T) {
		a, err := NewAuthoriser(newMockReadWrite(), secret)
		require.NoError(t, err)
		err = a.Verify(context.Background(), "invalid.token", func(ctx context.Context, key string) (Claims, error) {
			return Claims{}, nil
		})
		require.Error(t, err)
	})

	t.Run("Revoke with callback error", func(t *testing.T) {
		rw := newMockReadWrite()
		a, err := NewAuthoriser(rw, secret)
		require.NoError(t, err)

		token, err := a.Create(context.Background(), "user123", func(ctx context.Context, key string) (Claims, error) {
			return Claims{"userId": "user123"}, nil
		})
		require.NoError(t, err)

		err = a.Revoke(context.Background(), token.Refresh.Token, func(claimValue string) error {
			return errors.New("callback failed")
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to revoke refresh token")
	})
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
	delete(m.store, key)
	return nil
}
