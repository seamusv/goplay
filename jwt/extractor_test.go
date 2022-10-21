package jwt

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"net/http"
	"testing"
)

func TestAuthHeaderTokenExtractor(t *testing.T) {
	tests := []struct {
		name    string
		request *http.Request
		want    string
		wantErr string
	}{
		{
			name:    "empty / no header",
			request: &http.Request{},
		},
		{
			name: "token in header",
			request: &http.Request{
				Header: http.Header{
					"Authorization": {"Bearer WelcomeJungle"},
				},
			},
			want: "WelcomeJungle",
		},
		{
			name: "not a bearer token",
			request: &http.Request{
				Header: http.Header{
					"Authorization": {"Welcome to the Jungle!"},
				},
			},
			wantErr: "Authorization header format must be Bearer {token}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthHeaderTokenExtractor(tt.request)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			if got != tt.want {
				t.Errorf("AuthHeaderTokenExtractor() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCookieTokenExtractor(t *testing.T) {
	tests := []struct {
		name    string
		cookie  *http.Cookie
		want    string
		wantErr string
	}{
		{
			name:    "no cookie",
			cookie:  &http.Cookie{},
			wantErr: "http: named cookie not present",
		},
		{
			name:   "contains cookie",
			cookie: &http.Cookie{Name: "cookie", Value: "Welcome to the Jungle!"},
			want:   "Welcome to the Jungle!",
		},
		{
			name:   "empty cookie",
			cookie: &http.Cookie{Name: "cookie"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)

			if tt.cookie != nil {
				request.AddCookie(tt.cookie)
			}

			got, err := CookieTokenExtractor("cookie", request)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGrpcContextTokenExtractor(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{
			name:    "no token",
			wantErr: "named metadata not present",
		},
		{
			name:  "with token",
			value: "Welcome to the Jungle!",
			want:  "Welcome to the Jungle!",
		},
		{
			name:    "blank token",
			value:   "",
			wantErr: "named metadata not present",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.New(nil)
			if tt.value != "" {
				md.Set("token", tt.value)
			}
			ctx := metadata.NewIncomingContext(context.Background(), md)

			got, err := GrpcContextTokenExtractor(ctx, "token")
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
