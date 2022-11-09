package http

import (
	"crypto/tls"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net"
	"net/http"
)

func (s *Server) Serve(handler http.Handler) error {
	var g run.Group

	var tlsConfig *tls.Config

	if s.certsFS != nil {
		var err error
		tlsConfig, err = loadFromFS(s.certsFS)
		if err != nil {
			return errors.Wrap(err, "failed to load certificates from FS")
		}
	}

	if !s.disableAutoCert {
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
		}
		if s.hostPolicy != nil {
			certManager.HostPolicy = s.hostPolicy
		}
		if s.cache != nil {
			certManager.Cache = s.cache
		}

		ln, err := net.Listen("tcp", s.httpAddr)
		if err != nil {
			return errors.Wrap(err, "failed to listen on HTTP port")
		}
		g.Add(
			func() error {
				return http.Serve(ln, certManager.HTTPHandler(nil))
			},
			func(err error) {
				_ = ln.Close()
			},
		)

		if tlsConfig == nil {
			tlsConfig = certManager.TLSConfig()
		} else {
			tlsConfig = fallback(tlsConfig, certManager.TLSConfig())
		}
	}

	lnTLS, err := tls.Listen("tcp", s.httpsAddr, tlsConfig)
	if err != nil {
		return errors.Wrap(err, "failed to listen on HTTP port")
	}
	g.Add(
		func() error {
			if s.http2 {
				handler = h2c.NewHandler(handler, &http2.Server{})
			}
			return http.Serve(lnTLS, handler)
		},
		func(err error) {
			_ = lnTLS.Close()
		},
	)

	return g.Run()
}

func fallback(primary *tls.Config, fallback *tls.Config) *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := primary.GetCertificate(info)
			if err != nil {
				return fallback.GetCertificate(info)
			}
			return cert, err
		},
	}
}
