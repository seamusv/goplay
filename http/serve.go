package http

import (
	"crypto/tls"
	"fmt"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net"
	"net/http"
	"time"
)

func (s *Server) Serve(tlsHandler http.Handler, handler http.Handler) error {
	var g run.Group

	{
		tlsGetCertificates := &tlsGetCertificatesMiddleware{}

		if s.certsFS != nil {
			certificates, err := loadFromFS(s.certsFS)
			if err != nil {
				return errors.Wrap(err, "failed to load certificates from FS")
			}
			tlsGetCertificates.Append(staticGetCertificate(certificates))
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

			tlsGetCertificates.Append(certManager.GetCertificate)

			ln, err := net.Listen("tcp", s.httpAddr)
			if err != nil {
				return errors.Wrap(err, "failed to listen on HTTP port")
			}
			g.Add(
				func() error {
					srv := &http.Server{
						ReadTimeout:  5 * time.Second,
						WriteTimeout: 0,
						IdleTimeout:  120 * time.Second,
						Handler:      certManager.HTTPHandler(handler),
					}
					return srv.Serve(ln)
				},
				func(err error) {
					_ = ln.Close()
				},
			)
		}

		// Documentation: https://wiki.mozilla.org/Security/Server_Side_TLS
		tlsConfig := &tls.Config{
			GetCertificate: tlsGetCertificates.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos: []string{
				"h2", "http/1.1", // enable HTTP/2
				acme.ALPNProto, // enable tls-alpn ACME challenges
			},
			CurvePreferences: []tls.CurveID{
				tls.CurveP384,
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}

		lnTLS, err := tls.Listen("tcp", s.httpsAddr, tlsConfig)
		if err != nil {
			return errors.Wrap(err, "failed to listen on HTTP port")
		}
		g.Add(
			func() error {
				if s.useH2C {
					tlsHandler = h2c.NewHandler(tlsHandler, &http2.Server{})
				}
				srv := &http.Server{
					ReadTimeout:  s.readTimeout,
					WriteTimeout: s.writeTimeout,
					IdleTimeout:  s.idleTimeout,
					Handler:      tlsHandler,
				}
				return srv.Serve(lnTLS)
			},
			func(err error) {
				_ = lnTLS.Close()
			},
		)
	}

	{
		s.cancel = make(chan struct{})
		g.Add(
			func() error {
				select {
				case <-s.cancel:
					fmt.Printf("The first actor was canceled\n")
					return nil
				}
			},
			func(err error) {
				close(s.cancel)
			},
		)
	}

	return g.Run()
}
