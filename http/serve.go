package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/oklog/run"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
				return errors.Wrapf(err, "failed to listen on HTTP port %s", s.httpAddr)
			}
			httpSrv := &http.Server{
				ReadHeaderTimeout: s.readHeaderTimeout,
				ReadTimeout:       s.readTimeout,
				WriteTimeout:      s.writeTimeout,
				IdleTimeout:       s.idleTimeout,
				Handler:           certManager.HTTPHandler(handler),
			}
			if err := http2.ConfigureServer(httpSrv, nil); err != nil {
				return errors.Wrap(err, "failed to configure HTTP/2 server")
			}
			g.Add(
				func() error {
					return httpSrv.Serve(ln)
				},
				func(err error) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = httpSrv.Shutdown(ctx)
					_ = ln.Close()
				},
			)
		} else {
			ln, err := net.Listen("tcp", s.httpAddr)
			if err != nil {
				return errors.Wrapf(err, "failed to listen on HTTP port %s", s.httpAddr)
			}
			httpSrv := &http.Server{
				ReadHeaderTimeout: s.readHeaderTimeout,
				ReadTimeout:       s.readTimeout,
				WriteTimeout:      s.writeTimeout,
				IdleTimeout:       s.idleTimeout,
				Handler:           handler,
			}
			if s.useH2C {
				httpSrv.Handler = h2c.NewHandler(handler, &http2.Server{})
			} else {
				if err := http2.ConfigureServer(httpSrv, nil); err != nil {
					return errors.Wrap(err, "failed to configure HTTP/2 server")
				}
			}
			g.Add(
				func() error {
					return httpSrv.Serve(ln)
				},
				func(err error) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = httpSrv.Shutdown(ctx)
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
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		}

		lnTLS, err := tls.Listen("tcp", s.httpsAddr, tlsConfig)
		if err != nil {
			return errors.Wrapf(err, "failed to listen on HTTPS port %s", s.httpsAddr)
		}
		httpsSrv := &http.Server{
			ReadHeaderTimeout: s.readHeaderTimeout,
			ReadTimeout:       s.readTimeout,
			WriteTimeout:      s.writeTimeout,
			IdleTimeout:       s.idleTimeout,
			Handler:           tlsHandler,
		}
		g.Add(
			func() error {
				return httpsSrv.Serve(lnTLS)
			},
			func(err error) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpsSrv.Shutdown(ctx)
				_ = lnTLS.Close()
			},
		)
	}

	{
		g.Add(
			func() error {
				select {
				case <-s.closeCh:
					return nil
				}
			},
			func(err error) {
				s.Close()
			},
		)
	}

	return g.Run()
}
