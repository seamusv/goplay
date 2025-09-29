package http

import "crypto/tls"

type GetCertificateFunc func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)

type tlsGetCertificatesMiddleware struct {
	handlers []GetCertificateFunc
}

func (t *tlsGetCertificatesMiddleware) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var lastErr error
	for _, handler := range t.handlers {
		cert, err := handler(clientHello)
		if err != nil {
			lastErr = err
			continue
		}
		if cert != nil {
			return cert, nil
		}
	}
	return nil, lastErr
}

func (t *tlsGetCertificatesMiddleware) Append(handler GetCertificateFunc) {
	t.handlers = append(t.handlers, handler)
}

func staticGetCertificate(certificates []tls.Certificate) GetCertificateFunc {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for _, certificate := range certificates {
			if err := clientHello.SupportsCertificate(&certificate); err == nil {
				return &certificate, nil
			}
		}
		return nil, nil
	}
}
