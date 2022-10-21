package tls

import "crypto/tls"

func Fallback(primary *tls.Config, fallback *tls.Config) *tls.Config {
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
