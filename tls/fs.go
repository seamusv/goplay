package tls

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"strings"
)

func FS(certsFS fs.ReadFileFS) (*tls.Config, error) {
	var certificates []tls.Certificate

	err := fs.WalkDir(certsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			if strings.HasSuffix(path, ".pem") {
				pem, err := certsFS.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", path, err)
				}
				cert, err := tls.X509KeyPair(pem, pem)
				if err != nil {
					return fmt.Errorf("failed to parse certificate %s: %w", path, err)
				}
				certificates = append(certificates, cert)
			}

			if strings.HasSuffix(path, ".crt") {
				crt, err := certsFS.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", path, err)
				}
				key, err := certsFS.ReadFile(strings.Replace(path, ".crt", ".key", 1))
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", strings.Replace(path, ".crt", ".key", 1), err)
				}
				certificate, err := tls.X509KeyPair(crt, key)
				if err != nil {
					return fmt.Errorf("failed to parse certificate %s: %w", path, err)
				}
				certificates = append(certificates, certificate)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Documentation: https://wiki.mozilla.org/Security/Server_Side_TLS
	tlsConfig := &tls.Config{
		Certificates: certificates,
		MinVersion:   tls.VersionTLS12,
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
	return tlsConfig, nil
}
