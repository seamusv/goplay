package http

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"strings"
)

func loadFromFS(certsFS fs.ReadFileFS) ([]tls.Certificate, error) {
	var certificates []tls.Certificate

	err := fs.WalkDir(certsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

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
			return nil
		}

		if strings.HasSuffix(path, ".crt") {
			crt, err := certsFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}
			keyPath := strings.Replace(path, ".crt", ".key", 1)
			key, err := certsFS.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", keyPath, err)
			}
			certificate, err := tls.X509KeyPair(crt, key)
			if err != nil {
				return fmt.Errorf("failed to parse certificate %s: %w", path, err)
			}
			certificates = append(certificates, certificate)
			return nil
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return certificates, nil
}
