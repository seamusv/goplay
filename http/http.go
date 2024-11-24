package http

import (
	"golang.org/x/crypto/acme/autocert"
	"io/fs"
	"sync"
	"time"
)

type Server struct {
	disableAutoCert   bool
	certsFS           fs.ReadFileFS
	httpAddr          string
	httpsAddr         string
	useH2C            bool
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	hostPolicy        autocert.HostPolicy
	cache             Cache
	closeCh           chan struct{}
	closeOnce         sync.Once
}

type ServerOption func(*Server)

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		httpAddr:          ":80",
		httpsAddr:         ":443",
		readHeaderTimeout: 5 * time.Second,
		readTimeout:       0,
		writeTimeout:      0,
		idleTimeout:       120 * time.Second,
	}

	for _, option := range options {
		option(s)
	}

	return s
}

func (s *Server) Close() {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

func WithoutAutoCert() ServerOption {
	return func(s *Server) {
		s.disableAutoCert = true
	}
}

func WithEmbeddedCertificates(fs fs.ReadFileFS) ServerOption {
	return func(s *Server) {
		s.certsFS = fs
	}
}

func WithH2C() ServerOption {
	return func(s *Server) {
		s.useH2C = true
	}
}

func WithHTTPAddr(addr string) ServerOption {
	return func(s *Server) {
		s.httpAddr = addr
	}
}

func WithHTTPSAddr(addr string) ServerOption {
	return func(s *Server) {
		s.httpsAddr = addr
	}
}

func WithHostPolicy(policy HostPolicy) ServerOption {
	return func(s *Server) {
		s.hostPolicy = autocert.HostPolicy(policy)
	}
}

func WithHostWhitelistHostPolicy(hosts ...string) ServerOption {
	return func(s *Server) {
		s.hostPolicy = autocert.HostWhitelist(hosts...)
	}
}

func WithCache(cache Cache) ServerOption {
	return func(s *Server) {
		s.cache = cache
	}
}

func WithDirCache(dir string) ServerOption {
	return func(s *Server) {
		s.cache = autocert.DirCache(dir)
	}
}

func WithReadHeaderTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.readHeaderTimeout = timeout
	}
}

func WithReadTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.readTimeout = timeout
	}
}

func WithWriteTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.writeTimeout = timeout
	}
}

func WithIdleTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.idleTimeout = timeout
	}
}
