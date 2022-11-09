package http

import (
	"golang.org/x/crypto/acme/autocert"
	"io/fs"
)

type Server struct {
	disableAutoCert bool
	certsFS         fs.ReadFileFS
	httpAddr        string
	httpsAddr       string
	http2           bool
	hostPolicy      autocert.HostPolicy
	cache           Cache
}

type ServerOption func(*Server)

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		httpAddr:  ":80",
		httpsAddr: ":443",
	}

	for _, option := range options {
		option(s)
	}

	return s
}

func (s *Server) Close() {

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

func WithHTTP2() ServerOption {
	return func(s *Server) {
		s.http2 = true
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
