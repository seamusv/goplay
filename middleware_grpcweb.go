package play

import (
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
	"net/http"
	"strings"
)

func GrpcWeb(grpcServer *grpc.Server) func(http.Handler) http.Handler {
	grpcwServer := grpcweb.WrapServer(grpcServer)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isGrpcWebRequest(r) {
				grpcwServer.ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func GrpcWebHandler(grpcServer *grpc.Server) http.Handler {
	grpcwServer := grpcweb.WrapServer(grpcServer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isGrpcWebRequest(r) {
			grpcwServer.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}

func isGrpcWebRequest(req *http.Request) bool {
	return req.Method == http.MethodPost && strings.HasPrefix(req.Header.Get("Content-Type"), "application/grpc")
}
