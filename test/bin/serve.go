// Serve is a very simple static file server in Go.
// Inspired by https://gist.github.com/paulmach/7271283
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

var (
	path    = flag.String("path", ".", "path to the directory to serve.")
	address = flag.String("address", ":8080", "address to serve on.")
)

func main() {
	flag.Parse()

	pathAbs, err := filepath.Abs(*path)
	if err != nil {
		slog.Error("failed getting absolute path", "path", *path, "error", err)
		os.Exit(1)
	}

	err = Serve(*address, pathAbs)
	if err != nil {
		slog.Error("failed serving directory", "path", pathAbs, "address", *address, "error", err)
		os.Exit(1)
	}
}

func Serve(address string, path string) error {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(path))
	mux.Handle("/", logRequest(fs))

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed reserving TCP socket: %w", err)
	}

	slog.Info("started static file server", "path", path, "address", ln.Addr().String())

	return http.Serve(ln, mux)
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request",
			"remote_address", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
		)
		handler.ServeHTTP(w, r)
	})
}
