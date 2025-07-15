package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/web/server/api/v1"
	"go.hackfix.me/sesame/web/server/middleware"
)

// Server is a wrapper around http.Server with some custom behavior.
type Server struct {
	*http.Server
	logger *slog.Logger
}

// New returns a new web Server instance that will listen on addr. If tlsCert
// and tlsPrivKey are provided, ListenAndServe will start an HTTPS server.
func New(appCtx *actx.Context, addr string, tlsCert *tls.Certificate) (*Server, error) {
	var tlsCfg *tls.Config
	if tlsCert != nil {
		tlsCfg = crypto.DefaultTLSConfig()

		tlsCfg.Certificates = []tls.Certificate{*tlsCert}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

		caCert, err := crypto.ExtractCACert(*tlsCert)
		if err != nil {
			return nil, fmt.Errorf("failed extracting CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(caCert)
		tlsCfg.ClientCAs = caCertPool
	}

	logger := appCtx.Logger.With("component", "web-server")
	srv := &Server{
		Server: &http.Server{
			Handler:           SetupHandlers(appCtx, logger),
			Addr:              addr,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      10 * time.Minute,
			TLSConfig:         tlsCfg,
		},
		logger: logger,
	}

	return srv, nil
}

// ListenAndServe starts either an HTTP or HTTPS server. It stores the actual
// listen address, which is convenient when the address is dynamically
// determined by the system (e.g. ':0').
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		//nolint:wrapcheck // This is fine.
		return err
	}

	s.Addr = ln.Addr().String()
	s.logger.Info("started listener", "address", s.Addr)

	hl := &HybridListener{
		Listener:  ln,
		tlsConfig: s.Server.TLSConfig,
		logger:    s.logger,
	}

	//nolint:wrapcheck // This is fine.
	return s.Serve(hl)
}

// SetupHandlers configures the server HTTP handlers.
func SetupHandlers(appCtx *actx.Context, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", api.SetupHandlers(appCtx, logger)))

	logMux := middleware.Logger(logger)(mux)
	return logMux
}
