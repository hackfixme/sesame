package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httplog/v3"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/web/server/api/v1"
	"go.hackfix.me/sesame/web/server/types"
)

// Server is a wrapper around http.Server with some custom behavior.
type Server struct {
	*http.Server
	logger *slog.Logger
}

// New returns a new web Server instance that will listen on addr for both TCP
// and TLS connections. If tlsCert is provided, it configures TLS and requires
// clients using TLS to authenticate with certificates signed by tlsCert.
func New(
	appCtx *actx.Context, addr string, tlsCert *tls.Certificate, errLvl types.ErrorLevel,
) (*Server, error) {
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

	handlers, err := SetupHandlers(appCtx, errLvl, logger)
	if err != nil {
		return nil, err
	}

	srv := &Server{
		Server: &http.Server{
			Handler:           handlers,
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
		tlsConfig: s.TLSConfig,
		logger:    s.logger,
	}

	//nolint:wrapcheck // This is fine.
	return s.Serve(hl)
}

// SetupHandlers configures the server HTTP handlers.
func SetupHandlers(appCtx *actx.Context, errLvl types.ErrorLevel, logger *slog.Logger) (http.Handler, error) {
	mux := http.NewServeMux()

	apiHandlers, err := api.SetupHandlers(appCtx, errLvl, logger)
	if err != nil {
		return nil, err
	}

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiHandlers))

	logBody := func(_ *http.Request) bool {
		return appCtx.LogLevel == slog.LevelDebug
	}
	loggerMW := httplog.RequestLogger(logger, &httplog.Options{
		Level:              appCtx.LogLevel,
		Schema:             httplog.SchemaECS,
		RecoverPanics:      true,
		LogResponseHeaders: []string{"Content-Type"},
		LogRequestBody:     logBody,
		LogResponseBody:    logBody,
	})

	handler := chi.Chain(loggerMW).Handler(mux)

	return handler, nil
}
