package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/web/api/v1"
)

// Server is a wrapper around http.Server with some custom behavior.
type Server struct {
	*http.Server
	appCtx *actx.Context
}

// New returns a new web Server instance that will listen on addr. If tlsCert
// and tlsPrivKey are provided, ListenAndServe will start an HTTPS server.
func New(appCtx *actx.Context, addr string, tlsCert, tlsPrivKey []byte) (*Server, error) {
	var tlsCfg *tls.Config
	if tlsCert != nil && tlsPrivKey != nil {
		tlsCfg = defaultTLSConfig()
		certPair, err := tls.X509KeyPair(tlsCert, tlsPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed parsing PEM encoded TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{certPair}
	}

	srv := &Server{
		Server: &http.Server{
			Handler:           api.SetupHandlers(appCtx),
			Addr:              addr,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      10 * time.Minute,
			TLSConfig:         tlsCfg,
		},
		appCtx: appCtx,
	}

	return srv, nil
}

// ListenAndServe starts either an HTTP or HTTPS server. It stores the actual
// listen address, which is convenient when the address is dynamically
// determined by the system (e.g. ':0').
func (s *Server) ListenAndServe() error {
	var (
		ln      net.Listener
		err     error
		srvType string
	)
	if s.TLSConfig != nil {
		ln, err = tls.Listen("tcp", s.Addr, s.TLSConfig)
		srvType = "HTTPS"
	} else {
		ln, err = net.Listen("tcp", s.Addr)
		srvType = "HTTP"
	}
	if err != nil {
		return err
	}

	s.Addr = ln.Addr().String()
	s.appCtx.Logger.Info(fmt.Sprintf("started %s server", srvType), "address", s.Addr)

	return s.Serve(ln)
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS13,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveID(tls.CurveP256),
			tls.CurveID(tls.Ed25519),
		},
	}
}
