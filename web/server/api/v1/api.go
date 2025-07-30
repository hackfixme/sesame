package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/web/server/handler"
	"go.hackfix.me/sesame/web/server/types"
)

// Handler is the API endpoint handler.
type Handler struct {
	appCtx        *actx.Context
	logger        *slog.Logger
	fwMgr         *firewall.Manager
	tlsServerCert tls.Certificate
	tlsCACert     *x509.Certificate
}

// SetupHandlers configures the web API handlers.
func SetupHandlers(
	appCtx *actx.Context, errLvl types.ErrorLevel, logger *slog.Logger,
) (http.Handler, error) {
	fwCfg := appCtx.Config.Firewall
	if !fwCfg.Type.Valid {
		return nil, fmt.Errorf("no firewall was configured on this system")
	}

	_, fwMgr, err := firewall.Setup(appCtx, fwCfg.Type.V, fwCfg.DefaultAccessDuration.V, logger)
	if err != nil {
		return nil, fmt.Errorf("failed setting up firewall: %w", err)
	}

	tlsServerCert, err := appCtx.ServerTLSCert()
	if err != nil {
		return nil, err
	}

	tlsCACert, err := crypto.ExtractCACert(tlsServerCert)
	if err != nil {
		return nil, fmt.Errorf("failed extracting CA cert from TLS cert: %w", err)
	}

	if len(tlsCACert.DNSNames) == 0 {
		return nil, errors.New("no Subject Alternative Name values found in server CA certificate")
	}

	h := Handler{
		appCtx:        appCtx,
		fwMgr:         fwMgr,
		tlsServerCert: tlsServerCert,
		tlsCACert:     tlsCACert,
		logger:        logger,
	}

	httpPipeline := handler.NewPipeline(errLvl).
		WithSerializer(handler.JSON()).
		ProcessResponse(
			handler.Encrypt,
			handler.EncodeBase58,
		)

	httpsPipeline := handler.NewPipeline(types.ErrorLevelFull).
		WithSerializer(handler.JSON()).
		Auth(handler.TLSAuth(appCtx))

	mux := http.NewServeMux()
	mux.Handle("POST /join", handler.Handle(h.Join, httpPipeline.Auth(handler.InviteTokenAuth(appCtx))))
	mux.Handle("POST /open", handler.Handle(h.Open, httpsPipeline))
	mux.Handle("POST /close", handler.Handle(h.Close, httpsPipeline))

	return mux, nil
}
