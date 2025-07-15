package api

import (
	"log/slog"
	"net/http"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/web/server/middleware"
)

// Handler is the API endpoint handler.
type Handler struct {
	appCtx *actx.Context
	logger *slog.Logger
}

// SetupHandlers configures the web API handlers.
func SetupHandlers(appCtx *actx.Context, logger *slog.Logger) http.Handler {
	h := Handler{appCtx: appCtx, logger: logger}
	mux := http.NewServeMux()
	authn := middleware.Authn(appCtx, logger)

	mux.HandleFunc("POST /join", h.JoinPost)
	mux.Handle("POST /open", middleware.Chain(authn, http.HandlerFunc(h.OpenPost)))

	return mux
}
