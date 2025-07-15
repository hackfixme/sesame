package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

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
	mwChain := chi.Chain(middleware.Authn(appCtx, logger))

	mux.HandleFunc("POST /join", h.JoinPost)
	mux.Handle("POST /open", mwChain.HandlerFunc(h.OpenPost))

	return mux
}
