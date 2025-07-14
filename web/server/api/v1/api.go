package api

import (
	"net/http"

	actx "go.hackfix.me/sesame/app/context"
)

// Handler is the API endpoint handler.
type Handler struct {
	appCtx *actx.Context
}

// SetupHandlers configures the web API handlers.
func SetupHandlers(appCtx *actx.Context) http.Handler {
	h := Handler{appCtx}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /join", h.JoinPost)
	mux.HandleFunc("POST /open", h.OpenPost)
	return mux
}
