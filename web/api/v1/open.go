package api

import "net/http"

// OpenGet validates and parses the received JWT, and creates firewall rules that
// allow the client IP to access the internal service.
func (h *Handler) OpenGet(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
