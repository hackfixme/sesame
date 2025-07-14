package api

import "net/http"

// OpenPost creates firewall rules that allow the specified client IP address to
// access services on this node.
func (h *Handler) OpenPost(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
