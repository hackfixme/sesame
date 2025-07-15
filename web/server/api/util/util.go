package util

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes a JSON response to the HTTP response writer.
// It automatically sets the Content-Type header and HTTP status code.
func WriteJSON(w http.ResponseWriter, resp any) error {
	w.Header().Set("Content-Type", "application/json")

	// Extract status code from response
	if r, ok := resp.(interface{ GetStatusCode() int }); ok {
		w.WriteHeader(r.GetStatusCode())
	}

	return json.NewEncoder(w).Encode(resp)
}
