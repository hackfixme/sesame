package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/felixge/httpsnoop"
)

// Logger logs request details and response metrics.
func Logger(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := httpsnoop.CaptureMetrics(next, w, r)
			logger.Info(
				fmt.Sprintf("%s %s", r.Method, r.URL),
				"response_code", m.Code,
				"duration", m.Duration,
				"bytes_sent", m.Written,
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}
