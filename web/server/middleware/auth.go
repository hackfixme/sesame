package middleware

import (
	"context"
	"log/slog"
	"net/http"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/web/server/api/util"
	"go.hackfix.me/sesame/web/server/types"
)

// Authn authenticates the Sesame user from the received TLS client certificate,
// and loads the User record in the request context given that the Subject
// Common Name matches an existing User name. For this to be reached, the
// resource needs to have been accessed with a valid client certificate, which
// is validated in the Go runtime, before reaching Sesame HTTP endpoints.
//
// If this fails, a response with status 401 Unauthorized is returned. Otherwise
// the request is allowed to proceed.
func Authn(appCtx *actx.Context, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
				_ = util.WriteJSON(w, types.NewUnauthorizedError("failed TLS authentication"))
				return
			}

			subjectCN := r.TLS.VerifiedChains[0][0].Subject.CommonName
			user := &models.User{Name: subjectCN}
			if err := user.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
				logger.Warn(
					"failed loading user with the received TLS client certificate",
					"subject_common_name", subjectCN, "error", err.Error())
				_ = util.WriteJSON(w, types.NewUnauthorizedError("failed loading user identified in the client TLS certificate"))
				return
			}

			ctx := context.WithValue(r.Context(), types.ConnTLSUserKey, user)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
