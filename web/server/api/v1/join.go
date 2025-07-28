package api

import (
	"context"
	"net/http"
	"time"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/web/server/types"
)

// Join creates a TLS client certificate for a remote Sesame node, giving it
// access to privileged operations on this node, such as changing firewall rules.
// The client is expected to have previously been authenticated with a valid
// invitation token, and the response to be encrypted using a shared key
// produced by a successful ECDH key exchange. The bespoke authentication and
// encryption are required because this handler is meant to be served from a
// plain HTTP endpoint.
func (h *Handler) Join(_ context.Context, req *types.JoinRequest) (*types.JoinResponse, error) {
	if req.User == nil {
		return nil, types.NewError(http.StatusUnauthorized, "user object not found in the request context")
	}

	timeNow := h.appCtx.TimeNow()
	// TODO: Figure out certificate lifecycle management, make expiration configurable, etc.
	clientTLSCert, err := crypto.NewTLSCert(
		req.User.Name, []string{h.tlsCACert.DNSNames[0]}, timeNow, timeNow.Add(24*time.Hour), &h.tlsServerCert,
	)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}

	return types.NewJoinResponse(h.tlsCACert, clientTLSCert)
}
