package api

import (
	"context"
	"net/http"

	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/web/server/types"
)

// Close creates firewall rules that block access from specified IP addresses
// to services on this node. The client is expected to have previously been
// authenticated with a valid TLS client certificate (mTLS).
func (h *Handler) Close(_ context.Context, req *types.CloseRequest) (*types.CloseResponse, error) {
	if req.User == nil {
		return nil, types.NewError(http.StatusUnauthorized, "user object not found in the request context")
	}

	// Assume that if no clients were specified, the service should be closed for all.
	clients := req.Clients
	if len(clients) == 0 {
		clients = []string{"0.0.0.0/0", "::/0"}
	}

	ipSet, err := firewall.ParseToIPSet(clients...)
	if err != nil {
		return nil, types.NewError(http.StatusBadRequest, err.Error())
	}

	svc := &models.Service{Name: req.ServiceName}
	//nolint:contextcheck // This context is inherited from the global context.
	if err = svc.Load(h.appCtx.DB.NewContext(), h.appCtx.DB); err != nil {
		return nil, types.NewError(http.StatusBadRequest, err.Error())
	}

	err = h.fwMgr.DenyAccess(ipSet, svc, req.User)
	if err != nil {
		return nil, types.NewError(http.StatusBadRequest, err.Error())
	}

	return types.NewCloseResponse()
}
