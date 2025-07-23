package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/web/server/api/util"
	"go.hackfix.me/sesame/web/server/types"
)

// ClosePost creates firewall rules that block access from specified IP addresses
// to services on this node. The client is expected to already have been
// authenticated with a TLS certificate (mTLS).
func (h *Handler) ClosePost(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(types.ConnTLSUserKey).(*models.User)
	if !ok {
		_ = util.WriteJSON(w, types.NewUnauthorizedError("user object not found in the request context"))
		return
	}

	// TODO: Use slog.Group
	logger := h.logger.With("user_name", user.Name)

	if !h.appCtx.Config.Firewall.Type.Valid {
		_ = util.WriteJSON(w, types.NewInternalError("no firewall was configured on this system"))
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	_, fwMgr, err := firewall.Setup(
		h.appCtx, h.appCtx.Config.Firewall.Type.V, h.appCtx.Config.Firewall.DefaultAccessDuration.V, logger,
	)
	if err != nil {
		h.logger.Warn("failed setting up firewall", "firewall_type", h.appCtx.Config.Firewall.Type.V, "error", err.Error())
		_ = util.WriteJSON(w, types.NewInternalError(fmt.Sprintf("failed setting up firewall: %s", err)))
		return
	}

	var reqData types.ClosePostRequestData
	err = json.Unmarshal(reqBody, &reqData)
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	// Assume that if no clients were specified, the service should be closed for all.
	clients := reqData.Clients
	if len(clients) == 0 {
		clients = []string{"0.0.0.0/0", "::/0"}
	}

	ipSet, err := firewall.ParseToIPSet(clients...)
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	svc := &models.Service{Name: reqData.ServiceName}
	if err = svc.Load(h.appCtx.DB.NewContext(), h.appCtx.DB); err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	err = fwMgr.DenyAccess(ipSet, svc)
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = util.WriteJSON(w, types.NewResponse(http.StatusOK, nil))
}
