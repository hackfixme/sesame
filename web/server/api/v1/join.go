package api

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/models"
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
	timeNow := h.appCtx.TimeNow()
	// TODO: Figure out certificate lifecycle management, make expiration configurable, etc.
	clientTLSCert, err := crypto.NewTLSCert(
		req.User.Name, []string{h.tlsCACert.DNSNames[0]}, timeNow, timeNow.Add(24*time.Hour), &h.tlsServerCert,
	)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}

	// Store a record of the client certificate.
	var clientTLSx509Cert *x509.Certificate
	clientTLSx509Cert, err = crypto.ExtractLeafCert(clientTLSCert)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}

	var cc *models.ClientCertificate
	cc, err = models.NewClientCertificate(req.User, req.SiteID,
		h.appCtx.Config.Client.TLSCertRenewalTokenExpiration.V, clientTLSx509Cert)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}

	//nolint:contextcheck // This context is inherited from the global context.
	err = cc.Save(h.appCtx.DB.NewContext(), h.appCtx.DB, false)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}

	return types.NewJoinResponse(h.tlsCACert, clientTLSCert)
}
