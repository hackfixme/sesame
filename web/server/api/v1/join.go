package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mr-tron/base58"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/models"
	dbtypes "go.hackfix.me/sesame/db/types"
	"go.hackfix.me/sesame/web/common"
	"go.hackfix.me/sesame/web/server/api/util"
	"go.hackfix.me/sesame/web/server/types"
)

// JoinPost authenticates a remote Sesame node, giving it access to privileged
// operations on this node, such as changing firewall rules.
//
// The request is expected to contain an Authorization header with a
// base58-encoded token that consists of a 32-byte nonce and an HMAC produced by
// hashing the nonce using a shared secret key from the ECDH key exchange. If
// the nonce is found in an existing and valid invitation record, the request
// body is read, which is expected to contain the client's X25519 public key. If
// successful, ECDH key exchange is performed to generate the shared secret key,
// which is used to verify the HMAC. If this succeeds, the client is considered
// authenticated, and a TLS client certificate is created, which is sent in the
// response along with the server CA certificate, encrypted with the shared
// secret key.
//
// See the inline comments for details about the process.
func (h *Handler) JoinPost(w http.ResponseWriter, r *http.Request) {
	// 1. Extract the nonce and HMAC from the token in Authorization header.
	token := r.Header.Get("Authorization")
	reqNonce, reqHMAC, err := common.DecodeToken(token)
	if err != nil {
		_ = util.WriteJSON(w, types.NewUnauthorizedError("invalid invite token"))
		return
	}

	// 2. Lookup the invite in the DB using the nonce.
	inv := &models.Invite{Nonce: reqNonce}
	if err := inv.Load(h.appCtx.DB.NewContext(), h.appCtx.DB); err != nil {
		var errNoRes dbtypes.NoResultError
		if errors.As(err, &errNoRes) {
			_ = util.WriteJSON(w, types.NewUnauthorizedError("invalid invite token"))
			return
		}

		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	// 3. Read the client's X25519 public key from the request body.
	clientPubKeyEnc, err := io.ReadAll(r.Body)
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	clientPubKeyData, err := base58.Decode(string(clientPubKeyEnc))
	if err != nil {
		_ = util.WriteJSON(w, types.NewBadRequestError(err.Error()))
		return
	}

	// 4. Perform ECDH key exchange to generate the shared secret key.
	sharedKey, _, err := crypto.ECDHExchange(clientPubKeyData, inv.PrivateKey().Bytes())
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	// 5a. Derive a secure HMAC key from the ECDH key.
	hmacKey, err := crypto.DeriveHMACKey(sharedKey, []byte("HMAC key derivation"))
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError("failed deriving HMAC key"))
		return
	}

	// 5b. Verify the HMAC received in the request.
	if !crypto.CheckHMAC(inv.Nonce, reqHMAC, hmacKey) {
		_ = util.WriteJSON(w, types.NewUnauthorizedError("invalid invite token"))
		return
	}

	serverTLSCert, err := h.appCtx.ServerTLSCert()
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	serverTLSCACert, err := crypto.ExtractCACert(serverTLSCert)
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	if len(serverTLSCACert.DNSNames) == 0 {
		_ = util.WriteJSON(w, types.NewInternalError("no Subject Alternative Name values found in server CA certificate"))
		return
	}

	// 6. The client is authenticated, so create the TLS client certificate,
	// signed by the server certificate.
	clientTLSCert, err := crypto.NewTLSCert(
		inv.User.Name, []string{serverTLSCACert.DNSNames[0]}, time.Now().Add(24*time.Hour), &serverTLSCert,
	)
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	// 7. Assemble the response payload, and serialize it to JSON.
	clientTLSCertPEM, err := crypto.SerializeTLSCert(clientTLSCert)
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	data := &types.JoinPostResponseData{
		TLSCACert:     serverTLSCACert.Raw,
		TLSClientCert: clientTLSCertPEM,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	// 8. Encrypt the JSON response data with the ECDH shared key.
	var sharedKeyArr [32]byte
	copy(sharedKeyArr[:], sharedKey)
	dataEnc, err := crypto.EncryptSymInMemory(dataJSON, &sharedKeyArr)
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	// 9. Mark the invite as redeemed so that it can't be used again.
	err = inv.Redeem(h.appCtx.DB.NewContext(), h.appCtx.DB, h.appCtx.TimeNow().UTC())
	if err != nil {
		_ = util.WriteJSON(w, types.NewInternalError(err.Error()))
		return
	}

	// 10. Write the response.
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, base58.Encode(dataEnc))
}
