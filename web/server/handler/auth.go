package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/mr-tron/base58"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/models"
	dbtypes "go.hackfix.me/sesame/db/types"
	"go.hackfix.me/sesame/web/common"
	"go.hackfix.me/sesame/web/server/types"
)

// Authenticator validates a request and returns an updated context or an error.
// If authentication is successful, a valid User will be set on the Request.
type Authenticator func(context.Context, types.Request) (context.Context, error)

// TLSAuth creates an authenticator that validates requests using client TLS
// certificates. It extracts the Common Name from the verified certificate chain
// and loads the corresponding user.
func TLSAuth(appCtx *actx.Context) Authenticator {
	return func(ctx context.Context, req types.Request) (context.Context, error) {
		r := req.GetHTTPRequest()
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			return ctx, types.NewError(http.StatusUnauthorized, "failed TLS authentication")
		}

		subjectCN := r.TLS.VerifiedChains[0][0].Subject.CommonName
		user := &models.User{Name: subjectCN}
		if err := user.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			return ctx, types.NewError(http.StatusUnauthorized,
				"failed loading user identified in the client TLS certificate")
		}

		req.SetUser(user)

		return ctx, nil
	}
}

// InviteTokenAuth creates an authenticator that validates invite tokens using
// ECDH key exchange and HMAC authentication. If successful, it marks the invite
// as redeemed.
// See the inline comments for details about the process.
func InviteTokenAuth(appCtx *actx.Context) Authenticator {
	return func(ctx context.Context, req types.Request) (context.Context, error) {
		r := req.GetHTTPRequest()

		// 1. Extract the encoded invitation token and client's X25519 public key
		// from the Authorization header.
		tokenEnc, clientPubKeyEnc, err := parseAuthHeader(r.Header.Get("Authorization"))
		if err != nil {
			return ctx, types.NewError(http.StatusUnauthorized, err.Error())
		}
		if tokenEnc == "" || clientPubKeyEnc == "" {
			return ctx, types.NewError(http.StatusUnauthorized, "must provide an invite token and public key")
		}

		// 2. Decode the invitation token into an invite nonce and HMAC.
		nonce, hmac, err := common.DecodeToken(tokenEnc)
		if err != nil {
			return ctx, types.NewError(http.StatusUnauthorized, "invalid invite token")
		}

		// 3. Lookup the invite in the DB using the nonce.
		inv := &models.Invite{Nonce: nonce}
		if err = inv.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			var errNoRes dbtypes.NoResultError
			if errors.As(err, &errNoRes) {
				return ctx, types.NewError(http.StatusUnauthorized, "invite not found")
			}
			return ctx, types.NewError(http.StatusBadRequest, err.Error())
		}

		// 4. Decode the client's X25519 public key.
		clientPubKeyData, err := base58.Decode(clientPubKeyEnc)
		if err != nil {
			return ctx, types.NewError(http.StatusBadRequest, err.Error())
		}

		// 5. Perform ECDH key exchange to generate the shared secret key.
		sharedKey, _, err := crypto.ECDHExchange(clientPubKeyData, inv.PrivateKey().Bytes())
		if err != nil {
			return ctx, types.NewError(http.StatusInternalServerError, err.Error())
		}

		// 6a. Derive a secure HMAC key from the ECDH key.
		hmacKey, err := crypto.DeriveHMACKey(sharedKey, []byte("HMAC key derivation"))
		if err != nil {
			return ctx, types.NewError(http.StatusInternalServerError, err.Error())
		}

		// 6b. Verify the HMAC received in the request.
		if !crypto.CheckHMAC(inv.Nonce, hmac, hmacKey) {
			return ctx, types.NewError(http.StatusUnauthorized, "invalid invite token")
		}

		// 7. At this point the client is authenticated, so mark the invite as redeemed
		// to prevent it from being used again.
		err = inv.Redeem(appCtx.DB.NewContext(), appCtx.DB, appCtx.TimeNow().UTC())
		if err != nil {
			return ctx, types.NewError(http.StatusInternalServerError, err.Error())
		}

		req.SetUser(inv.User)

		// Store the shared key in the context, since it has to be used for
		// encrypting the response.
		ctx = setSharedKey(ctx, sharedKey)

		return ctx, nil
	}
}

// parseAuthHeader parses a Bearer token from an Authorization header, optionally
// with additional data after a semicolon delimiter.
func parseAuthHeader(header string) (token, rest string, err error) {
	if header == "" {
		return "", "", errors.New("empty Authorization header")
	}

	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", errors.New("invalid Authorization header scheme")
	}

	payload := strings.TrimPrefix(header, "Bearer ")
	parts := strings.SplitN(payload, ";", 2)

	token = parts[0]
	if len(parts) == 2 {
		rest = parts[1]
	}

	return token, rest, nil
}
