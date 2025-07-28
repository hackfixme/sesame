package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/mr-tron/base58"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/web/server/types"
)

// ResponseProcessor processes outgoing responses and can modify the response or context.
type ResponseProcessor func(ctx context.Context, resp types.Response) (context.Context, error)

// MarshalJSON encodes the response as JSON and stores it in the context for writing.
// It sets the appropriate Content-Type header.
func MarshalJSON(ctx context.Context, resp types.Response) (context.Context, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return ctx, fmt.Errorf("failed marshalling response into JSON: %w", err)
	}

	ctx = setResponseData(ctx, data)

	resp.GetHeader().Set("Content-Type", "application/json")

	return ctx, nil
}

// Encrypt encrypts response data using a shared key from the context.
// If no shared key is present, it passes through without modification.
func Encrypt(ctx context.Context, resp types.Response) (context.Context, error) {
	var (
		sharedKey = getSharedKey(ctx)
		data      = getResponseData(ctx)
	)
	if len(sharedKey) == 0 {
		// Nothing to do without a key.
		return ctx, nil
	}

	var keyArr [32]byte
	copy(keyArr[:], sharedKey)
	var err error
	data, err = crypto.EncryptSymInMemory(data, &keyArr)
	if err != nil {
		return ctx, fmt.Errorf("failed encrypting response: %w", err)
	}

	ctx = setResponseData(ctx, data)

	resp.GetHeader().Set("Content-Type", "application/octet-stream")

	return ctx, nil
}

// EncodeBase58 encodes response data using Base58 encoding.
func EncodeBase58(ctx context.Context, resp types.Response) (context.Context, error) {
	data := getResponseData(ctx)
	enc := base58.Encode(data)
	ctx = setResponseData(ctx, []byte(enc))
	resp.GetHeader().Set("Content-Type", "application/octet-stream")

	return ctx, nil
}

func writeResponse(ctx context.Context, w http.ResponseWriter, resp types.Response) error {
	data := getResponseData(ctx)

	// Respond with at least some kind of useful response, even if it's invalid.
	var terr *types.Error
	if len(data) == 0 && errors.As(resp.GetError(), &terr) {
		data = []byte(terr.Message)
	}

	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	w.WriteHeader(resp.GetStatusCode())
	_, err := w.Write(data)

	return err //nolint:wrapcheck // Wrapped by caller.
}
