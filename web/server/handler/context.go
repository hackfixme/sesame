package handler

import "context"

type contextKey string

const (
	contextKeySharedKey    contextKey = "shared_key"
	contextKeyResponseData contextKey = "response_data"
)

func getSharedKey(ctx context.Context) []byte {
	if v := ctx.Value(contextKeySharedKey); v != nil {
		return v.([]byte) //nolint:errcheck,forcetypeassert // Acceptable risk; only set with constant key.
	}
	return []byte{}
}

func setSharedKey(ctx context.Context, key []byte) context.Context {
	return context.WithValue(ctx, contextKeySharedKey, key)
}

func getResponseData(ctx context.Context) []byte {
	if v := ctx.Value(contextKeyResponseData); v != nil {
		return v.([]byte) //nolint:errcheck,forcetypeassert // Acceptable risk; only set with constant key.
	}
	return []byte{}
}

func setResponseData(ctx context.Context, data []byte) context.Context {
	return context.WithValue(ctx, contextKeyResponseData, data)
}
