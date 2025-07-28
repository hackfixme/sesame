package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.hackfix.me/sesame/web/server/types"
)

const maxBodySize = 1024 * 1024 // 1MiB

// RequestProcessor processes incoming requests and can modify the request or context.
type RequestProcessor func(ctx context.Context, req types.Request) (context.Context, error)

// UnmarshalJSON decodes JSON from the request body into the request object.
// It enforces a maximum body size limit to prevent resource exhaustion.
func UnmarshalJSON(ctx context.Context, req types.Request) (context.Context, error) {
	httpReq := req.GetHTTPRequest()

	if httpReq.Body == nil {
		return ctx, errors.New("empty request body")
	}

	limitedReader := io.LimitReader(httpReq.Body, maxBodySize)
	decoder := json.NewDecoder(limitedReader)
	if err := decoder.Decode(req); err != nil {
		return ctx, fmt.Errorf("failed decoding request body into JSON: %w", err)
	}

	return ctx, nil
}
