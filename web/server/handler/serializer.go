package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.hackfix.me/sesame/web/server/types"
)

const maxBodyReadSize = 1024 * 1024 // 1MiB

// Serializer is the interface for deserializing the raw request body data into
// the typed request value, and for serializing the typed response value into
// the raw response data.
type Serializer interface {
	Deserialize(ctx context.Context, req types.Request) (context.Context, error)
	Serialize(ctx context.Context, resp types.Response) (context.Context, error)
}

// JSONSerializer implements JSON request and response serialization.
type JSONSerializer struct{}

var _ Serializer = (*JSONSerializer)(nil)

// JSON returns a new JSON serializer.
func JSON() JSONSerializer {
	return JSONSerializer{}
}

// Deserialize decodes JSON from the request body into the request object.
// It enforces a maximum body size limit to prevent resource exhaustion.
func (JSONSerializer) Deserialize(ctx context.Context, req types.Request) (context.Context, error) {
	httpReq := req.GetHTTPRequest()

	if httpReq.Body == nil {
		return ctx, errors.New("empty request body")
	}

	limitedReader := io.LimitReader(httpReq.Body, maxBodyReadSize)
	decoder := json.NewDecoder(limitedReader)
	if err := decoder.Decode(req); err != nil {
		return ctx, fmt.Errorf("failed decoding request body into JSON: %w", err)
	}

	return ctx, nil
}

// Serialize encodes the response as JSON and stores it in the context for writing.
// It sets the appropriate Content-Type header.
func (JSONSerializer) Serialize(ctx context.Context, resp types.Response) (context.Context, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return ctx, fmt.Errorf("failed marshalling response into JSON: %w", err)
	}

	ctx = setResponseData(ctx, data)

	resp.GetHeader().Set("Content-Type", "application/json")

	return ctx, nil
}
