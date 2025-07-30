package handler

import (
	"context"

	"go.hackfix.me/sesame/web/server/types"
)

// RequestProcessor processes incoming requests and can modify the request or context.
type RequestProcessor func(ctx context.Context, req types.Request) (context.Context, error)
