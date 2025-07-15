package middleware

import (
	"net/http"
)

// Middleware is a function that wraps an http.Handler to provide additional
// functionality such as logging, authentication, CORS, etc. It takes a handler
// and returns a new handler.
type Middleware func(http.Handler) http.Handler

// asMiddleware converts an http.Handler to a Middleware
func asMiddleware(h http.Handler) Middleware {
	return func(next http.Handler) http.Handler {
		return h
	}
}

// Chain chains middlewares and handlers in the exact order specified.
// Each item wraps the next one, so execution flows from left to right.
func Chain(items ...any) http.Handler {
	var middlewares []Middleware

	for _, item := range items {
		switch v := item.(type) {
		case Middleware:
			middlewares = append(middlewares, v)
		case http.Handler:
			middlewares = append(middlewares, asMiddleware(v))
		default:
			panic("ChainHandlers accepts only Middleware or http.Handler")
		}
	}

	// Start with a no-op handler
	var result http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Apply middlewares from right to left to get left-to-right execution
	for i := len(middlewares) - 1; i >= 0; i-- {
		result = middlewares[i](result)
	}

	return result
}
