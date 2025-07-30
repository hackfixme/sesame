package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"

	"go.hackfix.me/sesame/web/server/types"
)

// Handle creates an HTTP handler function that processes requests through a
// configurable pipeline. It supports generic request/response types and handles
// authentication, request/response processing, and error handling
// automatically.
//
// Unfortunately, it relies on reflection, and on passing values between
// components using the request context and type assertions. Achieving a simple
// and clear API with Go generics alone turned out to be impossible. The
// overhead of reflection likely means that this won't be suitable for servers
// where performance is paramount. Trading performance for API ergonomics was a
// deliberate design decision.
//
//nolint:gocognit // The complexity is a bit high, but refactoring this would hurt legibility.
func Handle[Req types.Request, Resp types.Response](
	handlerFn func(context.Context, Req) (Resp, error),
	p *Pipeline,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx  = r.Context()
			req  = createInstance[Req]()
			resp = createInstance[Resp]()
			err  error
		)

		req.SetHTTPRequest(r)

		handleErr := errorHandler(resp, p.errorLevel)

		// Response handling is deferred, since it should happen in both success and
		// error scenarios.
		defer func() {
			// Allow response handlers to modify headers.
			resp.SetHeader(w.Header())

			// 6. Response serialization (optional)
			if p.serializer != nil {
				if ctx, err = p.serializer.Serialize(ctx, resp); handleErr(err) {
					return
				}
			}

			// 7. Response processing
			for _, process := range p.responseProcessors {
				ctx, err = process(ctx, resp)
				if handleErr(err) {
					break
				}
			}

			// 8. Write the response
			if err = writeResponse(ctx, w, resp); err != nil {
				slog.Error("failed writing response", "error", err.Error())
			}
		}()

		// 1. Authentication (optional)
		if p.auth != nil {
			if ctx, err = p.auth(ctx, req); handleErr(err) {
				return
			}
		}

		// 2. Request deserialization (optional)
		if p.serializer != nil {
			if ctx, err = p.serializer.Deserialize(ctx, req); handleErr(err) {
				return
			}
		}

		// 3. Request validation (optional)
		if reqV, ok := any(req).(interface{ Validate() error }); ok {
			if err = reqV.Validate(); handleErr(err) {
				return
			}
		}

		// 4. Request processing
		for _, process := range p.requestProcessors {
			if ctx, err = process(ctx, req); handleErr(err) {
				return
			}
		}

		// 5. Run the handler
		handlerResp, handlerErr := handlerFn(ctx, req)
		if !isNilResponse(handlerResp) {
			resp = handlerResp
		}
		handleErr(handlerErr)
	}
}

// createInstance returns a new instance of type T.
//
// TODO: Consider caching reflection operations if this becomes a performance
// bottleneck at high throughput (>1000 req/s). Current overhead is negligible
// for low-traffic APIs. Profile before optimizing.
//
//nolint:ireturn,nolintlint // Required for generic functionality.
func createInstance[T any]() T {
	var zero T
	tType := reflect.TypeOf(zero)

	if tType == nil {
		panic("cannot create instance of nil interface type")
	}

	switch tType.Kind() {
	case reflect.Ptr:
		// Create new instance of the underlying type
		return reflect.New(tType.Elem()).Interface().(T) //nolint:errcheck,forcetypeassert // It's fine.
	case reflect.Interface:
		panic("cannot create instance of interface type - need concrete type")
	default:
		// For value types, return zero value directly
		return zero
	}
}

func isNilResponse(resp types.Response) bool {
	return resp == nil || reflect.ValueOf(resp).IsNil()
}

func errorHandler[Resp types.Response](resp Resp, errLvl types.ErrorLevel) func(error) bool {
	return func(err error) bool {
		if err == nil {
			return false
		}

		// Ensure that response handlers have a valid HTTP error and status code.
		var (
			terr       *types.Error
			statusCode = http.StatusInternalServerError
		)
		switch {
		case !errors.As(err, &terr) || terr == nil:
			terr = types.NewError(statusCode, err.Error())
		case terr.StatusCode == 0:
			terr.StatusCode = statusCode
		default:
			statusCode = terr.StatusCode
		}

		terr = sanitizeError(terr, errLvl)
		if terr != nil {
			statusCode = terr.StatusCode
		}

		resp.SetStatusCode(statusCode)
		resp.SetError(terr)
		return true
	}
}
