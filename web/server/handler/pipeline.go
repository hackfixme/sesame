package handler

import (
	"net/http"

	"go.hackfix.me/sesame/web/server/types"
)

// Pipeline defines the processing stages for HTTP requests and responses.
// It provides a fluent interface for configuring authentication and processors.
type Pipeline struct {
	auth               Authenticator
	serializer         Serializer
	requestProcessors  []RequestProcessor
	responseProcessors []ResponseProcessor
	errorLevel         types.ErrorLevel
}

// NewPipeline creates a new empty pipeline for configuring request/response
// processing.
func NewPipeline(errorLevel types.ErrorLevel) *Pipeline {
	return &Pipeline{errorLevel: errorLevel}
}

// ProcessRequest adds one or more request processors to the pipeline.
func (p *Pipeline) ProcessRequest(processor ...RequestProcessor) *Pipeline {
	p.requestProcessors = append(p.requestProcessors, processor...)
	return p
}

// ProcessResponse adds one or more response processors to the pipeline.
func (p *Pipeline) ProcessResponse(processor ...ResponseProcessor) *Pipeline {
	p.responseProcessors = append(p.responseProcessors, processor...)
	return p
}

// WithAuth sets the authenticator for this pipeline.
func (p *Pipeline) WithAuth(auth Authenticator) *Pipeline {
	p.auth = auth
	return p
}

// WithSerializer sets the request and response serializer for this pipeline.
func (p *Pipeline) WithSerializer(s Serializer) *Pipeline {
	p.serializer = s
	return p
}

func sanitizeError(terr *types.Error, lvl types.ErrorLevel) *types.Error {
	if lvl == types.ErrorLevelNone {
		return nil
	}

	if lvl == types.ErrorLevelMinimal {
		switch terr.StatusCode {
		case http.StatusUnauthorized:
			return types.NewError(terr.StatusCode, "authentication failed")
		case http.StatusBadRequest:
			return types.NewError(terr.StatusCode, "invalid request")
		default:
			return types.NewError(terr.StatusCode, "request failed")
		}
	}

	return terr
}
