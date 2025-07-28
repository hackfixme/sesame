package handler

// Pipeline defines the processing stages for HTTP requests and responses.
// It provides a fluent interface for configuring authentication and processors.
type Pipeline struct {
	auth               Authenticator
	requestProcessors  []RequestProcessor
	responseProcessors []ResponseProcessor
}

// NewPipeline creates a new empty pipeline for configuring request/response
// processing.
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// Auth sets the authenticator for this pipeline.
func (p *Pipeline) Auth(auth Authenticator) *Pipeline {
	p.auth = auth
	return p
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
