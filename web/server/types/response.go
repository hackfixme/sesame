package types

import (
	"errors"
	"net/http"
)

// Response defines the interface for HTTP response wrappers.
type Response interface {
	GetError() error
	SetError(error)
	GetStatusCode() int
	SetStatusCode(int)
	SetHeader(http.Header)
	GetHeader() http.Header
}

// BaseResponse represents the base HTTP response structure.
type BaseResponse struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Error      error  `json:"error,omitempty"`
	header     http.Header
}

var _ Response = (*BaseResponse)(nil)

// NewBaseResponse returns a new generic response with the specified status code and
// optional error.
func NewBaseResponse(statusCode int, err error) BaseResponse {
	resp := BaseResponse{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		header:     make(http.Header),
	}

	if err != nil {
		resp.Error = err
	}

	return resp
}

// GetError returns the error associated with this response.
func (r *BaseResponse) GetError() error {
	return r.Error
}

// SetError sets the error for this response.
func (r *BaseResponse) SetError(err error) {
	r.Error = err
}

// GetStatusCode returns the HTTP status code for the response.
func (r *BaseResponse) GetStatusCode() int {
	code := r.StatusCode
	var terr *Error
	if code == 0 && errors.As(r.Error, &terr) {
		code = terr.StatusCode
	}
	return code
}

// SetStatusCode sets the HTTP status code and updates the status text.
func (r *BaseResponse) SetStatusCode(code int) {
	r.StatusCode = code
	r.Status = http.StatusText(code)
}

// GetHeader returns the HTTP headers for this response.
func (r *BaseResponse) GetHeader() http.Header {
	return r.header
}

// SetHeader sets the HTTP headers for this response.
func (r *BaseResponse) SetHeader(h http.Header) {
	r.header = h
}
