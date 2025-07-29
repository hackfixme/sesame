package types

import (
	"net/http"
)

// Response defines the interface for HTTP response wrappers.
type Response interface {
	GetError() *Error
	SetError(*Error)
	GetStatusCode() int
	SetStatusCode(int)
	SetHeader(http.Header)
	GetHeader() http.Header
}

// BaseResponse represents the base HTTP response structure.
type BaseResponse struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Error      *Error `json:"error,omitempty"`
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
		resp.Error = &Error{StatusCode: statusCode, Message: err.Error()}
	}

	return resp
}

// GetError returns the error associated with this response.
func (r *BaseResponse) GetError() *Error {
	return r.Error
}

// SetError sets the error for this response.
func (r *BaseResponse) SetError(err *Error) {
	r.Error = err
}

// GetStatusCode returns the HTTP status code for the response.
func (r *BaseResponse) GetStatusCode() int {
	code := r.StatusCode
	if code == 0 && r.Error != nil && r.Error.StatusCode > 0 {
		code = r.Error.StatusCode
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
