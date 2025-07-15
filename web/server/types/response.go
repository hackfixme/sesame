package types

import "net/http"

// Response represents the base HTTP response structure.
type Response struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

// NewResponse returns a new generic response with the specified status code and
// optional error.
func NewResponse(statusCode int, err error) *Response {
	resp := &Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
	}

	if err != nil {
		resp.Error = err.Error()
	}

	return resp
}

// GetStatusCode returns the HTTP status code for the response.
func (r Response) GetStatusCode() int {
	return r.StatusCode
}
