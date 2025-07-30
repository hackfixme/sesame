package types

import "net/http"

// CloseRequest is the request data to deny access of one or more clients to a
// service.
type CloseRequest struct {
	BaseRequest `json:"-"`
	Clients     []string `json:"clients"`
	ServiceName string   `json:"service_name"`
}

// Validate checks that the request is valid and ready for processing.
// Returns an error if validation fails.
func (r *CloseRequest) Validate() error {
	if r.User == nil {
		return NewError(http.StatusUnauthorized, "user object not found in the request context")
	}

	if r.ServiceName == "" {
		return NewError(http.StatusBadRequest, "service name must not be empty")
	}

	if len(r.Clients) == 0 {
		return NewError(http.StatusBadRequest, "clients must not be empty")
	}

	return nil
}

// CloseResponse is the response to a request to deny access of one or more
// clients to a service.
type CloseResponse struct {
	BaseResponse
	Data CloseResponseData `json:"data"`
}

// CloseResponseData is the data sent in the CloseResponse.
type CloseResponseData struct{}

// NewCloseResponse creates a new CloseResponse with HTTP 200 status.
func NewCloseResponse() (*CloseResponse, error) {
	return &CloseResponse{
		BaseResponse: NewBaseResponse(http.StatusOK, nil),
	}, nil
}
