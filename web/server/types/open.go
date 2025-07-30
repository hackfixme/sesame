package types

import (
	"net/http"
	"time"
)

// OpenRequest is the request data to grant access of one or more clients to a
// service.
type OpenRequest struct {
	BaseRequest `json:"-"`
	Clients     []string      `json:"clients"`
	ServiceName string        `json:"service_name"`
	Duration    time.Duration `json:"duration"`
}

// Validate checks that the request is valid and ready for processing.
// Returns an error if validation fails.
func (r *OpenRequest) Validate() error {
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

// OpenResponse is the response to a request to grant access of one or more
// clients to a service.
type OpenResponse struct {
	BaseResponse
	Data OpenResponseData `json:"data"`
}

// OpenResponseData is the data sent in the OpenResponse.
type OpenResponseData struct{}

// NewOpenResponse creates a new OpenResponse with HTTP 200 status.
func NewOpenResponse() (*OpenResponse, error) {
	return &OpenResponse{
		BaseResponse: NewBaseResponse(http.StatusOK, nil),
	}, nil
}
