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
