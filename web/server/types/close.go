package types

import "net/http"

// CloseRequest is the request data to deny access of one or more clients to a
// service.
type CloseRequest struct {
	BaseRequest `json:"-"`
	Clients     []string `json:"clients"`
	ServiceName string   `json:"service_name"`
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
