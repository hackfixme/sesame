package types

// ClosePostRequestData is the request data to deny access of one or more
// clients to a service.
type ClosePostRequestData struct {
	Clients     []string `json:"clients"`
	ServiceName string   `json:"service_name"`
}

// ClosePostResponse represents a successful HTTP response to a request to grant
// access to one or more clients to a service.
type ClosePostResponse struct {
	Response
}
