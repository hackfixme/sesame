package types

import "time"

// OpenPostRequestData is the request data to grant access of one or more
// clients to a service.
type OpenPostRequestData struct {
	Clients     []string      `json:"clients"`
	ServiceName string        `json:"service_name"`
	Duration    time.Duration `json:"duration"`
}

// OpenPostResponse represents a successful HTTP response to a request to grant
// access to one or more clients to a service.
type OpenPostResponse struct {
	Response
}
