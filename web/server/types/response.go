package types

// Response represents the base HTTP response structure.
type Response struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

// GetStatusCode returns the HTTP status code for the response.
func (r Response) GetStatusCode() int {
	return r.StatusCode
}
