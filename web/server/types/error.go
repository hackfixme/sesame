package types

// Error represents an HTTP error with status code and message.
type Error struct {
	StatusCode int    `json:"-"`
	Message    string `json:"message"`
}

// Error returns the error message string.
func (e Error) Error() string {
	return e.Message
}

// NewError creates a new Error with the specified status code and message.
func NewError(statusCode int, message string) *Error {
	return &Error{
		StatusCode: statusCode,
		Message:    message,
	}
}
