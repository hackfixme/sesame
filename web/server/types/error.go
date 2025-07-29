package types

// ErrorLevel is the detail level of error messages returned to clients from
// untrusted HTTP endpoints (e.g. /join), in order to avoid leaking sensitive
// information. This doesn't affect response status codes.
type ErrorLevel string

const (
	// ErrorLevelNone hides all error messages.
	ErrorLevelNone ErrorLevel = "none"
	// ErrorLevelMinimal sanitizes error messages to keep messages generic.
	ErrorLevelMinimal ErrorLevel = "minimal"
	// ErrorLevelFull keeps error messages intact.
	ErrorLevelFull ErrorLevel = "full"
)

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
