package types

import "net/http"

// BadRequestError represents a 400 Bad Request HTTP response.
type BadRequestError struct {
	Response
}

// NewBadRequestError creates a new BadRequestError with the specified message.
func NewBadRequestError(message string) *BadRequestError {
	return &BadRequestError{
		Response: Response{
			StatusCode: http.StatusBadRequest,
			Status:     http.StatusText(http.StatusBadRequest),
			Error:      message,
		},
	}
}

// NotFoundError represents a 404 Not Found HTTP response.
type NotFoundError struct {
	Response
}

// NewNotFoundError creates a new NotFoundError with the specified message.
func NewNotFoundError(message string) *NotFoundError {
	return &NotFoundError{
		Response: Response{
			StatusCode: http.StatusNotFound,
			Status:     http.StatusText(http.StatusNotFound),
			Error:      message,
		},
	}
}

// InternalError represents a 500 Internal Server Error HTTP response.
type InternalError struct {
	Response
}

// NewInternalError creates a new InternalError with the specified message.
func NewInternalError(message string) *InternalError {
	return &InternalError{
		Response: Response{
			StatusCode: http.StatusInternalServerError,
			Status:     http.StatusText(http.StatusInternalServerError),
			Error:      message,
		},
	}
}

// UnauthorizedError represents a 401 Unauthorized HTTP response.
type UnauthorizedError struct {
	Response
}

// NewUnauthorizedError creates a new UnauthorizedError with the specified message.
func NewUnauthorizedError(message string) *UnauthorizedError {
	return &UnauthorizedError{
		Response: Response{
			StatusCode: http.StatusUnauthorized,
			Status:     http.StatusText(http.StatusUnauthorized),
			Error:      message,
		},
	}
}
