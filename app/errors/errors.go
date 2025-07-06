package errors

import (
	"errors"
	"fmt"
	"log/slog"
)

// WithCause represents an error that can provide its underlying cause.
type WithCause interface{ Cause() error }

// WithHint represents an error that can provide a helpful hint for resolution.
type WithHint interface{ Hint() string }

// WithMessage represents an error that can provide its core message.
type WithMessage interface{ Message() string }

// RuntimeError represents a runtime error with an optional cause and hint.
type RuntimeError struct {
	msg   string
	cause error
	hint  string
}

// NewRuntimeError creates a new Runtime error with the given message, cause, and hint.
func NewRuntimeError(msg string, cause error, hint string) RuntimeError {
	return RuntimeError{msg: msg, cause: cause, hint: hint}
}

// Error returns the string representation of this runtime error.
func (e RuntimeError) Error() string {
	msgFmt := "%s"
	args := []any{e.msg}
	if e.cause != nil {
		msgFmt += ": %s"
		args = append(args, e.cause.Error())
	}
	if e.hint != "" {
		msgFmt += " (%s)"
		args = append(args, e.hint)
	}
	return fmt.Sprintf(msgFmt, args...)
}

// Cause returns the underlying error that caused this runtime error.
func (e RuntimeError) Cause() error {
	return e.cause
}

// Hint returns a helpful hint for resolving this runtime error.
func (e RuntimeError) Hint() string {
	return e.hint
}

// Message returns the core message of this runtime error.
func (e RuntimeError) Message() string {
	return e.msg
}

// Errorf logs an error message, extracting a hint or cause field if available.
func Errorf(err error, args ...any) {
	var rtErr RuntimeError
	if errors.As(err, &rtErr) {
		err = rtErr
	}
	msg := err.Error()
	if errh, ok := err.(WithMessage); ok {
		mmsg := errh.Message()
		if mmsg != "" {
			msg = mmsg
		}
	}
	if errh, ok := err.(WithHint); ok {
		hint := errh.Hint()
		if hint != "" {
			args = append([]any{"hint", hint}, args...)
		}
	}
	if errc, ok := err.(WithCause); ok {
		cause := errc.Cause()
		if cause != nil {
			args = append([]any{"cause", cause}, args...)
		}
	}

	slog.Error(msg, args...)
}
