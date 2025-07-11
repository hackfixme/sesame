package errors

import (
	"errors"
	"maps"
)

// StructuredError enhances an error with structured metadata and a cause, which
// can be rendered as fields by slog.
type StructuredError struct {
	err      error
	metadata map[string]any
	cause    error
}

// Error implements the error interface.
func (e StructuredError) Error() string {
	return e.err.Error()
}

// Unwrap allows errors.Is and errors.As to work.
func (e StructuredError) Unwrap() []error {
	var errs []error
	if e.err != nil {
		errs = append(errs, e.err)
	}
	if e.cause != nil {
		errs = append(errs, e.cause)
	}
	return errs
}

// Cause returns the cause error of this error. Implements the errors.causer
// interface.
func (e StructuredError) Cause() error {
	return e.cause
}

// Metadata returns a copy of the metadata map.
func (e StructuredError) Metadata() map[string]any {
	if e.metadata == nil {
		return nil
	}
	result := make(map[string]any, len(e.metadata))
	maps.Copy(result, e.metadata)
	return result
}

// NewWith creates a new StructuredError from a message string with optional metadata.
func NewWith(msg string, fields ...any) *StructuredError {
	return With(errors.New(msg), fields...)
}

// NewWithCause creates a new StructuredError from a message string with a cause
// and optional metadata.
func NewWithCause(msg string, cause error, fields ...any) *StructuredError {
	return WithCause(errors.New(msg), cause, fields...)
}

// With adds metadata to an error. If the error is already a StructuredError,
// it merges the metadata. Otherwise, it creates a new StructuredError.
func With(err error, fields ...any) *StructuredError {
	if len(fields)%2 != 0 {
		panic("an even number of fields is required")
	}

	metadata := make(map[string]any, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			panic("keys must be strings")
		}
		metadata[key] = fields[i+1]
	}

	if me, ok := err.(*StructuredError); ok {
		combined := make(map[string]any, len(me.metadata)+len(metadata))
		maps.Copy(combined, me.metadata)
		maps.Copy(combined, metadata) // newer metadata overwrites older
		return &StructuredError{
			err:      me.err,
			metadata: combined,
			cause:    me.cause,
		}
	}

	return &StructuredError{
		err:      err,
		metadata: metadata,
	}
}

// WithCause creates a StructuredError with a cause and optional metadata.
func WithCause(err error, cause error, fields ...any) *StructuredError {
	if len(fields)%2 != 0 {
		panic("an even number of fields is required")
	}

	metadata := make(map[string]any, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			panic("keys must be strings")
		}
		metadata[key] = fields[i+1]
	}

	if me, ok := err.(*StructuredError); ok {
		combined := make(map[string]any, len(me.metadata)+len(metadata))
		maps.Copy(combined, me.metadata)
		maps.Copy(combined, metadata) // newer metadata overwrites older
		return &StructuredError{
			err:      me.err,
			metadata: combined,
			cause:    cause,
		}
	}

	return &StructuredError{
		err:      err,
		metadata: metadata,
		cause:    cause,
	}
}
