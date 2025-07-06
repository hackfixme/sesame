package types

import (
	"errors"
	"fmt"

	"github.com/glebarez/go-sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// DuplicateError represents an error when attempting to create a record that
// already exists.
type DuplicateError struct {
	ModelName string
	ID        string
}

func (e DuplicateError) Error() string {
	return fmt.Sprintf("%s with %s already exists", e.ModelName, e.ID)
}

// IntegrityError represents a data integrity violation.
type IntegrityError struct {
	Msg string
}

// Error returns a string representation of the error.
func (e IntegrityError) Error() string {
	return fmt.Sprintf("integrity error: %s", e.Msg)
}

// InvalidInputError represents an error due to invalid input data.
type InvalidInputError struct {
	Msg string
}

// Error returns a string representation of the error.
func (e InvalidInputError) Error() string {
	return e.Msg
}

// LoadError represents an error that occurred while loading data from the database.
type LoadError struct {
	ModelName string
	Msg       string
	Err       error
}

// Error returns a string representation of the error.
func (e LoadError) Error() string {
	msg := e.Msg
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("failed loading %s: %s", e.ModelName, msg)
}

// Unwrap returns the underlying error for error unwrapping.
func (e LoadError) Unwrap() error {
	return e.Err
}

// NoResultError represents an error when a database query returns no results.
type NoResultError struct {
	ModelName string
	ID        string
}

// Error returns a string representation of the error.
func (e NoResultError) Error() string {
	return fmt.Sprintf("%s with %s doesn't exist", e.ModelName, e.ID)
}

// ReferenceError represents a foreign key constraint violation or similar
// reference error.
type ReferenceError struct {
	Msg string
	Err error
}

func (e ReferenceError) Error() string {
	return e.Msg
}

// Unwrap returns the underlying error for error unwrapping.
func (e ReferenceError) Unwrap() error {
	return e.Err
}

// ScanError represents an error that occurred while scanning database results
// into Go types.
type ScanError struct {
	ModelName string
	Err       error
}

// Error returns a string representation of the error.
func (e ScanError) Error() string {
	return fmt.Sprintf("failed scanning %s data: %s", e.ModelName, e.Err)
}

// Unwrap returns the underlying error for error unwrapping.
func (e ScanError) Unwrap() error {
	return e.Err
}

// Err converts an expected error returned by SQLite into a friendly DB error
// of one of the types defined above.
func Err(modelName, id string, err error) error {
	var sqlErr *sqlite.Error
	if !errors.As(err, &sqlErr) {
		return err
	}

	if sqlErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		return &DuplicateError{ModelName: modelName, ID: id}
	}

	return err
}
