package common

import "errors"

// ErrInvalidToken is returned when a provided token is invalid (malformed,
// expired, etc.).
var ErrInvalidToken = errors.New("invalid token")
