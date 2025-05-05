package models

import (
	"time"
)

// Service represents a process listening on a specific port that can be
// accessed by clients.
type Service struct {
	Name              string
	Port              uint16
	MaxAccessDuration time.Duration
}
