package models

import (
	"database/sql"
	"time"
)

// Service represents a process listening on a specific port that can be
// accessed by clients.
type Service struct {
	Name              sql.Null[string]
	Port              sql.Null[uint16]
	MaxAccessDuration sql.Null[time.Duration]
}
