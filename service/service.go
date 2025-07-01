package service

import (
	"database/sql"
	"time"
)

// Service represents a process listening on a specific port that can be
// accessed by clients.
type Service struct {
	Name              sql.Null[string]        `json:"name"`
	Port              sql.Null[uint16]        `json:"port"`
	MaxAccessDuration sql.Null[time.Duration] `json:"max_access_duration"`
}
