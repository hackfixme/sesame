package models

import "time"

// TimeSource is the source of time information.
type TimeSource interface {
	Now() time.Time
}
