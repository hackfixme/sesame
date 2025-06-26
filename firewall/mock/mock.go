package mock

import (
	"time"

	"go4.org/netipx"

	"go.hackfix.me/sesame/models"
)

// Mock is a firewall implementation for testing that tracks allowed IP ranges
// and ports with expiration times. It can be configured to simulate errors for
// testing failure scenarios.
type Mock struct {
	Allowed map[string]map[uint16]time.Time
	failErr error // to simulate errors
	timeNow func() time.Time
}

var _ models.Firewall = (*Mock)(nil)

// New creates a new Mock firewall instance with the provided time function.
// The timeNow function is used to determine current time for expiration calculations.
func New(timeNow func() time.Time) *Mock {
	return &Mock{
		Allowed: make(map[string]map[uint16]time.Time),
		timeNow: timeNow,
	}
}

// Setup performs any necessary initialization for the firewall.
// Returns the configured failure error if one is set.
func (m *Mock) Setup() error {
	return m.failErr
}

// Allow grants access for the specified IP range to the destination port for
// the given duration. Returns the configured failure error if one is set,
// otherwise tracks the allowance with expiration time.
func (m *Mock) Allow(ipRange netipx.IPRange, destPort uint16, duration time.Duration) error {
	if m.failErr != nil {
		return m.failErr
	}
	ipStr := ipRange.String()
	ports, ok := m.Allowed[ipStr]
	if !ok {
		m.Allowed[ipStr] = make(map[uint16]time.Time)
	}
	ports[destPort] = m.timeNow().Add(duration)
	return nil
}

// SetFailError configures the mock to return the specified error from Setup()
// and Allow() calls. Pass nil to disable error simulation.
func (m *Mock) SetFailError(err error) {
	m.failErr = err
}
