package mock

import (
	"time"

	"go4.org/netipx"

	ftypes "go.hackfix.me/sesame/firewall/types"
)

// Mock is a firewall implementation for testing that tracks allowed IP ranges
// and ports with expiration times. It can be configured to simulate errors for
// testing failure scenarios.
type Mock struct {
	Allowed map[string]map[uint16]time.Time
	failErr error // to simulate errors
	timeNow func() time.Time
}

var _ ftypes.Firewall = (*Mock)(nil)

// New creates a new Mock firewall instance with the provided time function.
// The timeNow function is used to determine current time for expiration calculations.
func New(timeNow func() time.Time) *Mock {
	return &Mock{
		Allowed: make(map[string]map[uint16]time.Time),
		timeNow: timeNow,
	}
}

// Init performs any necessary initialization for the firewall.
// Returns the configured failure error if one is set.
func (m *Mock) Init() error {
	return m.failErr
}

// Allow grants access to the destination port from a set of IP addresses for a
// specific amount of time. It returns the configured failure error if one is
// set, otherwise tracks the allowance with expiration time.
func (m *Mock) Allow(ipSet *netipx.IPSet, destPort uint16, duration time.Duration) error {
	if m.failErr != nil {
		return m.failErr
	}
	ipRanges := ipSet.Ranges()
	for _, ipRange := range ipRanges {
		ipStr := ipRange.String()
		ports, ok := m.Allowed[ipStr]
		if !ok {
			ports = make(map[uint16]time.Time)
			m.Allowed[ipStr] = ports
		}
		ports[destPort] = m.timeNow().Add(duration)
	}

	return nil
}

// SetFailError configures the mock to return the specified error from Setup()
// and Allow() calls. Pass nil to disable error simulation.
func (m *Mock) SetFailError(err error) {
	m.failErr = err
}
