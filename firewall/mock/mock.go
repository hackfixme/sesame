package mock

import (
	"time"

	"go4.org/netipx"

	"go.hackfix.me/sesame/models"
)

type Mock struct {
	Allowed map[string]map[uint16]time.Time
	failErr error // to simulate errors
	timeNow func() time.Time
}

var _ models.Firewall = (*Mock)(nil)

func New(timeNow func() time.Time) *Mock {
	return &Mock{
		Allowed: make(map[string]map[uint16]time.Time),
		timeNow: timeNow,
	}
}

func (m *Mock) Setup() error {
	return m.failErr
}

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

func (m *Mock) SetFailError(err error) {
	m.failErr = err
}
