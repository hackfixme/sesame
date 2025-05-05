package mock

import (
	"net/netip"
	"time"

	"go.hackfix.me/sesame/models"
)

type Mock struct {
	Allowed map[string]map[uint16]time.Time
	failErr error // to simulate errors
	ts      models.TimeSource
}

var _ models.Firewall = &Mock{}

func New(ts models.TimeSource) *Mock {
	return &Mock{
		Allowed: make(map[string]map[uint16]time.Time),
		ts:      ts,
	}
}

func (m *Mock) Setup() error {
	return m.failErr
}

func (m *Mock) Allow(srcIP netip.Addr, destPort uint16, duration time.Duration) error {
	if m.failErr != nil {
		return m.failErr
	}
	ipStr := srcIP.String()
	ports, ok := m.Allowed[ipStr]
	if !ok {
		m.Allowed[ipStr] = make(map[uint16]time.Time)
	}
	ports[destPort] = m.ts.Now().Add(duration)
	return nil
}

func (m *Mock) SetFailError(err error) {
	m.failErr = err
}
