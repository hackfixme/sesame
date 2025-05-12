package firewall

import (
	"fmt"
	"log/slog"
	"time"

	"go4.org/netipx"

	"go.hackfix.me/sesame/models"
)

// Manager manages access of client IPs to services.
type Manager struct {
	services map[string]models.Service
	firewall models.Firewall
	logger   *slog.Logger
}

var _ models.FirewallManager = &Manager{}

// NewManager returns a new Manager instance.
func NewManager(firewall models.Firewall, services map[string]models.Service, opts ...Option) (*Manager, error) {
	if firewall == nil {
		return nil, fmt.Errorf("firewall implementation is required")
	}

	m := &Manager{
		services: services,
		firewall: firewall,
	}

	opts = append(DefaultOptions(), opts...)
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	if err := m.firewall.Setup(); err != nil {
		return nil, fmt.Errorf("firewall setup failed: %w", err)
	}

	return m, nil
}

// AllowAccess allows access of client IP addresses to a service for a specific
// duration. The passed IPSet must consist of valid IPRanges.
func (m *Manager) AllowAccess(ipSet *netipx.IPSet, serviceName string, duration time.Duration) error {
	svc, ok := m.services[serviceName]
	if !ok {
		return fmt.Errorf("unknown service: %s", serviceName)
	}

	logger := m.logger.With(
		"service_name", serviceName,
		"service_port", svc.Port.V,
	)

	if duration > svc.MaxAccessDuration.V {
		logger.Debug("limiting access duration to configured service max",
			"requested_duration", duration,
			"service_max", svc.MaxAccessDuration.V,
		)
		duration = min(duration, svc.MaxAccessDuration.V)
	}

	logger = logger.With("duration", duration)

	for _, ipRange := range ipSet.Ranges() {
		logger.With("client_ip_range", ipRange.String()).Debug("creating temporary access")

		if err := m.firewall.Allow(ipRange, svc.Port.V, duration); err != nil {
			return fmt.Errorf("failed creating access for client IP range '%s' to service %s: %w", ipRange, serviceName, err)
		}

		logger.With("client_ip_range", ipRange.String()).Info("created temporary access")
	}

	return nil
}
