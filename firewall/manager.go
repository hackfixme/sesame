package firewall

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"go.hackfix.me/sesame/models"
)

// Manager manages access of client IPs to services.
type Manager struct {
	services map[string]models.Service
	firewall models.Firewall
	logger   *slog.Logger
}

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

// AllowAccess allows access of a client to a service for a specific duration.
func (m *Manager) AllowAccess(clientIP netip.Addr, serviceName string, duration time.Duration) error {
	svc, ok := m.services[serviceName]
	if !ok {
		return fmt.Errorf("unknown service: %s", serviceName)
	}
	logger := m.logger.With(
		"client_ip", clientIP,
		"service_name", serviceName,
		"service_port", svc.Port,
	)

	if duration > svc.MaxAccessDuration.V {
		logger.Debug("limiting access duration to configured service max",
			"requested_duration", duration,
			"service_max", svc.MaxAccessDuration,
		)
		duration = min(duration, svc.MaxAccessDuration.V)
	}

	logger = logger.With("duration", duration)
	logger.Debug("creating temporary access")

	if duration == 0 {
		logger.Warn("access duration is zero")
	}

	if err := m.firewall.Allow(clientIP, svc.Port.V, duration); err != nil {
		return fmt.Errorf("failed creating access for client %s to service %s: %w", clientIP, serviceName, err)
	}

	logger.Info("created temporary access")

	return nil
}
