package firewall

import (
	"fmt"
	"log/slog"
	"time"

	"go4.org/netipx"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/nftables"
	ftypes "go.hackfix.me/sesame/firewall/types"
	svc "go.hackfix.me/sesame/service"
)

// Manager manages access of client IPs to services.
type Manager struct {
	services map[string]svc.Service
	firewall ftypes.Firewall
	logger   *slog.Logger
}

// NewManager returns a new Manager instance.
func NewManager(firewall ftypes.Firewall, services map[string]svc.Service, opts ...Option) (*Manager, error) {
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

// Setup creates a new Firewall with the given type and a Manager for it that
// uses configured services.
//
//nolint:ireturn // Intentional, this is a generic function.
func Setup(appCtx *actx.Context, ft ftypes.FirewallType) (ftypes.Firewall, *Manager, error) {
	var (
		fw  ftypes.Firewall
		err error
	)
	switch ft {
	case ftypes.FirewallMock:
		fw = mock.New(appCtx.TimeNow)
	case ftypes.FirewallNFTables:
		fw, err = nftables.New(appCtx.Logger)
	default:
		return nil, nil, fmt.Errorf("unsupported firewall type '%s'", ft)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating %s firewall: %w", ft, err)
	}

	var fwMgr *Manager
	fwMgr, err = NewManager(
		fw, appCtx.Config.Services,
		WithLogger(appCtx.Logger),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating the firewall manager: %w", err)
	}

	return fw, fwMgr, nil
}
