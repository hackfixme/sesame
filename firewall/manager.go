package firewall

import (
	"fmt"
	"log/slog"
	"time"

	"go4.org/netipx"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/nftables"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

// Manager manages access of client IPs to services.
type Manager struct {
	firewall              ftypes.Firewall
	defaultAccessDuration time.Duration
	logger                *slog.Logger
}

// NewManager returns a new Manager instance.
func NewManager(firewall ftypes.Firewall, opts ...Option) (*Manager, error) {
	if firewall == nil {
		return nil, fmt.Errorf("firewall implementation is required")
	}

	m := &Manager{firewall: firewall}

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
func (m *Manager) AllowAccess(ipSet *netipx.IPSet, svc *models.Service, duration time.Duration) error {
	logger := m.logger.With(
		"service_name", svc.Name,
		"service_port", svc.Port,
	)

	if duration > svc.MaxAccessDuration {
		logger.Warn("requested duration exceeds configured service max; clamping to max",
			"requested_duration", duration,
			"service_max", svc.MaxAccessDuration,
		)
		duration = min(duration, svc.MaxAccessDuration)
	}
	if duration == 0 {
		duration = m.defaultAccessDuration
	}

	logger = logger.With("duration", duration)

	for _, ipRange := range ipSet.Ranges() {
		logger.With("client_ip_range", ipRange.String()).Debug("granting access")

		if err := m.firewall.Allow(ipRange, svc.Port, duration); err != nil {
			return fmt.Errorf("failed creating access for client IP range '%s' to service %s: %w", ipRange, svc.Name, err)
		}

		logger.With("client_ip_range", ipRange.String()).Info("granted access")
	}

	return nil
}

// Setup creates a new Firewall with the given type and a Manager for it that
// uses configured services.
//
//nolint:ireturn // Intentional, this is a generic function.
func Setup(
	appCtx *actx.Context, ft ftypes.FirewallType, defaultAccessDuration time.Duration,
	logger *slog.Logger,
) (ftypes.Firewall, *Manager, error) {
	var (
		fw  ftypes.Firewall
		err error
	)
	switch ft {
	case ftypes.FirewallMock:
		fw = mock.New(appCtx.TimeNow, logger)
	case ftypes.FirewallNFTables:
		fw, err = nftables.New(defaultAccessDuration, logger)
	default:
		return nil, nil, fmt.Errorf("unsupported firewall type '%s'", ft)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating %s firewall: %w", ft, err)
	}

	var fwMgr *Manager
	fwMgr, err = NewManager(fw, WithLogger(logger))
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating the firewall manager: %w", err)
	}

	return fw, fwMgr, nil
}
