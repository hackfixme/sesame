package firewall_test

import (
	"database/sql"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/types"
	svc "go.hackfix.me/sesame/service"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		firewall types.Firewall
		expErr   string
	}{
		{
			name:     "ok/valid",
			firewall: mock.New(time.Now),
		},
		{
			name:     "err/nil_firewall",
			firewall: nil,
			expErr:   "firewall implementation is required",
		},
		{
			name:     "err/firewall_setup_fail",
			firewall: setupFailingMock(),
			expErr:   "firewall setup failed: setup error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			services := make(map[string]svc.Service)
			manager, err := firewall.NewManager(tt.firewall, services)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Nil(t, manager)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, manager)
			}
		})
	}

	t.Run("ok/custom_logger", func(t *testing.T) {
		t.Parallel()

		mockFirewall := mock.New(time.Now)
		services := make(map[string]svc.Service)
		logger := slog.New(slog.DiscardHandler)
		manager, err := firewall.NewManager(mockFirewall, services, firewall.WithLogger(logger))
		require.NoError(t, err)
		assert.NotNil(t, manager)
	})
}

func TestManager_AllowAccess(t *testing.T) {
	t.Parallel()

	services := map[string]svc.Service{
		"web": {
			Name:              sql.Null[string]{V: "web", Valid: true},
			Port:              sql.Null[uint16]{V: 80, Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: 1 * time.Hour, Valid: true},
		},
		"db": {
			Name:              sql.Null[string]{V: "db", Valid: true},
			Port:              sql.Null[uint16]{V: 5432, Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
		},
	}

	tests := []struct {
		name        string
		ipAddr      []string
		serviceName string
		duration    time.Duration
		setupError  bool
		expErr      string
	}{
		{
			name:        "ok/single_ip",
			ipAddr:      []string{"192.168.1.100"},
			serviceName: "web",
			duration:    30 * time.Minute,
		},
		{
			name:        "ok/multiple_ips",
			ipAddr:      []string{"192.168.1.100", "10.0.0.5"},
			serviceName: "web",
			duration:    30 * time.Minute,
		},
		{
			name:        "ok/cidr_notation",
			ipAddr:      []string{"192.168.1.0/24"},
			serviceName: "web",
			duration:    30 * time.Minute,
		},
		{
			name:        "ok/ip_range",
			ipAddr:      []string{"192.168.1.1-192.168.1.10"},
			serviceName: "web",
			duration:    30 * time.Minute,
		},
		{
			name:        "ok/duration_limited_by_service_max",
			ipAddr:      []string{"192.168.1.100"},
			serviceName: "db",
			duration:    2 * time.Hour,
		},
		{
			name:        "err/unknown_service",
			ipAddr:      []string{"192.168.1.100"},
			serviceName: "unknown",
			duration:    30 * time.Minute,
			expErr:      "unknown service: unknown",
		},
		{
			name:        "err/firewall_allow_fails",
			ipAddr:      []string{"192.168.1.100"},
			serviceName: "web",
			duration:    30 * time.Minute,
			setupError:  true,
			expErr:      "failed creating access for client IP range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFirewall := mock.New(timeNowFn)

			// For the firewall allow failure test, we need to create the manager first
			// (without error) then set the error for the Allow operation.
			manager, err := firewall.NewManager(
				mockFirewall, services,
				firewall.WithLogger(slog.New(slog.DiscardHandler)),
			)
			require.NoError(t, err)

			if tt.setupError {
				mockFirewall.SetFailError(errors.New("firewall error"))
			}

			ipSet, err := firewall.ParseToIPSet(tt.ipAddr...)
			require.NoError(t, err)

			err = manager.AllowAccess(ipSet, tt.serviceName, tt.duration)
			if tt.expErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expErr)
				return
			}
			require.NoError(t, err)

			for _, ipRange := range ipSet.Ranges() {
				ports, exists := mockFirewall.Allowed[ipRange.String()]
				assert.True(t, exists, "IP range %s should be in allowed list", ipRange)

				expectedService := services[tt.serviceName]
				expectedDuration := min(tt.duration, expectedService.MaxAccessDuration.V)
				expectedExpiry := timeNow.Add(expectedDuration)
				actualExpiry, portExists := ports[expectedService.Port.V]
				assert.True(t, portExists, "Port %d should be allowed for IP range %s", expectedService.Port.V, ipRange)
				assert.Equal(t, expectedExpiry, actualExpiry)
			}
		})
	}
}

func setupFailingMock() *mock.Mock {
	m := mock.New(time.Now)
	m.SetFailError(errors.New("setup error"))
	return m
}

var timeNow = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func timeNowFn() time.Time {
	return timeNow
}
