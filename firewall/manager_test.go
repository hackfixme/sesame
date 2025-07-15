package firewall_test

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/types"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)

	tests := []struct {
		name     string
		firewall types.Firewall
		expErr   string
	}{
		{
			name:     "ok/valid",
			firewall: mock.New(time.Now, logger),
		},
		{
			name:     "err/nil_firewall",
			firewall: nil,
			expErr:   "firewall implementation is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manager, err := firewall.NewManager(tt.firewall)

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

		logger := slog.New(slog.DiscardHandler)
		mockFirewall := mock.New(time.Now, logger)
		manager, err := firewall.NewManager(mockFirewall, firewall.WithLogger(logger))
		require.NoError(t, err)
		assert.NotNil(t, manager)
	})
}

func TestManager_AllowAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ipAddr     []string
		duration   time.Duration
		setupError bool
		expErr     string
	}{
		{
			name:     "ok/single_ip",
			ipAddr:   []string{"192.168.1.100"},
			duration: 30 * time.Minute,
		},
		{
			name:     "ok/multiple_ips",
			ipAddr:   []string{"192.168.1.100", "10.0.0.5"},
			duration: 30 * time.Minute,
		},
		{
			name:     "ok/cidr_notation",
			ipAddr:   []string{"192.168.1.0/24"},
			duration: 30 * time.Minute,
		},
		{
			name:     "ok/ip_range",
			ipAddr:   []string{"192.168.1.1-192.168.1.10"},
			duration: 30 * time.Minute,
		},
		{
			name:     "ok/duration_limited_by_service_max",
			ipAddr:   []string{"192.168.1.100"},
			duration: 2 * time.Hour,
		},
		{
			name:       "err/firewall_allow_fails",
			ipAddr:     []string{"192.168.1.100"},
			duration:   30 * time.Minute,
			setupError: true,
			expErr:     "failed creating access for client IP range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			mockFirewall := mock.New(timeNowFn, logger)

			// For the firewall allow failure test, we need to create the manager first
			// (without error) then set the error for the Allow operation.
			manager, err := firewall.NewManager(
				mockFirewall, firewall.WithLogger(slog.New(slog.DiscardHandler)),
			)
			require.NoError(t, err)

			if tt.setupError {
				mockFirewall.SetFailError(errors.New("firewall error"))
			}

			ipSet, err := firewall.ParseToIPSet(tt.ipAddr...)
			require.NoError(t, err)

			svc := &models.Service{Name: "web", Port: 8080, MaxAccessDuration: time.Hour}
			err = manager.AllowAccess(ipSet, svc, tt.duration)
			if tt.expErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expErr)
				return
			}
			require.NoError(t, err)

			for _, ipRange := range ipSet.Ranges() {
				ports, exists := mockFirewall.Allowed[ipRange.String()]
				assert.True(t, exists, "IP range %s should be in allowed list", ipRange)

				expectedDuration := min(tt.duration, svc.MaxAccessDuration)
				expectedExpiry := timeNow.Add(expectedDuration)
				actualExpiry, portExists := ports[svc.Port]
				assert.True(t, portExists, "Port %d should be allowed for IP range %s", svc.Port, ipRange)
				assert.Equal(t, expectedExpiry, actualExpiry)
			}
		})
	}
}

var timeNow = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func timeNowFn() time.Time {
	return timeNow
}
