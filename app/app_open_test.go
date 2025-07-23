package app

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"
	"github.com/stretchr/testify/assert"

	"go.hackfix.me/sesame/app/config"
	"go.hackfix.me/sesame/db/models"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

func TestAppOpenIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		svcName        string
		clients        []string
		accessDuration time.Duration
		expStderr      []string
		expErr         string
	}{
		{
			name:           "ok/multiple_mixed",
			svcName:        "web",
			clients:        []string{"192.168.1.1", "10.0.0.0/8", "172.16.1.1-172.16.1.100", "2001:db8::/32"},
			accessDuration: 30 * time.Minute,
			expStderr: []string{
				"granted access", "service.name=web", "service.port=80", "duration=30m0s",
				`ip_ranges="[10.0.0.0-10.255.255.255 172.16.1.1-172.16.1.100 192.168.1.1-192.168.1.1 2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]`,
			},
		},
		{
			name:    "err/no_clients",
			svcName: "web",
			clients: []string{},
			expErr:  `failed parsing CLI arguments: expected "<clients> ..."`,
		},
		{
			name:    "err/invalid_client",
			svcName: "web",
			clients: []string{"not.an.ip"},
			expErr:  "failed parsing IP address 'not.an.ip'",
		},
		{
			name:    "err/unknown_service",
			svcName: "blah",
			clients: []string{"192.168.1.1"},
			expErr:  "unknown service",
		},
	}

	for _, tt := range tests {
		args := []string{"open"}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			services := []*models.Service{
				{
					Name:              "web",
					Port:              uint16(80),
					MaxAccessDuration: time.Hour,
				},
				{
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			}

			cfg := config.Config{
				Firewall: config.Firewall{
					Type: sql.Null[ftypes.FirewallType]{V: ftypes.FirewallMock, Valid: true},
				},
			}

			tctx, cancel, h := newTestContext(t, 5*time.Second)
			defer cancel()

			app, err := newTestApp(tctx)
			h(assert.NoError(t, err))

			cfgJSON, err := json.Marshal(cfg)
			h(assert.NoError(t, err))
			err = vfs.WriteFile(app.ctx.FS, "/config.json", cfgJSON, 0o644)
			h(assert.NoError(t, err))

			err = initTestDB(app.ctx, services)
			h(assert.NoError(t, err))

			args = append(args,
				"--duration", tt.accessDuration.String(), tt.svcName,
			)
			args = append(args, tt.clients...)

			err = app.Run(args...)
			stdout := app.stdout.String()
			stderr := app.stderr.String()

			if tt.expErr != "" {
				h(assert.ErrorContains(t, err, tt.expErr))
				h(assert.Empty(t, stdout))
				h(assert.Empty(t, stderr))
				return
			}

			h(assert.NoError(t, err))
			h(assert.Empty(t, stdout))
			h(assert.NotEmpty(t, stderr))
			for _, expStderr := range tt.expStderr {
				h(assert.Contains(t, stderr, expStderr))
			}
		})
	}
}
