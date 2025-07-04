package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"
	"github.com/stretchr/testify/assert"

	"go.hackfix.me/sesame/app/config"
	ftypes "go.hackfix.me/sesame/firewall/types"
	svc "go.hackfix.me/sesame/service"
)

func TestAppOpen(t *testing.T) {
	t.Parallel()

	services := map[string]svc.Service{
		"web": {
			Name:              sql.Null[string]{V: "web", Valid: true},
			Port:              sql.Null[uint16]{V: 80, Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: time.Hour, Valid: true},
		},
		"db": {
			Name:              sql.Null[string]{V: "db", Valid: true},
			Port:              sql.Null[uint16]{V: 5432, Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
		},
	}
	cfgOK := config.Config{
		Firewall: config.Firewall{
			Type: sql.Null[ftypes.FirewallType]{V: ftypes.FirewallMock, Valid: true},
		},
		Services: services,
	}

	cfgNoServices := config.Config{
		Firewall: config.Firewall{
			Type: sql.Null[ftypes.FirewallType]{V: ftypes.FirewallMock, Valid: true},
		},
	}

	tests := []struct {
		name           string
		config         config.Config
		svcName        string
		clients        []string
		accessDuration time.Duration
		expStderr      []string
		expErr         string
	}{
		{
			name:           "ok/multiple_mixed",
			config:         cfgOK,
			svcName:        "web",
			clients:        []string{"192.168.1.1", "10.0.0.0/8", "172.16.1.1-172.16.1.100", "2001:db8::/32"},
			accessDuration: 30 * time.Minute,
			expStderr: []string{
				"created temporary access", "service_name=web",
				"service_port=80", "duration=30m0s",
				"client_ip_range=192.168.1.1-192.168.1.1",
				"client_ip_range=10.0.0.0-10.255.255.255",
				"client_ip_range=172.16.1.1-172.16.1.100",
				"client_ip_range=2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
			},
		},
		{
			name:    "err/no_clients",
			config:  cfgNoServices,
			svcName: "web",
			clients: []string{},
			expErr:  `failed parsing CLI arguments: expected "<clients> ..."`,
		},
		{
			name:    "err/invalid_client",
			config:  cfgNoServices,
			svcName: "web",
			clients: []string{"not.an.ip"},
			expErr:  "failed parsing IP address 'not.an.ip'",
		},
		{
			name:    "err/unknown_service",
			config:  cfgNoServices,
			svcName: "web",
			clients: []string{"192.168.1.1"},
			expErr:  "unknown service: web",
		},
	}

	for _, tt := range tests {
		args := []string{"open"}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tctx, cancel, h := newTestContext(t, 5*time.Second)
			defer cancel()

			app, err := newTestApp(tctx)
			h(assert.NoError(t, err))

			cfgJSON, err := json.Marshal(tt.config)
			h(assert.NoError(t, err))
			err = vfs.WriteFile(app.ctx.FS, "/config.json", cfgJSON, 0o644)
			h(assert.NoError(t, err))

			args = append(args,
				"--access-duration", fmt.Sprintf("%s", tt.accessDuration), tt.svcName,
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

func TestAppService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		expStdout string
		expStderr string
		expErr    string
		expConfig config.Config
	}{
		{
			name: "ok/add_basic",
			args: []string{"add", "web", "80"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"web": {
						Name:              sql.Null[string]{V: "web", Valid: true},
						Port:              sql.Null[uint16]{V: 80, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: time.Hour, Valid: true},
					},
				},
			},
		},
		{
			name: "ok/add_custom_access_duration",
			args: []string{"add", "db", "5432", "--max-access-duration", "30m"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"web": {
						Name:              sql.Null[string]{V: "web", Valid: true},
						Port:              sql.Null[uint16]{V: 80, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: time.Hour, Valid: true},
					},
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
		},
		{
			name: "ok/update",
			args: []string{"update", "web", "8080", "--max-access-duration", "5m"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"web": {
						Name:              sql.Null[string]{V: "web", Valid: true},
						Port:              sql.Null[uint16]{V: 8080, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 5 * time.Minute, Valid: true},
					},
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
		},
		{
			name: "ok/list",
			args: []string{"list"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"web": {
						Name:              sql.Null[string]{V: "web", Valid: true},
						Port:              sql.Null[uint16]{V: 8080, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 5 * time.Minute, Valid: true},
					},
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
			expStdout: "" +
				"Name  Port  Max Access Duration\n" +
				"----  ----  -------------------\n" +
				"db    5432  30m0s\n" +
				"web   8080  5m0s\n",
		},
		{
			name: "ok/remove_1",
			args: []string{"remove", "web"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
		},
		{
			name: "err/invalid_port",
			args: []string{"add", "web", "0"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
			expErr: "failed parsing CLI arguments: <port>: must be greater than 0",
		},
		{
			name: "err/service_exists",
			args: []string{"add", "db", "5000"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
			expErr: "service 'db' already exists",
		},
		{
			name: "err/remove_service_doesnot_exist",
			args: []string{"remove", "web"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
			expErr: "service 'web' doesn't exist",
		},
		{
			name: "err/update_service_doesnot_exist",
			args: []string{"update", "web", "5000"},
			expConfig: config.Config{
				Services: map[string]svc.Service{
					"db": {
						Name:              sql.Null[string]{V: "db", Valid: true},
						Port:              sql.Null[uint16]{V: 5432, Valid: true},
						MaxAccessDuration: sql.Null[time.Duration]{V: 30 * time.Minute, Valid: true},
					},
				},
			},
			expErr: "service 'web' doesn't exist",
		},
		{
			name:      "ok/remove_2",
			args:      []string{"remove", "db"},
			expConfig: config.Config{Services: map[string]svc.Service{}},
		},
		{
			name:      "ok/list_empty",
			args:      []string{"list"},
			expConfig: config.Config{Services: map[string]svc.Service{}},
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	for _, tt := range tests {
		args := []string{"service"}
		t.Run(tt.name, func(t *testing.T) {
			args = append(args, tt.args...)
			err = app.Run(args...)
			stdout := app.stdout.String()
			stderr := app.stderr.String()

			if tt.expErr != "" {
				h(assert.ErrorContains(t, err, tt.expErr))
			} else {
				h(assert.NoError(t, err))
			}

			h(assert.Equal(t, tt.expStdout, stdout))
			h(assert.Equal(t, tt.expStderr, stderr))

			cfgJSON, err := vfs.ReadFile(app.ctx.FS, "/config.json")
			h(assert.NoError(t, err))
			var cfg config.Config
			err = json.Unmarshal(cfgJSON, &cfg)
			h(assert.NoError(t, err))
			h(assert.Equal(t, tt.expConfig, cfg))
		})
	}
}
