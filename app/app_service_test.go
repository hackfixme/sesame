package app

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
)

func TestAppServiceIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		expStdout   string
		expStderr   string
		expErr      string
		expServices []*models.Service
	}{
		{
			name: "ok/add_basic",
			args: []string{"add", "web", "80"},
			expServices: []*models.Service{
				{
					ID:                1,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "web",
					Port:              uint16(80),
					MaxAccessDuration: time.Hour,
				},
			},
		},
		{
			name: "ok/add_custom_access_duration",
			args: []string{"add", "db", "5432", "--max-access-duration", "30m"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
				{
					ID:                1,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "web",
					Port:              uint16(80),
					MaxAccessDuration: time.Hour,
				},
			},
		},
		{
			name: "ok/update",
			args: []string{"update", "web", "8080", "--max-access-duration", "5m"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
				{
					ID:                1,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "web",
					Port:              uint16(8080),
					MaxAccessDuration: 5 * time.Minute,
				},
			},
		},
		{
			name: "ok/list",
			args: []string{"list"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
				{
					ID:                1,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "web",
					Port:              uint16(8080),
					MaxAccessDuration: 5 * time.Minute,
				},
			},
			expStdout: "" +
				" NAME  PORT  MAX ACCESS DURATION \n" +
				" db    5432  30m                 \n" +
				" web   8080  5m                  \n",
		},
		{
			name: "ok/remove_1",
			args: []string{"remove", "web"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			},
		},
		{
			name: "err/invalid_port",
			args: []string{"add", "web", "0"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			},
			expErr: "failed parsing CLI arguments: <port>: must be greater than 0",
		},
		{
			name: "err/service_exists",
			args: []string{"add", "db", "5000"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			},
			expErr: "service with name 'db' already exists",
		},
		{
			name: "err/remove_service_doesnot_exist",
			args: []string{"remove", "web"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			},
			expErr: "service with name 'web' doesn't exist",
		},
		{
			name: "err/update_service_doesnot_exist",
			args: []string{"update", "web", "5000"},
			expServices: []*models.Service{
				{
					ID:                2,
					CreatedAt:         timeNow,
					UpdatedAt:         timeNow,
					Name:              "db",
					Port:              uint16(5432),
					MaxAccessDuration: 30 * time.Minute,
				},
			},
			expErr: "service with name 'web' doesn't exist",
		},
		{
			name:        "ok/remove_2",
			args:        []string{"remove", "db"},
			expServices: []*models.Service{},
		},
		{
			name:        "ok/list_empty",
			args:        []string{"list"},
			expServices: []*models.Service{},
		},
	}

	tctx, cancel, h := newTestContext(t, 5*time.Second)
	defer cancel()

	app, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	err = initTestDB(app.ctx, nil)
	h(assert.NoError(t, err))

	for _, tt := range tests {
		args := []string{"service"}
		t.Run(tt.name, func(t *testing.T) {
			args = append(args, tt.args...)
			err = app.Run(args...)
			stdout := app.stdout.String()
			stderr := app.stderr.String()

			var serr *aerrors.StructuredError
			if errors.As(err, &serr) {
				err = serr.Cause()
			}

			if tt.expErr != "" {
				h(assert.ErrorContains(t, err, tt.expErr))
			} else {
				h(assert.NoError(t, err))
			}

			h(assert.Equal(t, tt.expStdout, stdout))
			h(assert.Equal(t, tt.expStderr, stderr))

			services, err := models.Services(app.ctx.DB.NewContext(), app.ctx.DB, nil)
			h(assert.NoError(t, err))
			h(assert.Equal(t, tt.expServices, services))
		})
	}
}
