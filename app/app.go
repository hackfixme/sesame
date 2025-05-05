package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mandelsoft/vfs/pkg/memoryfs"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/cli"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/nftables"
	"go.hackfix.me/sesame/models"
)

// App is the application.
type App struct {
	name string
	ctx  *actx.Context
	cli  *cli.CLI
	args []string
	// the logging level is set via the CLI, if the app was initialized with the
	// WithLogger option.
	logLevel *slog.LevelVar
}

// New initializes a new application.
func New(name string, opts ...Option) (*App, error) {
	version, err := actx.GetVersion()
	if err != nil {
		return nil, err
	}

	defaultCtx := &actx.Context{
		Ctx:     context.Background(),
		FS:      memoryfs.New(),
		Logger:  slog.Default(),
		Version: version,

		FirewallType: models.FirewallMock,
	}
	app := &App{name: name, ctx: defaultCtx}

	for _, opt := range opts {
		opt(app)
	}

	ver := fmt.Sprintf("%s %s", app.name, app.ctx.Version.String())
	app.cli, err = cli.New(ver)
	if err != nil {
		return nil, err
	}

	return app, nil
}

// Run initializes the application environment and starts execution of the
// application.
func (app *App) Run(args []string) error {
	if err := app.cli.Parse(args); err != nil {
		return err
	}

	if app.logLevel != nil {
		app.logLevel.Set(app.cli.Log.Level)
		slog.SetLogLoggerLevel(app.cli.Log.Level)
	}

	if err := app.setupFirewall(); err != nil {
		return err
	}

	if err := app.cli.Execute(app.ctx); err != nil {
		return err
	}

	return nil
}

func (app *App) setupFirewall() error {
	var fw models.Firewall
	switch app.ctx.FirewallType {
	case models.FirewallMock:
		fw = mock.New(app.ctx.TimeSource)
	case models.FirewallNFTables:
		fw = nftables.New(app.ctx.Logger)
	}

	var err error
	app.ctx.FirewallManager, err = firewall.NewManager(
		fw, map[string]models.Service{}, // TODO: Get from config
		firewall.WithLogger(app.ctx.Logger),
	)
	if err != nil {
		return aerrors.NewRuntimeError("failed creating new firewall manager", err, "")
	}

	return nil
}
