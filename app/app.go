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
	// the logging level is set via the CLI, if the app was initialized with the
	// WithLogger option.
	logLevel       *slog.LevelVar
	configFilePath string
}

// New initializes a new application.
func New(name string, configFilePath string, opts ...Option) (*App, error) {
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
	app := &App{
		name:           name,
		ctx:            defaultCtx,
		configFilePath: configFilePath,
	}

	for _, opt := range opts {
		opt(app)
	}

	ver := fmt.Sprintf("%s %s", app.name, app.ctx.Version.String())
	app.cli, err = cli.New(configFilePath, ver)
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

	if app.ctx.Config == nil || app.ctx.Config.Path() != app.cli.ConfigFile {
		app.ctx.Config = models.NewConfig(app.ctx.FS, app.configFilePath)
		if err := app.ctx.Config.Load(); err != nil {
			return err
		}
	}

	app.cli.ApplyConfig(app.ctx.Config)

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
		fw = mock.New(app.ctx.TimeNow)
	case models.FirewallNFTables:
		var err error
		fw, err = nftables.New(app.ctx.Logger)
		if err != nil {
			return aerrors.NewRuntimeError("failed creating the nftables firewall", err, "")
		}
	}

	var err error
	app.ctx.FirewallManager, err = firewall.NewManager(
		fw, app.ctx.Config.Services,
		firewall.WithLogger(app.ctx.Logger),
	)
	if err != nil {
		return aerrors.NewRuntimeError("failed creating the firewall manager", err, "")
	}

	return nil
}
