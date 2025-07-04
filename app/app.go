package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/mandelsoft/vfs/pkg/memoryfs"
	"github.com/nrednav/cuid2"

	cfg "go.hackfix.me/sesame/app/config"
	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/cli"
	"go.hackfix.me/sesame/db"
	"go.hackfix.me/sesame/db/queries"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/firewall/mock"
	"go.hackfix.me/sesame/firewall/nftables"
	ftypes "go.hackfix.me/sesame/firewall/types"
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

// New initializes a new application with the given options.
// configFilePath specifies the path to the configuration file. This can be overridden
// with the SESAME_CONFIG_FILE environment variable, or the --config-file CLI flag.
// dataDir specifies the path to the directory where application data will be stored.
// This can be overridden with the SESAME_DATA_DIR environment variable, or the
// --data-dir CLI flag.
func New(name, configFilePath, dataDir string, opts ...Option) (*App, error) {
	version, err := actx.GetVersion()
	if err != nil {
		return nil, err
	}

	defaultCtx := &actx.Context{
		Ctx:          context.Background(),
		FS:           memoryfs.New(),
		Logger:       slog.Default(),
		Version:      version,
		FirewallType: ftypes.FirewallMock,
	}
	app := &App{
		name:           name,
		ctx:            defaultCtx,
		configFilePath: configFilePath,
	}

	for _, opt := range opts {
		opt(app)
	}

	uuidgen, err := cuid2.Init(cuid2.WithLength(12))
	if err != nil {
		return nil, aerrors.NewRuntimeError(
			"failed creating UUID generation function", err, "")
	}
	app.ctx.UUIDGen = uuidgen

	ver := fmt.Sprintf("%s %s", app.name, app.ctx.Version.String())
	app.cli, err = cli.New(configFilePath, dataDir, ver)
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
		app.ctx.Config = cfg.NewConfig(app.ctx.FS, app.configFilePath)
		if err := app.ctx.Config.Load(); err != nil {
			return err
		}
	}

	app.cli.ApplyConfig(app.ctx.Config)

	if err := app.setupFirewall(); err != nil {
		return err
	}

	if err := app.createDataDir(app.cli.DataDir); err != nil {
		return err
	}
	dataDir := app.cli.DataDir
	if app.ctx.FS.Name() == "MemoryFileSystem" {
		// The SQLite lib will attempt to write directly with the os interface,
		// so prevent it by using SQLite's in-memory support.
		dataDir = ":memory:"
	}

	if err := app.setupDB(dataDir); err != nil {
		return err
	}

	if err := app.cli.Execute(app.ctx); err != nil {
		return err
	}

	return nil
}

func (app *App) createDataDir(dir string) error {
	err := app.ctx.FS.MkdirAll(dir, 0o700)
	if err != nil {
		return aerrors.NewRuntimeError(
			fmt.Sprintf("failed creating app data directory '%s'", dir), err, "")
	}
	return nil
}

func (app *App) setupDB(dataDir string) error {
	var err error
	if app.ctx.DB == nil {
		dbPath := filepath.Join(dataDir, "sesame.db")
		app.ctx.DB, err = db.Open(app.ctx.Ctx, dbPath)
		if err != nil {
			return err
		}
	}

	version, _ := queries.Version(app.ctx.DB.NewContext(), app.ctx.DB)
	if version.Valid {
		app.ctx.VersionInit = version.V
	}

	return nil
}

func (app *App) setupFirewall() error {
	var fw ftypes.Firewall
	switch app.ctx.FirewallType {
	case ftypes.FirewallMock:
		fw = mock.New(app.ctx.TimeNow)
	case ftypes.FirewallNFTables:
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
