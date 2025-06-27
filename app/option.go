package app

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mandelsoft/vfs/pkg/vfs"

	cfg "go.hackfix.me/sesame/app/config"
	actx "go.hackfix.me/sesame/app/context"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

// Option is a function that allows configuring the application.
type Option func(*App)

// WithConfig sets the configuration object.
func WithConfig(cfg *cfg.Config) Option {
	return func(app *App) {
		app.ctx.Config = cfg
	}
}

// WithContext sets the main context.
func WithContext(ctx context.Context) Option {
	return func(app *App) {
		app.ctx.Ctx = ctx
	}
}

// WithEnv sets the process environment used by the application.
func WithEnv(env actx.Environment) Option {
	return func(app *App) {
		app.ctx.Env = env
	}
}

// WithFDs sets the file descriptors used by the application.
func WithFDs(stdin io.Reader, stdout, stderr io.Writer) Option {
	return func(app *App) {
		app.ctx.Stdin = stdin
		app.ctx.Stdout = stdout
		app.ctx.Stderr = stderr
	}
}

// WithFirewall sets the firewall implementation used by the application.
func WithFirewall(ft ftypes.FirewallType) Option {
	return func(app *App) {
		app.ctx.FirewallType = ft
	}
}

// WithFS sets the filesystem used by the application.
func WithFS(fs vfs.FileSystem) Option {
	return func(app *App) {
		app.ctx.FS = fs
	}
}

// WithLogger initializes the logger used by the application.
func WithLogger(_, isStderrTTY bool) Option {
	return func(app *App) {
		lvl := &slog.LevelVar{}
		lvl.Set(slog.LevelInfo)
		logger := slog.New(
			tint.NewHandler(app.ctx.Stderr, &tint.Options{
				Level:      lvl,
				NoColor:    !isStderrTTY,
				TimeFormat: "2006-01-02 15:04:05.000",
			}),
		)
		app.logLevel = lvl
		app.ctx.Logger = logger
		slog.SetDefault(logger)
	}
}

// WithTimeNow sets the function used to retrieve the current system time.
func WithTimeNow(timeNowFn func() time.Time) Option {
	return func(app *App) {
		app.ctx.TimeNow = timeNowFn
	}
}
