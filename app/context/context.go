package context

import (
	"context"
	"io"
	"log/slog"

	"github.com/mandelsoft/vfs/pkg/vfs"

	"go.hackfix.me/sesame/models"
)

// Context contains common objects used by the application. It is passed around
// the application to avoid direct dependencies on external systems, and make
// testing easier.
type Context struct {
	Ctx        context.Context // global context
	FS         vfs.FileSystem  // filesystem
	Env        Environment     // process environment
	Logger     *slog.Logger    // global logger
	TimeSource models.TimeSource
	Config     *models.Config // values read from the configuration file

	// Standard streams
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	FirewallType    models.FirewallType
	FirewallManager models.FirewallManager

	// Metadata
	Version *VersionInfo
}
