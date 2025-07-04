package context

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"

	cfg "go.hackfix.me/sesame/app/config"
	"go.hackfix.me/sesame/db"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

// Context contains common objects used by the application. It is passed around
// the application to avoid direct dependencies on external systems, and make
// testing easier.
type Context struct {
	Ctx     context.Context // global context
	FS      vfs.FileSystem  // filesystem
	Env     Environment     // process environment
	Logger  *slog.Logger    // global logger
	TimeNow func() time.Time
	Config  *cfg.Config   // values read from the configuration file
	UUIDGen func() string // UUID generator

	// Standard streams
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	DB *db.DB

	FirewallType    ftypes.FirewallType
	FirewallManager ftypes.FirewallManager

	// Metadata
	Version     *VersionInfo
	VersionInit string // app version the DB was initialized with
}
