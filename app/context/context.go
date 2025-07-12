package context

import (
	"context"
	"crypto/tls"
	"database/sql"
	"io"
	"log/slog"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"

	cfg "go.hackfix.me/sesame/app/config"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db"
	"go.hackfix.me/sesame/db/queries"
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

	// Metadata
	Version     *VersionInfo
	VersionInit string // app version the DB was initialized with
}

// ServerTLSCert returns the TLS certificate used by the Sesame web server.
func (c *Context) ServerTLSCert() (tlsCert tls.Certificate, err error) {
	var certNull sql.Null[[]byte]
	certNull, err = queries.GetServerTLSCert(c.DB.NewContext(), c.DB)
	if err != nil {
		return
	}

	return crypto.DeserializeTLSCert(certNull.V)
}
