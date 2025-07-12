package db

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"log/slog"
	"math"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite"

	"go.hackfix.me/sesame/db/migrator"
	"go.hackfix.me/sesame/db/types"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type DB struct {
	*sql.DB
	ctx        context.Context
	timeNow    func() time.Time
	path       string
	migrations []*migrator.Migration
}

var _ types.Querier = (*DB)(nil)

// Init creates the database schema and initial records.
func (d *DB) Init(
	appVersion string, serverTLSCert []byte, logger *slog.Logger,
) error {
	dblogger := logger.With("path", d.path)
	dblogger.Debug("initializing database")

	err := migrator.RunMigrations(d, d.migrations, migrator.MigrationUp, "all", logger)
	if err != nil {
		return err
	}

	_, err = d.ExecContext(d.NewContext(),
		`INSERT INTO _meta (version, server_tls_cert) VALUES (?, ?)`,
		appVersion, serverTLSCert)
	if err != nil {
		return err
	}

	dblogger.Info("database initialized")

	return nil
}

// NewContext returns a new child context of the main database context.
func (d *DB) NewContext() context.Context {
	// TODO: Return cancel func?
	ctx, _ := context.WithCancel(d.ctx)
	return ctx
}

func Open(ctx context.Context, path string, timeNow func() time.Time) (*DB, error) {
	var d *DB
	if strings.Contains(path, "mode=memory") || strings.Contains(path, ":memory:") {
		defer func() {
			if d != nil {
				// See https://github.com/mattn/go-sqlite3#faq
				d.SetMaxIdleConns(10)
				d.SetConnMaxLifetime(time.Duration(math.Inf(1)))
			}
		}()
	}

	sqliteDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	d = &DB{DB: sqliteDB, ctx: ctx, path: path, timeNow: timeNow}

	// Enable foreign key enforcement
	_, err = d.Exec(`PRAGMA foreign_keys = ON;`)
	if err != nil {
		return nil, err
	}

	migrationsDir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	migrations, err := migrator.LoadMigrations(migrationsDir)
	if err != nil {
		return nil, err
	}
	d.migrations = migrations

	return d, nil
}

// TimeNow returns the current system time.
func (d *DB) TimeNow() time.Time {
	return d.timeNow()
}
