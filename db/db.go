package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"strings"
	"time"

	//nolint:revive,nolintlint // Idiomatic way of loading DB libraries.
	_ "github.com/glebarez/go-sqlite"

	"go.hackfix.me/sesame/db/migrator"
	"go.hackfix.me/sesame/db/types"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps sql.DB with additional context and migration functionality.
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
		return fmt.Errorf("failed inserting into _meta: %w", err)
	}

	dblogger.Info("database initialized")

	return nil
}

// NewContext returns a new child context of the main database context.
func (d *DB) NewContext() context.Context {
	// TODO: Return cancel func?
	ctx, _ := context.WithCancel(d.ctx) //nolint:govet // I'll handle this later...
	return ctx
}

// Open creates and configures a new SQLite database connection with migrations support.
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
		return nil, fmt.Errorf("failed opening SQLite database: %w", err)
	}

	d = &DB{DB: sqliteDB, ctx: ctx, path: path, timeNow: timeNow}

	// Enable foreign key enforcement
	_, err = d.Exec(`PRAGMA foreign_keys = ON;`)
	if err != nil {
		return nil, fmt.Errorf("failed enabling foreign key enforcement: %w", err)
	}

	migrationsDir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed getting migrations directory: %w", err)
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
