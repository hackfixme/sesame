package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"go.hackfix.me/sesame/db/types"
)

// GetServerTLSCert retrieves the server TLS certificate from the database. It
// returns an error if its is missing or invalid.
func GetServerTLSCert(ctx context.Context, d types.Querier) (
	cert sql.Null[[]byte], err error,
) {
	err = d.QueryRowContext(ctx, `SELECT server_tls_cert FROM _meta`).Scan(&cert)
	if err != nil {
		return
	}

	if !cert.Valid {
		return cert, errors.New("server TLS certificate not found")
	}

	return
}

// GetAllTables returns a map of all table names in the database that contain user data.
func GetAllTables(ctx context.Context, d types.Querier) (allTables map[string]struct{}, rerr error) {
	allTables = make(map[string]struct{})
	rows, err := d.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing sqlite_master rows: %w", err)
		}
	}()

	for rows.Next() {
		var name string
		err = rows.Scan(&name)
		if err != nil {
			return nil, fmt.Errorf("failed scanning sqlite_master row: %w", err)
		}

		// Exclude internal tables
		if !strings.HasPrefix(name, "_") {
			allTables[name] = struct{}{}
		}
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over sqlite_master rows: %w", err)
	}

	return allTables, nil
}

// Version returns the Sesame application version the database was initialized
// with. If the returned sql.Null value is invalid, it indicates that the
// database hasn't been initialized.
func Version(ctx context.Context, d types.Querier) (sql.Null[string], error) {
	var version sql.Null[string]
	err := d.QueryRowContext(ctx, `SELECT version FROM _meta`).
		Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return version, fmt.Errorf("failed scanning _meta row: %w", err)
	}

	return version, nil
}
