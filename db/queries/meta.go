package queries

import (
	"context"
	"database/sql"
	"errors"
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
func GetAllTables(ctx context.Context, d types.Querier) (map[string]struct{}, error) {
	allTables := make(map[string]struct{})
	rows, err := d.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var name string
		err = rows.Scan(&name)
		if err != nil {
			return nil, err
		}

		// Exclude internal tables
		if !strings.HasPrefix(name, "_") {
			allTables[name] = struct{}{}
		}
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
		return version, err
	}

	return version, nil
}
