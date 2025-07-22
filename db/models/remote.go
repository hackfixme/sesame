package models

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/types"
)

// Remote represents a remote Sesame node that allows the local user to manage
// it remotely.
type Remote struct {
	ID            uint64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Name          string
	Address       string
	TLSCACert     *x509.Certificate
	TLSClientCert *tls.Certificate
}

// NewRemote creates a new remote object.
func NewRemote(
	name, address string, tlsCACert *x509.Certificate, tlsClientCert *tls.Certificate,
) *Remote {
	return &Remote{
		Name:          name,
		Address:       address,
		TLSCACert:     tlsCACert,
		TLSClientCert: tlsClientCert,
	}
}

// Save stores the remote data in the database. If update is true, either the
// remote ID or name must be set for the lookup.
func (r *Remote) Save(ctx context.Context, d types.Querier, update bool) error {
	var (
		stmt      string
		filterStr string
		op        string
		args      []any
		timeNow   = d.TimeNow().UTC()
	)
	if update {
		var (
			filter *types.Filter
			err    error
		)
		filter, filterStr, err = r.createFilter(ctx, d, 1)
		if err != nil {
			return fmt.Errorf("failed creating query filter: %w", err)
		}
		stmt = fmt.Sprintf(`UPDATE remotes
			SET updated_at = ?,
				name = ?,
				address = ?
			WHERE %s`, filter.Where)
		args = append([]any{timeNow, r.Name, r.Address}, filter.Args...)
		op = fmt.Sprintf("updating remote with %s", filterStr)
	} else {
		tlsClientCertPEM, err := crypto.SerializeTLSCert(*r.TLSClientCert)
		if err != nil {
			return fmt.Errorf("failed serializing the client TLS certificate: %w", err)
		}

		stmt = `INSERT INTO remotes (
					id, created_at, updated_at, name, address,
					tls_ca_cert, tls_client_cert)
				VALUES (NULL, ?, ?, ?, ?, ?, ?)`
		args = []any{
			timeNow, timeNow, r.Name, r.Address, r.TLSCACert.Raw, tlsClientCertPEM,
		}
		op = "saving new remote"
	}

	res, err := d.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("failed %s: %w", op, err)
	}

	if update {
		var n int64
		if n, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("failed getting affected rows: %w", err)
		} else if n == 0 {
			return types.NoResultError{ModelName: "remote", ID: filterStr}
		}
		r.UpdatedAt = timeNow
	} else {
		r.ID, err = lastInsertID(res)
		if err != nil {
			return err
		}
		r.CreatedAt = timeNow
		r.UpdatedAt = timeNow
	}

	return err
}

// Load the remote record from the database. The remote ID or name must be set
// for the lookup.
func (r *Remote) Load(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := r.createFilter(ctx, d, 1)
	if err != nil {
		return types.LoadError{ModelName: "remote", Err: err}
	}

	remotes, err := Remotes(ctx, d, filter)
	if err != nil {
		return err
	}

	if len(remotes) == 0 {
		return types.NoResultError{ModelName: "remote", ID: filterStr}
	}

	*r = *remotes[0]

	return nil
}

// Delete removes the remote record from the database. Either the remote ID or
// name must be set for the lookup.
//
//nolint:dupl // Similar method to Service.Delete. "A little copying is better than a little dependency."
func (r *Remote) Delete(ctx context.Context, d types.Querier) error {
	if r.ID == 0 && r.Name == "" {
		return types.InvalidInputError{Msg: "either remote ID or Name must be set"}
	}

	var filter *types.Filter
	var filterStr string
	if r.ID != 0 {
		filter = &types.Filter{Where: "id = ?", Args: []any{r.ID}}
		filterStr = fmt.Sprintf("ID %d", r.ID)
	} else if r.Name != "" {
		filter = &types.Filter{Where: "name = ?", Args: []any{r.Name}}
		filterStr = fmt.Sprintf("name '%s'", r.Name)
	}

	stmt := fmt.Sprintf(`DELETE FROM remotes WHERE %s`, filter.Where)

	res, err := d.ExecContext(ctx, stmt, filter.Args...)
	if err != nil {
		return types.Err("remote", filterStr, err)
	}

	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("failed getting affected rows: %w", err)
	} else if n == 0 {
		return types.NoResultError{ModelName: "remote", ID: filterStr}
	}

	return nil
}

// ClientTLSConfig returns the TLS configuration used to authenticate a user
// with the Sesame HTTP API.
func (r *Remote) ClientTLSConfig() (*tls.Config, error) {
	tlsConfig := crypto.DefaultTLSConfig()

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(r.TLSCACert)
	tlsConfig.RootCAs = caCertPool

	tlsConfig.Certificates = []tls.Certificate{*r.TLSClientCert}
	if len(r.TLSCACert.DNSNames) == 0 {
		return nil, fmt.Errorf("no Subject Alternative Name values found in server CA certificate")
	}
	tlsConfig.ServerName = r.TLSCACert.DNSNames[0]

	return tlsConfig, nil
}

func (r *Remote) createFilter(ctx context.Context, d types.Querier, limit int) (*types.Filter, string, error) {
	var filter *types.Filter
	var filterStr string
	switch {
	case r.ID != 0:
		filter = types.NewFilter("id = ?", []any{r.ID})
		filterStr = fmt.Sprintf("ID %d", r.ID)
	case r.Name != "":
		filter = types.NewFilter("name = ?", []any{r.Name})
		filterStr = fmt.Sprintf("name '%s'", r.Name)
	default:
		return nil, "", errors.New("must provide either an remote ID or name")
	}

	if limit > 0 {
		if count, err := filterCount(ctx, d, "remotes", filter); err != nil {
			return nil, "", err
		} else if count > limit {
			return nil, "", fmt.Errorf("filter %s returns %d results; make the filter more specific", filterStr, count)
		}

		filter.Limit = limit
	}

	return filter, filterStr, nil
}

// Remotes returns one or more remotes from the database. An optional filter can
// be passed to limit the results.
func Remotes(ctx context.Context, d types.Querier, filter *types.Filter) (remotes []*Remote, rerr error) {
	queryFmt := `SELECT r.id, r.created_at, r.updated_at, r.name, r.address,
					r.tls_ca_cert, r.tls_client_cert
				FROM remotes r
				%s ORDER BY r.name ASC %s`

	where := "1=1"
	var limit string
	args := []any{}
	if filter != nil {
		where = filter.Where
		args = filter.Args
		if filter.Limit > 0 {
			limit = fmt.Sprintf("LIMIT %d", filter.Limit)
		}
	}

	query := fmt.Sprintf(queryFmt, fmt.Sprintf("WHERE %s", where), limit)

	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, types.LoadError{ModelName: "remotes", Err: err}
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing remotes rows: %w", err)
		}
	}()

	remotes = make([]*Remote, 0)
	for rows.Next() {
		var (
			r                Remote
			tlsCACertRaw     []byte
			tlsClientCertRaw []byte
		)
		err = rows.Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt, &r.Name, &r.Address,
			&tlsCACertRaw, &tlsClientCertRaw)
		if err != nil {
			return nil, types.ScanError{ModelName: "remote", Err: err}
		}

		r.TLSCACert, err = x509.ParseCertificate(tlsCACertRaw)
		if err != nil {
			return nil, fmt.Errorf("failed parsing raw TLS CA certificate: %w", err)
		}

		var tlsClientCert tls.Certificate
		tlsClientCert, err = crypto.DeserializeTLSCert(tlsClientCertRaw)
		if err != nil {
			return nil, fmt.Errorf("failed deserializing TLS client certificate: %w", err)
		}
		r.TLSClientCert = &tlsClientCert

		remotes = append(remotes, &r)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over remotes rows: %w", err)
	}

	return remotes, nil
}
