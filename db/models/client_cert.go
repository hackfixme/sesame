package models

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/types"
)

// ClientCertificate is a record of a TLS client certificate issued for a remote
// Sesame user.
type ClientCertificate struct {
	ID        uint64
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	// A unique identifier of the certificate within the context of this server.
	// It is a hex representation of its serial number.
	SerialNumber string
	// The Sesame user this certificate was issued for.
	User *User
	// A unique identifier of the remote site this certificate is used in.
	// It's essentially the reverse of the remote name used by the client.
	SiteID string

	// A renewal token is used for renewing a certificate that has already expired.
	// It's done to avoid burdening users from going through the invitation process again.
	RenewalToken []byte
	// Renewal tokens can also expire, but this date must be ahead of the
	// certificate expiration date. If the renewal token also expires, the user
	// will have to go through the invitation process again.
	RenewalTokenExpiresAt time.Time
}

// NewClientCertificate returns a new client certificate record for the remote
// user and remote site ID. It creates a new unique renewal token that expires
// renTkDur time after the certificate expiration date.
func NewClientCertificate(
	user *User, siteID string, renTkDur time.Duration, cert *x509.Certificate,
) (*ClientCertificate, error) {
	renewalToken, err := crypto.RandomData(32)
	if err != nil {
		return nil, fmt.Errorf("failed generating renewal token: %w", err)
	}
	return &ClientCertificate{
		ExpiresAt:             cert.NotAfter,
		SerialNumber:          cert.SerialNumber.Text(16),
		User:                  user,
		SiteID:                siteID,
		RenewalToken:          renewalToken,
		RenewalTokenExpiresAt: cert.NotAfter.Add(renTkDur),
	}, nil
}

// Save stores the client certificate data in the database. If update is true,
// either the ID, serial number, or renewal token must be set for the lookup.
// It returns an error if the client certificate doesn't exist, or if more than
// one record would be updated.
func (cc *ClientCertificate) Save(ctx context.Context, d types.Querier, update bool) error {
	var (
		stmt      string
		filterStr string
		op        string
		args      []any
	)

	timeNow := d.TimeNow().UTC()
	if update {
		var (
			filter *types.Filter
			err    error
		)
		filter, filterStr, err = cc.createFilter(ctx, d, 1)
		if err != nil {
			return fmt.Errorf("failed creating query filter: %w", err)
		}
		args = []any{timeNow}
		var additional string
		if cc.SiteID != "" {
			additional += ", site_id = ?"
			args = append(args, cc.SiteID)
		}
		args = append(args, filter.Args...)
		stmt = fmt.Sprintf(`UPDATE client_certs
			SET updated_at = ?%s
			WHERE %s`, additional, filter.Where)
		op = fmt.Sprintf("updating client certificate with %s", filterStr)
	} else {
		stmt = `INSERT INTO client_certs (
				id, created_at, updated_at, expires_at, serial_number, user_id, site_id,
				renewal_token, renewal_token_expires_at)
			VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)`
		args = []any{
			timeNow, timeNow, cc.ExpiresAt, cc.SerialNumber, cc.User.ID, cc.SiteID,
			cc.RenewalToken, cc.RenewalTokenExpiresAt,
		}
		op = "saving new client certificate"
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
			return types.NoResultError{ModelName: "client certificate", ID: filterStr}
		}
		cc.UpdatedAt = timeNow
	} else {
		cc.ID, err = lastInsertID(res)
		if err != nil {
			return err
		}
		cc.CreatedAt = timeNow
		cc.UpdatedAt = timeNow
	}

	return nil
}

// Load the client certificate record from the database. The ID, serial number,
// or renewal token must be set for the lookup.
func (cc *ClientCertificate) Load(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := cc.createFilter(ctx, d, 1)
	if err != nil {
		return fmt.Errorf("failed creating query filter: %w", err)
	}

	ccs, err := ClientCertificates(ctx, d, filter)
	if err != nil {
		return err
	}

	if len(ccs) == 0 {
		return types.NoResultError{ModelName: "client certificate", ID: filterStr}
	}

	*cc = *ccs[0]

	return nil
}

// Delete removes the client certificate record from the database. The ID,
// serial number, or renewal token must be set for the lookup. It returns an
// error if the client certificate doesn't exist, or if more than one record
// would be deleted.
func (cc *ClientCertificate) Delete(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := cc.createFilter(ctx, d, 1)
	if err != nil {
		return fmt.Errorf("failed creating query filter: %w", err)
	}

	stmt := fmt.Sprintf(`DELETE FROM client_certs WHERE %s`, filter.Where)
	res, err := d.ExecContext(ctx, stmt, filter.Args...)
	if err != nil {
		return fmt.Errorf("failed deleting client certificate with %s: %w", filterStr, err)
	}

	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("failed getting affected rows: %w", err)
	} else if n == 0 {
		return types.NoResultError{ModelName: "client certificate", ID: filterStr}
	}

	return nil
}

func (cc *ClientCertificate) createFilter(
	ctx context.Context, d types.Querier, limit int,
) (*types.Filter, string, error) {
	var filter *types.Filter
	var filterStr string
	switch {
	case cc.ID != 0:
		filter = types.NewFilter("id = ?", []any{cc.ID})
		filterStr = fmt.Sprintf("ID %d", cc.ID)
	case cc.SerialNumber != "":
		filter = types.NewFilter("serial_number = ?", []any{cc.SerialNumber})
		filterStr = fmt.Sprintf("serial number '%s'", cc.SerialNumber)
	case len(cc.RenewalToken) > 0:
		filter = types.NewFilter("renewal_token = ?", []any{cc.RenewalToken}).
			And(types.NewFilter("renewal_token_expires_at > ?", []any{d.TimeNow().UTC()}))
		filterStr = "renewal token"
	default:
		return nil, "", errors.New("must provide either a client certificate ID, serial number or renewal token")
	}

	if count, err := filterCount(ctx, d, "client certificates", filter); err != nil {
		return nil, "", err
	} else if count > limit {
		return nil, "", fmt.Errorf("filter with %s returns %d results; make the filter more specific", filterStr, count)
	}

	filter.Limit = limit

	return filter, filterStr, nil
}

// ClientCertificates returns one or more client certificates from the database.
// An optional filter can be passed to limit the results.
func ClientCertificates(
	ctx context.Context, d types.Querier, filter *types.Filter,
) (ccs []*ClientCertificate, rerr error) {
	queryFmt := `SELECT
			cc.id, cc.created_at, cc.updated_at, cc.expires_at, cc.serial_number, cc.user_id,
			cc.site_id, cc.renewal_token, cc.renewal_token_expires_at)
		FROM client_certs cc
		%s ORDER BY cc.expires_at ASC %s`

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
		return nil, types.LoadError{ModelName: "client certificates", Err: err}
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing client_certs rows: %w", err)
		}
	}()

	ccs = make([]*ClientCertificate, 0)
	users := make(map[uint64]*User)
	for rows.Next() {
		var (
			cc     = &ClientCertificate{}
			userID uint64
		)
		err = rows.Scan(
			&cc.ID, &cc.CreatedAt, &cc.UpdatedAt, &cc.ExpiresAt, &cc.SerialNumber,
			&userID, &cc.SiteID, cc.RenewalToken, &cc.RenewalTokenExpiresAt)
		if err != nil {
			return nil, types.ScanError{ModelName: "client certificate", Err: err}
		}

		// TODO: Load users in the same query for efficiency
		user, ok := users[userID]
		if !ok {
			user = &User{ID: userID}
			if err = user.Load(ctx, d); err != nil {
				return nil, types.LoadError{ModelName: "client certificate user", Err: err}
			}
			users[userID] = user
		}
		cc.User = user

		ccs = append(ccs, cc)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over client certificate rows: %w", err)
	}

	return ccs, nil
}
