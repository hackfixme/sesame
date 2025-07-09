package models

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mr-tron/base58"
	"github.com/nrednav/cuid2"

	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/types"
)

type Invite struct {
	ID        uint64
	UUID      string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	User      *User
	Nonce     []byte

	privKey *ecdh.PrivateKey
}

// NewInvite creates a new invitation for a remote user, which contains a unique
// token that must be supplied when authenticating to the server.
func NewInvite(user *User, expiration time.Time, uuid string) (*Invite, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	nonce, err := crypto.RandomData(32)
	if err != nil {
		return nil, fmt.Errorf("failed generating nonce: %w", err)
	}

	return &Invite{
		UUID:      uuid,
		ExpiresAt: expiration,
		User:      user,
		Nonce:     nonce,
		privKey:   privKey,
	}, nil
}

// Save stores the invite data in the database. If update is true, either the
// invite ID or UUID must be set for the lookup. The UUID may be a prefix, as
// long as it matches exactly one record. It returns an error if the invite
// doesn't exist, or if more than one record would be updated.
func (inv *Invite) Save(ctx context.Context, d types.Querier, update bool) error {
	var (
		stmt      string
		filterStr string
		op        string
		args      = []any{}
	)

	timeNow := d.TimeNow().UTC()
	if update {
		var (
			filter *types.Filter
			err    error
		)
		filter, filterStr, err = inv.createFilter(ctx, d, 1)
		if err != nil {
			return fmt.Errorf("failed creating query filter: %w", err)
		}
		stmt = fmt.Sprintf(`UPDATE invites
			SET updated_at = ?,
				expires_at = ?
			WHERE %s`, filter.Where)
		args = append([]any{timeNow, inv.ExpiresAt}, filter.Args...)
		op = fmt.Sprintf("updating invite with %s", filterStr)
	} else {
		stmt = `INSERT INTO invites (
				id, uuid, created_at, updated_at, expires_at, user_id, private_key, nonce)
				VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)`
		args = []any{inv.UUID, timeNow, timeNow, inv.ExpiresAt, inv.User.ID, inv.privKey.Bytes(), inv.Nonce}
		op = "saving new invite"
	}

	res, err := d.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("failed %s: %w", op, err)
	}

	if update {
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return types.NoResultError{ModelName: "invite", ID: filterStr}
		}
		inv.UpdatedAt = timeNow
	} else {
		invID, err := res.LastInsertId()
		if err != nil {
			return err
		}
		inv.ID = uint64(invID)
		inv.CreatedAt = timeNow
		inv.UpdatedAt = timeNow
	}

	return nil
}

// Load the invite record from the database. The invite ID, UUID or token must
// be set for the lookup.
func (inv *Invite) Load(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := inv.createFilter(ctx, d, 1)
	if err != nil {
		return fmt.Errorf("failed creating query filter: %w", err)
	}

	invites, err := Invites(ctx, d, filter)
	if err != nil {
		return err
	}

	if len(invites) == 0 {
		return types.NoResultError{ModelName: "invite", ID: filterStr}
	}

	*inv = *invites[0]

	return nil
}

// Delete removes the invite record from the database. Either the invite ID or
// UUID must be set for the lookup. The UUID may be a prefix, as long as it
// matches exactly one record. It returns an error if the invite doesn't exist,
// or if more than one record would be deleted.
func (inv *Invite) Delete(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := inv.createFilter(ctx, d, 1)
	if err != nil {
		return fmt.Errorf("failed creating query filter: %w", err)
	}

	stmt := fmt.Sprintf(`DELETE FROM invites WHERE %s`, filter.Where)
	res, err := d.ExecContext(ctx, stmt, filter.Args...)
	if err != nil {
		return fmt.Errorf("failed deleting invite with %s: %w", filterStr, err)
	}

	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return types.NoResultError{ModelName: "invite", ID: filterStr}
	}

	return nil
}

// Token generates the invite token by concatenating the nonce with the
// X25519 public key, and encoding it in base58.
func (inv *Invite) Token() (string, error) {
	token := slices.Concat(inv.Nonce, inv.privKey.PublicKey().Bytes())
	return base58.Encode(token), nil
}

// PrivateKey returns the X25519 private key.
func (inv *Invite) PrivateKey() *ecdh.PrivateKey {
	return inv.privKey
}

func (inv *Invite) createFilter(ctx context.Context, d types.Querier, limit int) (*types.Filter, string, error) {
	var filter *types.Filter
	var filterStr string
	if inv.ID != 0 {
		filter = types.NewFilter("id = ?", []any{inv.ID})
		filterStr = fmt.Sprintf("ID %d", inv.ID)
	} else if inv.UUID != "" {
		if !cuid2.IsCuid(inv.UUID) {
			return nil, "", fmt.Errorf("invalid invite UUID: '%s'", inv.UUID)
		}
		if len(inv.UUID) < 12 {
			filter = types.NewFilter("uuid LIKE ?", []any{fmt.Sprintf("%s%%", inv.UUID)})
			filterStr = fmt.Sprintf("UUID '%s*'", inv.UUID)
		} else {
			filter = types.NewFilter("uuid = ?", []any{inv.UUID})
			filterStr = fmt.Sprintf("UUID '%s'", inv.UUID)
		}
	} else if len(inv.Nonce) > 0 {
		filter = types.NewFilter("nonce = ?", []any{inv.Nonce}).
			And(types.NewFilter("expires_at > ?", []any{d.TimeNow().UTC()}))
		filterStr = "nonce"
	} else {
		return nil, "", errors.New("must provide either an invite ID, UUID or token")
	}

	if count, err := filterCount(ctx, d, "invites", filter); err != nil {
		return nil, "", err
	} else if count > limit {
		return nil, "", fmt.Errorf("filter with %s returns %d results; make the filter more specific", filterStr, count)
	}

	filter.Limit = limit

	return filter, filterStr, nil
}

// Invites returns one or more invites from the database. An optional filter can
// be passed to limit the results.
func Invites(ctx context.Context, d types.Querier, filter *types.Filter) ([]*Invite, error) {
	queryFmt := `SELECT inv.id, inv.uuid, inv.created_at, inv.updated_at, inv.expires_at, inv.user_id, inv.private_key, inv.nonce
		FROM invites inv
		%s ORDER BY inv.expires_at ASC %s`

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
		return nil, types.LoadError{ModelName: "invites", Err: err}
	}

	invites := []*Invite{}
	users := map[uint64]*User{}
	for rows.Next() {
		var (
			inv          = Invite{}
			userID       uint64
			privKeyBytes []byte
		)
		err := rows.Scan(&inv.ID, &inv.UUID, &inv.CreatedAt, &inv.UpdatedAt, &inv.ExpiresAt, &userID, &privKeyBytes, &inv.Nonce)
		if err != nil {
			return nil, types.ScanError{ModelName: "invite", Err: err}
		}

		// TODO: Load users in the same query for efficiency
		user, ok := users[userID]
		if !ok {
			user = &User{ID: userID}
			if err = user.Load(ctx, d); err != nil {
				return nil, types.LoadError{ModelName: "invite user", Err: err}
			}
			users[userID] = user
		}
		inv.User = user

		privKey, err := ecdh.X25519().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed loading X25519 private key: %w", err)
		}
		inv.privKey = privKey

		invites = append(invites, &inv)
	}

	return invites, nil
}
