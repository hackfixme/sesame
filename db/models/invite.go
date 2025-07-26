package models

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mr-tron/base58"
	"github.com/nrednav/cuid2"

	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/db/types"
)

// InviteStatus is a computed status of the invite based on its ExpiresAt and
// RedeemedAt fields.
type InviteStatus string

// Valid invite status values.
const (
	// InviteStatusActive represents an invite that hasn't yet expired nor been redeemed.
	InviteStatusActive InviteStatus = "active"
	// InviteStatusExpired represents an invite that has expired without being redeemed.
	InviteStatusExpired InviteStatus = "expired"
	// InviteStatusRedeemed represents an invite that was redeemed before it expired.
	InviteStatusRedeemed InviteStatus = "redeemed"
)

// Title returns the status text in title case.
func (s InviteStatus) Title() string {
	// strings.Title is deprecated, and I don't want to add another dependency for this
	return fmt.Sprintf("%s%s", strings.ToUpper(string(s[0])), s[1:])
}

// Invite is a single-use claim that is created by the server for a specific
// user that allows remote management of a Sesame node.
type Invite struct {
	ID         uint64
	UUID       string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ExpiresAt  time.Time
	RedeemedAt sql.Null[time.Time]
	User       *User
	// A unique identifier of the remote site this invite will be used in.
	// It's essentially the reverse of the remote name used by the client.
	SiteID string
	Nonce  []byte

	privKey *ecdh.PrivateKey
}

// NewInvite creates a new invitation for a remote user, which contains a unique
// token that must be supplied when authenticating to the server.
func NewInvite(user *User, expiration time.Time, siteID string, uuidGen func() string) (*Invite, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating X25519 key: %w", err)
	}

	nonce, err := crypto.RandomData(32)
	if err != nil {
		return nil, fmt.Errorf("failed generating nonce: %w", err)
	}

	if siteID == "" {
		siteID = uuidGen()
	}

	return &Invite{
		UUID:      uuidGen(),
		ExpiresAt: expiration,
		User:      user,
		SiteID:    siteID,
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
		args      []any
	)

	timeNow := d.TimeNow().UTC()
	if update { //nolint:nestif // It's fine.
		var (
			filter *types.Filter
			err    error
		)
		filter, filterStr, err = inv.createFilter(ctx, d, 1)
		if err != nil {
			return fmt.Errorf("failed creating query filter: %w", err)
		}
		args = []any{timeNow}
		var additional string
		if !inv.ExpiresAt.IsZero() {
			additional += ", expires_at = ?"
			args = append(args, inv.ExpiresAt)
		}
		if inv.IsRedeemed() {
			additional += ", redeemed_at = ?"
			args = append(args, inv.RedeemedAt.V)
		}
		if inv.SiteID != "" {
			additional += ", site_id = ?"
			args = append(args, inv.SiteID)
		}
		args = append(args, filter.Args...)
		stmt = fmt.Sprintf(`UPDATE invites
			SET updated_at = ?%s
			WHERE %s`, additional, filter.Where)
		op = fmt.Sprintf("updating invite with %s", filterStr)
	} else {
		stmt = `INSERT INTO invites (
				id, uuid, created_at, updated_at, expires_at, user_id, site_id, private_key, nonce)
				VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)`
		args = []any{
			inv.UUID, timeNow, timeNow, inv.ExpiresAt, inv.User.ID, inv.SiteID,
			inv.privKey.Bytes(), inv.Nonce,
		}
		op = "saving new invite"
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
			return types.NoResultError{ModelName: "invite", ID: filterStr}
		}
		inv.UpdatedAt = timeNow
	} else {
		inv.ID, err = lastInsertID(res)
		if err != nil {
			return err
		}
		inv.CreatedAt = timeNow
		inv.UpdatedAt = timeNow
	}

	return nil
}

// Load the invite record from the database. The invite ID, UUID or token must
// be set for the lookup. For filtering by RedeemedAt: Valid=false filters for
// NULL, Valid=true with zero time means no filter, and Valid=true with non-zero
// time filters for exact match.
func (inv *Invite) Load(ctx context.Context, d types.Querier) error {
	filter, filterStr, err := inv.createFilter(ctx, d, 1)
	if err != nil {
		return fmt.Errorf("failed creating query filter: %w", err)
	}

	if !inv.RedeemedAt.Valid {
		filter = filter.And(types.NewFilter("redeemed_at IS NULL", nil))
	} else if !inv.RedeemedAt.V.IsZero() {
		filter = filter.And(types.NewFilter("redeemed_at = ?", []any{inv.RedeemedAt.V}))
	}

	invites, err := Invites(ctx, d, filter, "")
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

	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("failed getting affected rows: %w", err)
	} else if n == 0 {
		return types.NoResultError{ModelName: "invite", ID: filterStr}
	}

	return nil
}

// Redeem stores the time this invite was redeemed at. An invite must not be
// redeemed more than once.
func (inv *Invite) Redeem(ctx context.Context, d types.Querier, t time.Time) error {
	if inv.IsRedeemed() {
		return errors.New("invite is already redeemed")
	}

	inv.RedeemedAt = sql.Null[time.Time]{V: t, Valid: true}
	if err := inv.Save(ctx, d, true); err != nil {
		return err
	}

	return nil
}

// IsRedeemed returns whether this invite has been redeemed.
func (inv *Invite) IsRedeemed() bool {
	return inv.RedeemedAt.Valid && !inv.RedeemedAt.V.IsZero()
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

// Status returns the current status of the invite based on its field values.
func (inv *Invite) Status(now time.Time) InviteStatus {
	if inv.RedeemedAt.Valid {
		return InviteStatusRedeemed
	}
	if now.After(inv.ExpiresAt) {
		return InviteStatusExpired
	}
	return InviteStatusActive
}

func (inv *Invite) createFilter(ctx context.Context, d types.Querier, limit int) (*types.Filter, string, error) {
	var filter *types.Filter
	var filterStr string
	switch {
	case inv.ID != 0:
		filter = types.NewFilter("id = ?", []any{inv.ID})
		filterStr = fmt.Sprintf("ID %d", inv.ID)
	case inv.UUID != "":
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
	case len(inv.Nonce) > 0:
		filter = types.NewFilter("nonce = ?", []any{inv.Nonce}).
			And(types.NewFilter("expires_at > ?", []any{d.TimeNow().UTC()}))
		filterStr = "nonce"
	default:
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
// be passed to limit the results, as well as an ORDER BY clause.
func Invites(
	ctx context.Context, d types.Querier, filter *types.Filter, orderBy string,
) (invites []*Invite, rerr error) {
	queryFmt := `SELECT
			inv.id, inv.uuid, inv.created_at, inv.updated_at, inv.expires_at, inv.redeemed_at,
			inv.user_id, inv.site_id, inv.private_key, inv.nonce
		FROM invites inv
		%s %s %s`

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

	if orderBy != "" {
		orderBy = fmt.Sprintf("ORDER BY %s", orderBy)
	}

	query := fmt.Sprintf(queryFmt, fmt.Sprintf("WHERE %s", where), orderBy, limit)

	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, types.LoadError{ModelName: "invites", Err: err}
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing invites rows: %w", err)
		}
	}()

	invites = make([]*Invite, 0)
	users := make(map[uint64]*User)
	for rows.Next() {
		var (
			inv          = &Invite{}
			userID       uint64
			privKeyBytes []byte
		)
		err = rows.Scan(
			&inv.ID, &inv.UUID, &inv.CreatedAt, &inv.UpdatedAt, &inv.ExpiresAt, &inv.RedeemedAt,
			&userID, &inv.SiteID, &privKeyBytes, &inv.Nonce)
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

		inv.privKey, err = ecdh.X25519().NewPrivateKey(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed loading X25519 private key: %w", err)
		}

		invites = append(invites, inv)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over invites rows: %w", err)
	}

	return invites, nil
}

// InvitesByStatus returns invites filtered by their status, ordered by Active
// -> Redeemed -> Expired, and ordered within each status by the most useful
// criteria:
// - Active: soonest expiration first (most urgent)
// - Redeemed: most recently redeemed first (latest activity)
// - Expired: most recently expired first (latest activity)
// TODO: Optimize this to use a single query with CTEs.
func InvitesByStatus(
	ctx context.Context, d types.Querier, statusFilter map[InviteStatus]bool,
	timeNow time.Time,
) ([]*Invite, error) {
	invitesAll := make([]*Invite, 0)

	if statusFilter[InviteStatusActive] {
		filter := types.NewFilter("inv.expires_at > ? AND inv.redeemed_at IS NULL", []any{timeNow})
		invites, err := Invites(ctx, d, filter, "inv.expires_at ASC")
		if err != nil {
			return nil, aerrors.NewWithCause("failed querying active invites", err)
		}
		invitesAll = append(invitesAll, invites...)
	}

	if statusFilter[InviteStatusRedeemed] {
		filter := types.NewFilter("inv.redeemed_at IS NOT NULL", nil)
		invites, err := Invites(ctx, d, filter, "inv.redeemed_at DESC")
		if err != nil {
			return nil, aerrors.NewWithCause("failed querying redeemed invites", err)
		}
		invitesAll = append(invitesAll, invites...)
	}

	if statusFilter[InviteStatusExpired] {
		filter := types.NewFilter("inv.expires_at <= ? AND inv.redeemed_at IS NULL", []any{timeNow})
		invites, err := Invites(ctx, d, filter, "inv.expires_at DESC")
		if err != nil {
			return nil, aerrors.NewWithCause("failed querying expired invites", err)
		}
		invitesAll = append(invitesAll, invites...)
	}

	return invitesAll, nil
}
