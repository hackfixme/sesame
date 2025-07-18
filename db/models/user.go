package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.hackfix.me/sesame/db/types"
)

// User represents a remote Sesame user.
type User struct {
	ID        uint64
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      string
}

// Save stores the user data in the database.
func (u *User) Save(ctx context.Context, d types.Querier, update bool) error {
	timeNow := d.TimeNow().UTC()
	if update { //nolint:nestif // It's fine.
		var filter *types.Filter
		var filterStr string
		switch {
		case u.ID != 0:
			filter = &types.Filter{Where: "id = ?", Args: []any{u.ID}}
			filterStr = fmt.Sprintf("ID %d", u.ID)
		case u.Name != "":
			filter = &types.Filter{Where: "name = ?", Args: []any{u.Name}}
			filterStr = fmt.Sprintf("name '%s'", u.Name)
		default:
			return errors.New("must provide either a user name or ID to update")
		}

		args := append([]any{timeNow}, filter.Args...)
		updateStmt := fmt.Sprintf(`UPDATE users
			SET updated_at = ?
			WHERE %s`, filter.Where)
		res, err := d.ExecContext(ctx, updateStmt, args...)
		if err != nil {
			return err
		}

		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed getting affected rows: %w", err)
		}
		if n == 0 {
			return types.NoResultError{ModelName: "user", ID: filterStr}
		}
		if n > 1 {
			return types.IntegrityError{Msg: fmt.Sprintf("updated %d users", n)}
		}
		u.UpdatedAt = timeNow
	} else {
		insertStmt := `INSERT INTO users
		(id, created_at, updated_at, name)
		VALUES (NULL, ?, ?, ?)`
		res, err := d.ExecContext(ctx, insertStmt, timeNow, timeNow, u.Name)
		if err != nil {
			return types.Err("user", fmt.Sprintf("name '%s'", u.Name), err)
		}

		u.ID, err = lastInsertID(res)
		if err != nil {
			return err
		}
		u.CreatedAt = timeNow
		u.UpdatedAt = timeNow
	}

	return nil
}

// Load the user data from the database. Either the user ID or Name must be set
// for the lookup.
//
//nolint:dupl // Similar method to Service.Load. "A little copying is better than a little dependency."
func (u *User) Load(ctx context.Context, d types.Querier) error {
	if u.ID == 0 && u.Name == "" {
		return types.InvalidInputError{Msg: "either user ID or Name must be set"}
	}

	var filter *types.Filter
	var filterStr string
	if u.ID != 0 {
		filter = &types.Filter{Where: "u.id = ?", Args: []any{u.ID}}
		filterStr = fmt.Sprintf("ID %d", u.ID)
	} else if u.Name != "" {
		filter = &types.Filter{Where: "u.name = ?", Args: []any{u.Name}}
		filterStr = fmt.Sprintf("name '%s'", u.Name)
	}

	users, err := Users(ctx, d, filter)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		return types.NoResultError{ModelName: "user", ID: filterStr}
	}

	// This is dodgy, but the unique constraint on both users.id and users.name
	// should return only a single result.
	if len(users) > 1 {
		panic(fmt.Sprintf("users query returned more than 1 user: %d", len(users)))
	}
	*u = *users[0]

	return nil
}

// Delete removes the user data from the database. Either the user ID or Name
// must be set for the lookup. It returns an error if the user doesn't exist.
func (u *User) Delete(ctx context.Context, d types.Querier) error {
	if u.ID == 0 && u.Name == "" {
		return types.InvalidInputError{Msg: "either user ID or Name must be set"}
	}

	var filter *types.Filter
	var filterStr string
	if u.ID != 0 {
		filter = &types.Filter{Where: "id = ?", Args: []any{u.ID}}
		filterStr = fmt.Sprintf("ID %d", u.ID)
	} else if u.Name != "" {
		filter = &types.Filter{Where: "name = ?", Args: []any{u.Name}}
		filterStr = fmt.Sprintf("name '%s'", u.Name)
	}

	stmt := fmt.Sprintf(`DELETE FROM users WHERE %s`, filter.Where)

	res, err := d.ExecContext(ctx, stmt, filter.Args...)
	if err != nil {
		return types.Err("user", filterStr, err)
	}

	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("failed getting affected rows: %w", err)
	} else if n == 0 {
		return types.NoResultError{ModelName: "user", ID: filterStr}
	}

	return nil
}

// Users returns one or more users from the database. An optional filter can be
// passed to limit the results.
func Users(ctx context.Context, d types.Querier, filter *types.Filter) (users []*User, rerr error) {
	query := `SELECT u.id, u.created_at, u.updated_at, u.name
		FROM users u %s
		ORDER BY u.name ASC`

	where := "1=1"
	args := []any{}
	if filter != nil {
		where = filter.Where
		args = filter.Args
	}

	query = fmt.Sprintf(query, fmt.Sprintf("WHERE %s", where))

	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, types.LoadError{ModelName: "users", Err: err}
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing users rows: %w", err)
		}
	}()

	users = make([]*User, 0)
	for rows.Next() {
		var u User
		err = rows.Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt, &u.Name)
		if err != nil {
			return nil, types.ScanError{ModelName: "user", Err: err}
		}
		users = append(users, &u)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over users rows: %w", err)
	}

	return users, nil
}
