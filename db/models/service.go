package models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.hackfix.me/sesame/db/types"
)

// Service represents a system service whose access can be managed by a firewall.
type Service struct {
	ID                uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Name              string
	Port              uint16
	MaxAccessDuration time.Duration
}

// Save stores the service data in the database.
func (s *Service) Save(ctx context.Context, d types.Querier, update bool) error {
	timeNow := d.TimeNow().UTC()
	if update { //nolint:nestif // It's fine.
		var filter *types.Filter
		var filterStr string
		switch {
		case s.ID != 0:
			filter = &types.Filter{Where: "id = ?", Args: []any{s.ID}}
			filterStr = fmt.Sprintf("ID %d", s.ID)
		case s.Name != "":
			filter = &types.Filter{Where: "name = ?", Args: []any{s.Name}}
			filterStr = fmt.Sprintf("name '%s'", s.Name)
		default:
			return errors.New("must provide either a service name or ID to update")
		}

		args := append([]any{timeNow, s.Port, s.MaxAccessDuration}, filter.Args...)
		updateStmt := fmt.Sprintf(`UPDATE services
			SET updated_at = ?,
			    port = ?,
			    max_access_duration = ?
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
			return types.NoResultError{ModelName: "service", ID: filterStr}
		}
		if n > 1 {
			return types.IntegrityError{Msg: fmt.Sprintf("updated %d services", n)}
		}
		s.UpdatedAt = timeNow
	} else {
		insertStmt := `INSERT INTO services
		(id, created_at, updated_at, name, port, max_access_duration)
		VALUES (NULL, ?, ?, ?, ?, ?)`
		res, err := d.ExecContext(ctx, insertStmt, timeNow, timeNow, s.Name, s.Port, s.MaxAccessDuration)
		if err != nil {
			return types.Err("service", fmt.Sprintf("name '%s'", s.Name), err)
		}

		s.ID, err = lastInsertID(res)
		if err != nil {
			return err
		}
		s.CreatedAt = timeNow
		s.UpdatedAt = timeNow
	}

	return nil
}

// Load the service data from the database. Either the service ID or Name must be set
// for the lookup.
//
//nolint:dupl // Similar method to Users.Load. "A little copying is better than a little dependency."
func (s *Service) Load(ctx context.Context, d types.Querier) error {
	if s.ID == 0 && s.Name == "" {
		return types.InvalidInputError{Msg: "either service ID or Name must be set"}
	}

	var filter *types.Filter
	var filterStr string
	if s.ID != 0 {
		filter = &types.Filter{Where: "s.id = ?", Args: []any{s.ID}}
		filterStr = fmt.Sprintf("ID %d", s.ID)
	} else if s.Name != "" {
		filter = &types.Filter{Where: "s.name = ?", Args: []any{s.Name}}
		filterStr = fmt.Sprintf("name '%s'", s.Name)
	}

	services, err := Services(ctx, d, filter)
	if err != nil {
		return err
	}

	if len(services) == 0 {
		return types.NoResultError{ModelName: "service", ID: filterStr}
	}

	// This is dodgy, but the unique constraint on both users.id and users.name
	// should return only a single result.
	if len(services) > 1 {
		panic(fmt.Sprintf("services query returned more than 1 service: %d", len(services)))
	}
	*s = *services[0]

	return nil
}

// Delete removes the service data from the database. Either the service ID or Name
// must be set for the lookup. It returns an error if the service doesn't exist.
//
//nolint:dupl // Similar method to Remote.Delete. "A little copying is better than a little dependency."
func (s *Service) Delete(ctx context.Context, d types.Querier) error {
	if s.ID == 0 && s.Name == "" {
		return types.InvalidInputError{Msg: "either user ID or Name must be set"}
	}

	var filter *types.Filter
	var filterStr string
	if s.ID != 0 {
		filter = &types.Filter{Where: "id = ?", Args: []any{s.ID}}
		filterStr = fmt.Sprintf("ID %d", s.ID)
	} else if s.Name != "" {
		filter = &types.Filter{Where: "name = ?", Args: []any{s.Name}}
		filterStr = fmt.Sprintf("name '%s'", s.Name)
	}

	stmt := fmt.Sprintf(`DELETE FROM services WHERE %s`, filter.Where)

	res, err := d.ExecContext(ctx, stmt, filter.Args...)
	if err != nil {
		return types.Err("service", filterStr, err)
	}

	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("failed getting affected rows: %w", err)
	} else if n == 0 {
		return types.NoResultError{ModelName: "service", ID: filterStr}
	}

	return nil
}

// Services returns one or more services from the database. An optional filter can be
// passed to limit the results.
func Services(ctx context.Context, d types.Querier, filter *types.Filter) (services []*Service, rerr error) {
	query := `SELECT
			s.id, s.created_at, s.updated_at, s.name, s.port, s.max_access_duration
		FROM services s %s
		ORDER BY s.name ASC`

	where := "1=1"
	args := []any{}
	if filter != nil {
		where = filter.Where
		args = filter.Args
	}

	query = fmt.Sprintf(query, fmt.Sprintf("WHERE %s", where))

	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, types.LoadError{ModelName: "services", Err: err}
	}
	defer func() {
		if err = rows.Close(); err != nil {
			rerr = fmt.Errorf("failed closing services rows: %w", err)
		}
	}()

	services = make([]*Service, 0)
	for rows.Next() {
		var s Service
		err = rows.Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt, &s.Name, &s.Port, &s.MaxAccessDuration)
		if err != nil {
			return nil, types.ScanError{ModelName: "service", Err: err}
		}
		services = append(services, &s)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating over services rows: %w", err)
	}

	return services, nil
}
