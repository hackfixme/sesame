package models

import (
	"context"
	"database/sql"
	"fmt"

	"go.hackfix.me/sesame/db/types"
)

func filterCount(ctx context.Context, d types.Querier, table string, filter *types.Filter) (int, error) {
	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM "%s" WHERE %s`, table, filter.Where)
	var count int
	err := d.QueryRowContext(ctx, countQ, filter.Args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed scanning %s count query: %w", table, err)
	}

	return count, nil
}

func lastInsertID(result sql.Result) (uint64, error) {
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	if id < 0 {
		return 0, fmt.Errorf("invalid negative ID from database: %d", id)
	}

	return uint64(id), nil
}
