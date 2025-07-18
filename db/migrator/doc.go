// Package migrator provides functionality to manage database schema migrations.
//
// Features:
// - Supports both forward (`up`) and rollback (`down`) migrations
// - Loads SQL migration files from an embedded filesystem with structured naming (`{id}-{name}.{up|down}.sql`)
// - Tracks migration history in a dedicated database table
// - Executes migration plans to a target state or "all" migrations
// - Maintains chronological migration history with timestamps
package migrator
