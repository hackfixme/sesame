package firewall

import (
	"log/slog"
	"time"
)

// Option is a function that allows configuring the Manager.
type Option func(*Manager) error

// WithDefaultAccessDuration sets the default duration to allow access if unspecified.
func WithDefaultAccessDuration(dur time.Duration) Option {
	return func(m *Manager) error {
		m.defaultAccessDuration = dur
		return nil
	}
}

// WithLogger sets the logger used by the Manager.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Manager) error {
		m.logger = logger.With("component", "firewall")
		return nil
	}
}

// DefaultOptions returns the default Manager options.
func DefaultOptions() []Option {
	return []Option{
		WithDefaultAccessDuration(5 * time.Minute),
		WithLogger(slog.Default()),
	}
}
