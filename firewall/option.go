package firewall

import (
	"log/slog"
)

// Option is a function that allows configuring the Manager.
type Option func(*Manager) error

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
		WithLogger(slog.Default()),
	}
}
