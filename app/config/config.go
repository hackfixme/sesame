package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"

	ftypes "go.hackfix.me/sesame/firewall/types"
)

// Config represents the application configuration, backed by a filesystem for
// persistence.
type Config struct {
	Firewall Firewall
	Server   Server

	fs   vfs.FileSystem
	path string
}

// NewConfig creates a new Config instance with the specified filesystem
// and configuration file path.
func NewConfig(fs vfs.FileSystem, path string) *Config {
	return &Config{fs: fs, path: path}
}

// Load reads and parses the configuration file from the filesystem.
// If the file doesn't exist, it initializes with an empty configuration.
func (c *Config) Load() error {
	if err := c.fs.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return fmt.Errorf("failed creating configuration directory: %w", err)
	}

	configJSON, err := vfs.ReadFile(c.fs, c.path)
	if err != nil && !vfs.IsErrNotExist(err) {
		return fmt.Errorf("failed reading configuration file: %w", err)
	}

	// Ensure that unmarshalling JSON doesn't fail if the file doesn't exist or is empty.
	if len(configJSON) == 0 {
		configJSON = []byte("{}")
	}

	if err = json.Unmarshal(configJSON, c); err != nil {
		return fmt.Errorf("failed parsing configuration file: %w", err)
	}

	return nil
}

// Path returns the filesystem path where the configuration is stored.
func (c *Config) Path() string {
	return c.path
}

// Save writes the current configuration to the filesystem as JSON.
func (c *Config) Save() error {
	if err := c.fs.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return fmt.Errorf("failed creating configuration directory: %w", err)
	}
	configJSON, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed serializing configuration data: %w", err)
	}
	if err = vfs.WriteFile(c.fs, c.path, configJSON, 0o644); err != nil {
		return fmt.Errorf("failed writing configuration file: %w", err)
	}

	return nil
}

// Server holds server-specific configuration options.
type Server struct {
	Address sql.Null[string] `json:"address"`
}

// Firewall holds firewall-specific configuration options.
type Firewall struct {
	Type                  sql.Null[ftypes.FirewallType] `json:"type"`
	DefaultAccessDuration sql.Null[time.Duration]       `json:"default_access_duration"`
}

type cfgWrapper struct {
	Firewall fwCfgWrapper  `json:"firewall"`
	Server   srvCfgWrapper `json:"server"`
}
type fwCfgWrapper struct {
	Type                  string `json:"type,omitempty"`
	DefaultAccessDuration string `json:"default_access_duration,omitempty"`
}
type srvCfgWrapper struct {
	Address string `json:"address,omitempty"`
}
type svcWrapper struct {
	Port              uint16 `json:"port"`
	MaxAccessDuration string `json:"max_access_duration,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to convert sql.Null values
// to their underlying types, omitting invalid/null fields from the output.
func (c Config) MarshalJSON() ([]byte, error) {
	w := cfgWrapper{}

	if c.Firewall.Type.Valid {
		w.Firewall.Type = string(c.Firewall.Type.V)
	}
	if c.Firewall.DefaultAccessDuration.Valid {
		w.Firewall.DefaultAccessDuration = c.Firewall.DefaultAccessDuration.V.String()
	}

	if c.Server.Address.Valid {
		w.Server.Address = c.Server.Address.V
	}

	//nolint:wrapcheck // This is fine.
	return json.Marshal(w)
}

// UnmarshalJSON implements custom JSON unmarshaling to convert plain values
// into sql.Null types and parse duration strings into time.Duration values.
func (c *Config) UnmarshalJSON(data []byte) error {
	var w cfgWrapper
	if err := json.Unmarshal(data, &w); err != nil {
		//nolint:wrapcheck // This is fine.
		return err
	}

	if w.Firewall.Type != "" {
		ft, err := ftypes.FirewallTypeFromString(w.Firewall.Type)
		if err != nil {
			return err
		}
		c.Firewall.Type = sql.Null[ftypes.FirewallType]{V: ft, Valid: true}
	}
	if w.Firewall.DefaultAccessDuration != "" {
		dur, err := time.ParseDuration(w.Firewall.DefaultAccessDuration)
		if err != nil {
			return fmt.Errorf("failed parsing default access duration: %w", err)
		}
		c.Firewall.DefaultAccessDuration = sql.Null[time.Duration]{V: dur, Valid: true}
	}

	if w.Server.Address != "" {
		c.Server.Address = sql.Null[string]{V: w.Server.Address, Valid: true}
	}

	return nil
}
