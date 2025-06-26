package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"
)

// Config represents the application configuration, backed by a filesystem for
// persistence.
type Config struct {
	fs       vfs.FileSystem
	path     string
	Server   ConfigServer
	Services map[string]Service `json:"services"`
}

// ConfigServer holds server-specific configuration options including
// network address and TLS certificate settings.
type ConfigServer struct {
	Address     sql.Null[string] `json:"address"`
	TLSCertFile sql.Null[string] `json:"tls_cert_file"`
	TLSKeyFile  sql.Null[string] `json:"tls_key_file"`
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

type cfgWrapper struct {
	Server   srvCfgWrapper         `json:"server"`
	Services map[string]svcWrapper `json:"services"`
}
type srvCfgWrapper struct {
	Address     string `json:"address,omitempty"`
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
}
type svcWrapper struct {
	Port              uint16 `json:"port"`
	MaxAccessDuration string `json:"max_access_duration,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to convert sql.Null values
// to their underlying types, omitting invalid/null fields from the output.
func (c Config) MarshalJSON() ([]byte, error) {
	w := cfgWrapper{
		Services: make(map[string]svcWrapper),
	}

	if c.Server.Address.Valid {
		w.Server.Address = c.Server.Address.V
	}
	if c.Server.TLSCertFile.Valid {
		w.Server.TLSCertFile = c.Server.TLSCertFile.V
	}
	if c.Server.TLSKeyFile.Valid {
		w.Server.TLSKeyFile = c.Server.TLSKeyFile.V
	}

	for name, svc := range c.Services {
		w.Services[name] = svcWrapper{
			Port:              svc.Port.V,
			MaxAccessDuration: svc.MaxAccessDuration.V.String(),
		}
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

	if w.Server.Address != "" {
		c.Server.Address = sql.Null[string]{V: w.Server.Address, Valid: true}
	}
	if w.Server.TLSCertFile != "" {
		c.Server.TLSCertFile = sql.Null[string]{V: w.Server.TLSCertFile, Valid: true}
	}
	if w.Server.TLSKeyFile != "" {
		c.Server.TLSKeyFile = sql.Null[string]{V: w.Server.TLSKeyFile, Valid: true}
	}

	c.Services = make(map[string]Service)

	for name, svc := range w.Services {
		maxDuration, err := time.ParseDuration(svc.MaxAccessDuration)
		if err != nil {
			return fmt.Errorf("invalid duration for service %s: %w", name, err)
		}

		c.Services[name] = Service{
			Name:              sql.Null[string]{V: name, Valid: true},
			Port:              sql.Null[uint16]{V: svc.Port, Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: maxDuration, Valid: true},
		}
	}

	return nil
}
