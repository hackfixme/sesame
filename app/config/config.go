package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mandelsoft/vfs/pkg/vfs"

	ftypes "go.hackfix.me/sesame/firewall/types"
	"go.hackfix.me/sesame/xtime"
)

// Config represents the application configuration, backed by a filesystem for
// persistence.
type Config struct {
	Firewall Firewall
	Server   Server
	Client   Client

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

// Server defines configuration options specific to the HTTP server.
type Server struct {
	// Address is the network address in [host]:port format the server will listen on.
	Address sql.Null[string] `json:"address"`
	// TLSCertExpiration is the amount of time the server's TLS certificate is valid for.
	// It serializes from/to xtime.Duration string values. Minimum value: 1 hour.
	TLSCertExpiration sql.Null[time.Duration] `json:"tls_cert_expiration"`
	// TLSCertRenewalThreshold is the proportion of the server's TLS certificate
	// lifetime after which a new certificate will be issued.
	// E.g. if TLSCertExpiration is set to 90 days and TLSCertRenewalThreshold is
	// set to 0.75, the server's certificate will be scheduled for renewal after
	// 67.5 days.
	TLSCertRenewalThreshold sql.Null[float64] `json:"tls_cert_renewal_threshold"`
}

// Client defines configuration options specific to the HTTP client.
type Client struct {
	// TLSCertExpiration is the amount of time client TLS certificates are valid for.
	// It serializes from/to xtime.Duration string values. Minimum value: 1 hour.
	TLSCertExpiration sql.Null[time.Duration] `json:"tls_cert_expiration"`
	// TLSCertRenewalThreshold is the proportion of the client's TLS certificate
	// lifetime after which a new certificate will be requested.
	// E.g. if TLSCertExpiration is set to 30 days and TLSCertRenewalThreshold is
	// set to 0.75, the client will request a certificate renewal after 22.5 days.
	TLSCertRenewalThreshold sql.Null[float64] `json:"tls_cert_renewal_threshold"`
	// TLSCertRenewalTokenExpiration is the amount of time the client's renewal
	// token is valid for after the TLSCertExpiration time.
	// It serializes from/to xtime.Duration string values. Minimum value: 1 hour.
	TLSCertRenewalTokenExpiration sql.Null[time.Duration] `json:"tls_cert_renewal_token_expiration"`
}

// Firewall defines firewall-specific configuration options.
type Firewall struct {
	// Type is the firewall backend used on this system.
	Type sql.Null[ftypes.FirewallType] `json:"type"`
	// DefaultAccessDuration is the time clients are allowed access to services on
	// this system unless specified by the user.
	// It serializes from/to xtime.Duration string values. Minimum value: 1 minute.
	DefaultAccessDuration sql.Null[time.Duration] `json:"default_access_duration"`
}

type cfgWrapper struct {
	Firewall fwCfgWrapper     `json:"firewall"`
	Server   srvCfgWrapper    `json:"server"`
	Client   clientCfgWrapper `json:"client"`
}
type fwCfgWrapper struct {
	Type                  string `json:"type,omitempty"`
	DefaultAccessDuration string `json:"default_access_duration,omitempty"`
}
type srvCfgWrapper struct {
	Address                 string  `json:"address,omitempty"`
	TLSCertExpiration       string  `json:"tls_cert_expiration,omitempty"`
	TLSCertRenewalThreshold float64 `json:"tls_cert_renewal_threshold,omitempty"`
}
type clientCfgWrapper struct {
	TLSCertExpiration             string  `json:"tls_cert_expiration,omitempty"`
	TLSCertRenewalThreshold       float64 `json:"tls_cert_renewal_threshold,omitempty"`
	TLSCertRenewalTokenExpiration string  `json:"tls_cert_renewal_token_expiration,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to convert sql.Null values
// to their underlying types, omitting invalid/null fields from the output.
func (c Config) MarshalJSON() ([]byte, error) {
	w := cfgWrapper{}

	if c.Firewall.Type.Valid {
		w.Firewall.Type = string(c.Firewall.Type.V)
	}
	if c.Firewall.DefaultAccessDuration.Valid {
		w.Firewall.DefaultAccessDuration = xtime.FormatDuration(c.Firewall.DefaultAccessDuration.V, time.Minute)
	}

	if c.Server.Address.Valid {
		w.Server.Address = c.Server.Address.V
	}
	if c.Server.TLSCertExpiration.Valid {
		w.Server.TLSCertExpiration = xtime.FormatDuration(c.Server.TLSCertExpiration.V, time.Hour)
	}
	if c.Server.TLSCertRenewalThreshold.Valid {
		w.Server.TLSCertRenewalThreshold = c.Server.TLSCertRenewalThreshold.V
	}

	if c.Client.TLSCertExpiration.Valid {
		w.Client.TLSCertExpiration = xtime.FormatDuration(c.Client.TLSCertExpiration.V, time.Hour)
	}
	if c.Client.TLSCertRenewalThreshold.Valid {
		w.Client.TLSCertRenewalThreshold = c.Client.TLSCertRenewalThreshold.V
	}
	if c.Client.TLSCertRenewalTokenExpiration.Valid {
		w.Client.TLSCertRenewalTokenExpiration = xtime.FormatDuration(c.Client.TLSCertRenewalTokenExpiration.V, time.Hour)
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
		dur, err := xtime.ParseDuration(w.Firewall.DefaultAccessDuration)
		if err != nil {
			return fmt.Errorf("failed parsing default access duration: %w", err)
		}
		c.Firewall.DefaultAccessDuration = sql.Null[time.Duration]{V: dur, Valid: true}
	}

	if w.Server.Address != "" {
		c.Server.Address = sql.Null[string]{V: w.Server.Address, Valid: true}
	}
	if w.Server.TLSCertExpiration != "" {
		dur, err := xtime.ParseDuration(w.Server.TLSCertExpiration)
		if err != nil {
			return fmt.Errorf("failed parsing server's TLS cert expiration: %w", err)
		}
		c.Server.TLSCertExpiration = sql.Null[time.Duration]{V: dur, Valid: true}
	}
	if w.Server.TLSCertRenewalThreshold > 0 {
		c.Server.TLSCertRenewalThreshold = sql.Null[float64]{V: w.Server.TLSCertRenewalThreshold, Valid: true}
	}

	if w.Client.TLSCertExpiration != "" {
		dur, err := xtime.ParseDuration(w.Client.TLSCertExpiration)
		if err != nil {
			return fmt.Errorf("failed parsing client's TLS cert expiration: %w", err)
		}
		c.Client.TLSCertExpiration = sql.Null[time.Duration]{V: dur, Valid: true}
	}
	if w.Client.TLSCertRenewalThreshold > 0 {
		c.Client.TLSCertRenewalThreshold = sql.Null[float64]{V: w.Client.TLSCertRenewalThreshold, Valid: true}
	}
	if w.Client.TLSCertRenewalTokenExpiration != "" {
		dur, err := xtime.ParseDuration(w.Client.TLSCertRenewalTokenExpiration)
		if err != nil {
			return fmt.Errorf("failed parsing client's TLS cert renewal token expiration: %w", err)
		}
		c.Client.TLSCertRenewalTokenExpiration = sql.Null[time.Duration]{V: dur, Valid: true}
	}

	return nil
}

// SetDefaults sets default configuration values if they weren't set already.
func (c *Config) SetDefaults() {
	if !c.Server.TLSCertExpiration.Valid {
		// ~3 months
		c.Server.TLSCertExpiration = sql.Null[time.Duration]{V: 24 * time.Hour * 90, Valid: true}
	}
	if !c.Server.TLSCertRenewalThreshold.Valid {
		c.Server.TLSCertRenewalThreshold = sql.Null[float64]{V: 0.75, Valid: true}
	}
	if !c.Client.TLSCertExpiration.Valid {
		// ~1 month
		c.Client.TLSCertExpiration = sql.Null[time.Duration]{V: 24 * time.Hour * 30, Valid: true}
	}
	if !c.Client.TLSCertRenewalThreshold.Valid {
		c.Client.TLSCertRenewalThreshold = sql.Null[float64]{V: 0.75, Valid: true}
	}
	if !c.Client.TLSCertRenewalTokenExpiration.Valid {
		// ~5 months
		c.Client.TLSCertRenewalTokenExpiration = sql.Null[time.Duration]{V: 24 * time.Hour * 30 * 5, Valid: true}
	}
}
