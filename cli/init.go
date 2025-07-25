package cli

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/mr-tron/base58"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/crypto"
	"go.hackfix.me/sesame/firewall"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

// The Init command creates initial Sesame artifacts, such as firewall rules,
// the API server TLS key and certificate, and the Sesame database.
type Init struct {
	FirewallType                  ftypes.FirewallType `help:"The firewall to initialize. Valid values: nftables"`
	FirewallDefaultAccessDuration time.Duration       `default:"5m" help:"The default duration to allow access if unspecified."` //nolint:lll // Long struct tags are unavoidable.
}

// Run the init command.
func (c *Init) Run(appCtx *actx.Context) error {
	if appCtx.VersionInit != "" {
		appCtx.Logger.Warn("The Sesame database is already initialized, skipping", "version", appCtx.VersionInit)
	} else {
		if err := initDB(appCtx); err != nil {
			return aerrors.NewWithCause("failed initializing database", err)
		}
	}

	cfg := appCtx.Config
	if c.FirewallType != "" { //nolint:nestif // Meh, it's fine.
		if cfg.Firewall.Type.Valid {
			appCtx.Logger.Warn("A firewall is already initialized, skipping", "type", cfg.Firewall.Type.V)
		} else {
			fw, _, err := firewall.Setup(appCtx, c.FirewallType, c.FirewallDefaultAccessDuration, appCtx.Logger)
			if err != nil {
				return err
			}

			if err = fw.Init(); err != nil {
				return err
			}

			cfg.Firewall.Type.V = c.FirewallType
			cfg.Firewall.Type.Valid = true
			cfg.Firewall.DefaultAccessDuration.V = c.FirewallDefaultAccessDuration
			cfg.Firewall.DefaultAccessDuration.Valid = true
		}
	}

	cfg.SetDefaults()

	if err := cfg.Save(); err != nil {
		return aerrors.NewWithCause("failed saving configuration", err)
	}

	return nil
}

func initDB(appCtx *actx.Context) error {
	rndSANb := make([]byte, 16)
	_, err := rand.Read(rndSANb)
	if err != nil {
		return fmt.Errorf("failed generating random SAN: %w", err)
	}
	rndSAN := base58.Encode(rndSANb)

	timeNow := appCtx.TimeNow()
	// TODO: Figure out certificate lifecycle management, make expiration configurable, etc.
	tlsCert, err := crypto.NewTLSCert(
		"Sesame server", []string{rndSAN}, timeNow, timeNow.Add(24*time.Hour), nil,
	)
	if err != nil {
		return fmt.Errorf("failed generating the server TLS certificate: %w", err)
	}

	tlsCertPEM, err := crypto.EncodeTLSCert(tlsCert)
	if err != nil {
		return fmt.Errorf("failed encoding the server TLS certificate: %w", err)
	}

	err = appCtx.DB.Init(appCtx.Version.Semantic, tlsCertPEM, appCtx.Logger)
	if err != nil {
		return err
	}

	return nil
}
