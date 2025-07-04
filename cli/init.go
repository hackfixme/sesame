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
	FirewallType ftypes.FirewallType `help:"The firewall to initialize. Valid values: nftables"`
}

// Run the init command.
func (c *Init) Run(appCtx *actx.Context) error {
	if appCtx.VersionInit != "" {
		appCtx.Logger.Warn("The Sesame database is already initialized, skipping", "version", appCtx.VersionInit)
	} else {
		if err := initDB(appCtx); err != nil {
			return aerrors.NewRuntimeError("failed initializing database", err, "")
		}
	}

	if c.FirewallType != "" { //nolint:nestif // Meh, it's fine.
		if appCtx.Config.Firewall.Type.Valid {
			appCtx.Logger.Warn("A firewall is already initialized, skipping", "type", appCtx.Config.Firewall.Type.V)
		} else {
			fw, _, err := firewall.Setup(appCtx, c.FirewallType)
			if err != nil {
				return err
			}

			if err = fw.Init(); err != nil {
				return err
			}

			appCtx.Config.Firewall.Type.V = c.FirewallType
			appCtx.Config.Firewall.Type.Valid = true
		}
	}

	if err := appCtx.Config.Save(); err != nil {
		return aerrors.NewRuntimeError("failed saving configuration", err, "")
	}

	return nil
}

func initDB(appCtx *actx.Context) error {
	rndSANb := make([]byte, 16)
	_, err := rand.Read(rndSANb)
	if err != nil {
		return err
	}
	rndSAN := base58.Encode(rndSANb)
	tlsCert, tlsPrivKey, err := crypto.NewTLSCert(
		// TODO: Figure out certificate lifecycle management, make expiration configurable, etc.
		"Sesame server", []string{rndSAN}, time.Now().Add(24*time.Hour), nil,
	)
	if err != nil {
		return fmt.Errorf("failed generating the server TLS certificate: %w", err)
	}

	err = appCtx.DB.Init(appCtx.Version.Semantic, tlsCert.Raw, tlsPrivKey, rndSAN, appCtx.Logger)
	if err != nil {
		return err
	}

	return nil
}
