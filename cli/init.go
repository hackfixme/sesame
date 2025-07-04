package cli

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/mr-tron/base58"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/crypto"
)

// The Init command creates initial Sesame artifacts, such as firewall rules,
// the API server TLS key and certificate, and the Sesame database.
type Init struct{}

// Run the init command.
func (c *Init) Run(appCtx *actx.Context) error {
	if appCtx.VersionInit != "" {
		// TODO: Add --force option?
		return fmt.Errorf("Sesame is already initialized with version %s", appCtx.VersionInit)
	}

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
		return aerrors.NewRuntimeError("failed initializing database", err, "")
	}

	// TODO: Initialize the firewall here as well. Essentially Firewall.Setup
	// should be renamed to Firewall.Init, and only run here instead of in NewManager.

	return nil
}
