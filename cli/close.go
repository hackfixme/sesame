package cli

import (
	"context"
	"time"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/web/client"
)

// Close denies clients access to services.
type Close struct {
	ServiceName string `arg:"" required:"" help:"The name of the service."`
	//nolint:lll // Long struct tags are unavoidable.
	Clients []string `arg:"" optional:"" help:"Zero or more client IP addresses in plain, CIDR or range notation. \n Examples: 10.0.0.10, 192.168.1.0/24, 172.16.1.10-172.16.1.100, a3:bc00::/32 \n If no clients are specified, the service will be closed for all."`
	Remote  string   `help:"Name of the remote Sesame node on which to grant access."`
}

// Run the close command.
func (c *Close) Run(appCtx *actx.Context) error {
	// Assume that if no clients were specified, the service should be closed for all.
	clients := c.Clients
	if len(clients) == 0 {
		clients = []string{"0.0.0.0/0", "::/0"}
	}

	if c.Remote != "" { //nolint:nestif // It's fine.
		r := &models.Remote{Name: c.Remote}
		if err := r.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			return err
		}

		tlsConfig, err := r.ClientTLSConfig()
		if err != nil {
			return err
		}

		clientCtx, cancelClientCtx := context.WithTimeout(appCtx.Ctx, 10*time.Second)
		defer cancelClientCtx()

		client := client.New(r.Address, tlsConfig, appCtx.Logger)
		err = client.Close(clientCtx, clients, c.ServiceName)
		if err != nil {
			return err
		}
	} else {
		if !appCtx.Config.Firewall.Type.Valid {
			return aerrors.NewWith(
				"no firewall was configured on this system", "hint", "Did you forget to run 'sesame init'?")
		}

		ipSet, err := firewall.ParseToIPSet(clients...)
		if err != nil {
			return err
		}

		var fwMgr *firewall.Manager
		_, fwMgr, err = firewall.Setup(
			appCtx, appCtx.Config.Firewall.Type.V, appCtx.Config.Firewall.DefaultAccessDuration.V, appCtx.Logger,
		)
		if err != nil {
			return aerrors.NewWithCause(
				"failed setting up firewall", err, "firewall.type", appCtx.Config.Firewall.Type.V)
		}

		svc := &models.Service{Name: c.ServiceName}
		if err = svc.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			return aerrors.NewWithCause("unknown service", err, "service.name", c.ServiceName)
		}

		err = fwMgr.DenyAccess(ipSet, svc, nil)
		if err != nil {
			return aerrors.NewWithCause(
				"failed denying access", err,
				"service.name", c.ServiceName,
				"firewall.type", appCtx.Config.Firewall.Type.V)
		}
	}

	return nil
}
