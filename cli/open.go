package cli

import (
	"context"
	"crypto/tls"
	"time"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/firewall"
	"go.hackfix.me/sesame/web/client"
)

// Open grants clients access to services.
type Open struct {
	ServiceName string `arg:"" required:"" help:"The name of the service."`
	//nolint:lll // Long struct tags are unavoidable.
	Clients  []string      `arg:"" required:"" help:"One or more client IP addresses in plain, CIDR or range notation. \n Examples: 10.0.0.10, 192.168.1.0/24, 172.16.1.10-172.16.1.100, a3:bc00::/32"`
	Duration time.Duration `short:"d" help:"Duration of the access."`
	Remote   string        `help:"Name of the remote Sesame node on which to grant access."`
}

// Run the open command.
func (c *Open) Run(appCtx *actx.Context) error {
	ipSet, err := firewall.ParseToIPSet(c.Clients...)
	if err != nil {
		return err
	}

	if c.Remote != "" { //nolint:nestif // It's fine.
		r := &models.Remote{Name: c.Remote}
		if err = r.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			return err
		}

		var tlsConfig *tls.Config
		tlsConfig, err = r.ClientTLSConfig()
		if err != nil {
			return err
		}

		clientCtx, cancelClientCtx := context.WithTimeout(appCtx.Ctx, 10*time.Second)
		defer cancelClientCtx()

		client := client.New(r.Address, tlsConfig, appCtx.Logger)
		err = client.Open(clientCtx, c.Clients, c.ServiceName, c.Duration)
		if err != nil {
			return err
		}
	} else {
		if !appCtx.Config.Firewall.Type.Valid {
			return aerrors.NewWith(
				"no firewall was configured on this system", "hint", "Did you forget to run 'sesame init'?")
		}

		var fwMgr *firewall.Manager
		_, fwMgr, err = firewall.Setup(
			appCtx, appCtx.Config.Firewall.Type.V, appCtx.Config.Firewall.DefaultAccessDuration.V, appCtx.Logger,
		)
		if err != nil {
			return aerrors.NewWithCause(
				"failed setting up firewall", err, "firewall_type", appCtx.Config.Firewall.Type.V)
		}

		svc := &models.Service{Name: c.ServiceName}
		if err = svc.Load(appCtx.DB.NewContext(), appCtx.DB); err != nil {
			return aerrors.NewWithCause("unknown service", err, "service.name", c.ServiceName)
		}

		err = fwMgr.AllowAccess(ipSet, svc, c.Duration)
		if err != nil {
			return aerrors.NewWithCause(
				"failed granting access", err, "firewall_type", appCtx.Config.Firewall.Type.V)
		}
	}

	return nil
}
