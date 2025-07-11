package cli

import (
	"time"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/firewall"
)

// Open grants clients access to services.
type Open struct {
	ServiceName string `arg:"" required:"" help:"The name of the service."`
	//nolint:lll // Long struct tags are unavoidable.
	Clients  []string      `arg:"" required:"" help:"One or more client IP addresses in plain, CIDR or range notation. \n Examples: 10.0.0.10, 192.168.1.0/24, 172.16.1.10-172.16.1.100, a3:bc00::/32"`
	Duration time.Duration `short:"d" help:"Duration of the access."`
}

// Run the open command.
func (c *Open) Run(appCtx *actx.Context) error {
	if !appCtx.Config.Firewall.Type.Valid {
		return aerrors.NewWith(
			"no firewall was configured on this system", "hint", "Did you forget to run 'sesame init'?")
	}

	ipSet, err := firewall.ParseToIPSet(c.Clients...)
	if err != nil {
		return err
	}

	_, fwMgr, err := firewall.Setup(
		appCtx, appCtx.Config.Firewall.Type.V, appCtx.Config.Firewall.DefaultAccessDuration.V,
	)
	if err != nil {
		return err
	}

	err = fwMgr.AllowAccess(ipSet, c.ServiceName, c.Duration)
	if err != nil {
		return err
	}

	return nil
}
