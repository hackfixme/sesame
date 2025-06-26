package cli

import (
	"time"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/firewall"
)

// Open grants clients access to services.
type Open struct {
	ServiceName string `arg:"" required:"" help:"The name of the service."`
	//nolint:lll // Long struct tags are unavoidable.
	Clients        []string      `arg:"" required:"" help:"One or more client IP addresses in plain, CIDR or range notation. \n Examples: 10.0.0.10, 192.168.1.0/24, 172.16.1.10-172.16.1.100, a3:bc00::/32"`
	AccessDuration time.Duration `help:"Duration of the access."`
}

// Run the open command.
func (c *Open) Run(appCtx *actx.Context) error {
	ipSet, err := firewall.ParseToIPSet(c.Clients...)
	if err != nil {
		return err
	}

	err = appCtx.FirewallManager.AllowAccess(ipSet, c.ServiceName, c.AccessDuration)
	if err != nil {
		return err
	}

	return nil
}
