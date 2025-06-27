package cli

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	svc "go.hackfix.me/sesame/service"
)

// Service manages the services clients are allowed to access.
type Service struct {
	Add struct {
		Name              string        `arg:"" help:"Service name."`
		Port              portField     `arg:"" help:"Service port."`
		MaxAccessDuration time.Duration `default:"1h" help:"The maximum access duration per client."`
	} `kong:"cmd,help='Add a new service.'"`
	Remove struct {
		Name string `arg:"" help:"Service name."`
	} `kong:"cmd,help='Remove a service.',aliases='rm'"`
	Update struct {
		Name              string        `arg:"" help:"Service name."`
		Port              portField     `arg:"" help:"Service port."`
		MaxAccessDuration time.Duration `default:"1h" help:"The maximum access duration per client."`
	} `kong:"cmd,help='Update a service.'"`
	List struct{} `kong:"cmd,help='List all services.',aliases='ls'"`
}

// Run the service command.
func (c *Service) Run(kctx *kong.Context, appCtx *actx.Context) error {
	// TODO: Update firewall rules.

	var action string
	switch kctx.Args[1] {
	case "add":
		if _, ok := appCtx.Config.Services[c.Add.Name]; ok {
			return aerrors.NewRuntimeError(fmt.Sprintf("service '%s' already exists", c.Add.Name), nil, "")
		}
		appCtx.Config.Services[c.Add.Name] = svc.Service{
			Name:              sql.Null[string]{V: c.Add.Name, Valid: true},
			Port:              sql.Null[uint16]{V: uint16(c.Add.Port), Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: c.Add.MaxAccessDuration, Valid: true},
		}
		action = "adding"
	case "remove", "rm":
		if _, ok := appCtx.Config.Services[c.Remove.Name]; !ok {
			return aerrors.NewRuntimeError(fmt.Sprintf("service '%s' doesn't exist", c.Remove.Name), nil, "")
		}
		delete(appCtx.Config.Services, c.Remove.Name)
		action = "removing"
	case "update":
		if _, ok := appCtx.Config.Services[c.Update.Name]; !ok {
			return aerrors.NewRuntimeError(fmt.Sprintf("service '%s' doesn't exist", c.Update.Name), nil, "")
		}
		appCtx.Config.Services[c.Update.Name] = svc.Service{
			Name:              sql.Null[string]{V: c.Update.Name, Valid: true},
			Port:              sql.Null[uint16]{V: uint16(c.Update.Port), Valid: true},
			MaxAccessDuration: sql.Null[time.Duration]{V: c.Update.MaxAccessDuration, Valid: true},
		}
		action = "updating"
	case "list", "ls":
		if len(appCtx.Config.Services) == 0 {
			return nil
		}

		svcNames := make([]string, 0, len(appCtx.Config.Services))
		for svcName := range appCtx.Config.Services {
			svcNames = append(svcNames, svcName)
		}
		slices.Sort(svcNames)

		w := tabwriter.NewWriter(appCtx.Stdout, 6, 2, 2, ' ', 0)
		_, err := fmt.Fprintln(w, "Name\tPort\tMax Access Duration")
		if err != nil {
			return aerrors.NewRuntimeError("failed writing to stdout", err, "")
		}
		_, err = fmt.Fprintln(w, "----\t----\t-------------------")
		if err != nil {
			return aerrors.NewRuntimeError("failed writing to stdout", err, "")
		}
		for _, svcName := range svcNames {
			svc := appCtx.Config.Services[svcName]
			_, err = fmt.Fprintf(w, "%s\t%d\t%s\n", svc.Name.V, svc.Port.V, svc.MaxAccessDuration.V)
			if err != nil {
				return aerrors.NewRuntimeError("failed writing to stdout", err, "")
			}
		}
		err = w.Flush()
		if err != nil {
			return aerrors.NewRuntimeError("failed flushing stdout writer", err, "")
		}

		return nil
	}

	if err := appCtx.Config.Save(); err != nil {
		return aerrors.NewRuntimeError(fmt.Sprintf("failed %s service %s", action, c.Add.Name), err, "")
	}

	return nil
}

type portField uint16

func (p portField) Validate() error {
	if p == 0 {
		return errors.New("must be greater than 0")
	}
	return nil
}
