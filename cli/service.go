package cli

import (
	"errors"
	"strconv"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/xtime"
)

// Service manages the services clients are allowed to access.
type Service struct {
	Add struct {
		Name              string        `arg:"" help:"Service name."`
		Port              portField     `arg:"" help:"Service port."`
		MaxAccessDuration time.Duration `default:"1h" help:"The maximum access duration per client."`
	} `cmd:"" help:"Add a new service."`
	Remove struct {
		Name string `arg:"" help:"Service name."`
	} `cmd:"" aliases:"rm" help:"Remove a service."`
	Update struct {
		Name              string        `arg:"" help:"Service name."`
		Port              portField     `arg:"" help:"Service port."`
		MaxAccessDuration time.Duration `required:"" help:"The maximum access duration per client."`
	} `cmd:"" help:"Update a service."`
	List struct{} `cmd:"" aliases:"ls" help:"List all services."`
}

// Run the service command.
func (c *Service) Run(kctx *kong.Context, appCtx *actx.Context) error {
	// TODO: Update firewall rules.
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Command() {
	case "service add <name> <port>":
		svc := &models.Service{
			Name:              c.Add.Name,
			Port:              uint16(c.Add.Port),
			MaxAccessDuration: c.Add.MaxAccessDuration,
		}
		if err := svc.Save(dbCtx, appCtx.DB, false); err != nil {
			return aerrors.NewWithCause("failed adding service", err)
		}
	case "service remove <name>":
		svc := &models.Service{Name: c.Remove.Name}
		if err := svc.Delete(dbCtx, appCtx.DB); err != nil {
			return aerrors.NewWithCause("failed removing service", err)
		}
	case "service update <name> <port>":
		svc := &models.Service{
			Name:              c.Update.Name,
			Port:              uint16(c.Update.Port),
			MaxAccessDuration: c.Update.MaxAccessDuration,
		}
		if err := svc.Save(dbCtx, appCtx.DB, true); err != nil {
			return aerrors.NewWithCause("failed updating service", err)
		}
	case "service list":
		services, err := models.Services(dbCtx, appCtx.DB, nil)
		if err != nil {
			return aerrors.NewWithCause("failed querying services", err)
		}

		data := make([][]string, len(services))
		for i, svc := range services {
			data[i] = []string{svc.Name, strconv.Itoa(int(svc.Port)), xtime.FormatDuration(svc.MaxAccessDuration, time.Second)}
		}

		if len(data) > 0 {
			header := []string{"Name", "Port", "Max Access Duration"}
			err = renderTable(header, data, appCtx.Stdout)
			if err != nil {
				return aerrors.NewWithCause("failed rendering table", err)
			}
		}
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
