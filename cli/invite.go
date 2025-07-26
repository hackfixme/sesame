package cli

import (
	"fmt"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/xtime"
)

// The Invite command manages invitations for remote users.
type Invite struct {
	User struct {
		Name string `arg:"" help:"The name of the user to invite."`
		//nolint:lll // Long struct tags are unavoidable.
		Expiration time.Time `default:"1h" short:"e" type:"expiration" help:"Invite expiration as a time duration from now (e.g. 5m, 1h, 3d, 1w) or a future timestamp in RFC 3339 format (e.g. %s)."`
		SiteID     string    `short:"s" help:"A unique identifier for this remote site. E.g.: home, work. Default: random"`
	} `cmd:"" help:"Create a new invitation token for an existing user to access this Sesame node remotely."`
	List struct {
		//nolint:lll // Long struct tags are unavoidable.
		Status []string `short:"s" enum:"all,active,expired,redeemed" help:"Show invites with a specific status. Valid values: ${enum} \n Multiple values can be specified separated by comma, or 'all' to show all invites."`
		Token  bool     `short:"t" help:"Show the complete invitation token."`
	} `cmd:"" aliases:"ls" help:"List invites."`
	Remove struct {
		ID []string `arg:"" help:"Unique invite IDs. A short prefix can be specified as long as it is unique."`
	} `cmd:"" aliases:"rm" help:"Delete one or more invites."`
	Update struct {
		ID string `arg:"" help:"Unique invite ID. A short prefix can be specified as long as it is unique."`
		//nolint:lll // Long struct tags are unavoidable.
		Expiration time.Time `short:"e" type:"expiration" help:"Invite expiration as a time duration from now (e.g. 5m, 1h, 3d, 1w) or a future timestamp in RFC 3339 format (e.g. %s)."`
		SiteID     string    `short:"s" help:"A unique identifier for this remote site. E.g.: home, work."`
	} `cmd:"" help:"Update an invite."`
}

// Run the invite command.
func (c *Invite) Run(kctx *kong.Context, appCtx *actx.Context) error {
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Command() {
	case "invite user <name>":
		user := &models.User{Name: c.User.Name}
		if err := user.Load(dbCtx, appCtx.DB); err != nil {
			return aerrors.NewWithCause("failed loading user", err, "name", c.User.Name)
		}
		inv, err := models.NewInvite(user, c.User.Expiration, c.User.SiteID, appCtx.UUIDGen)
		if err != nil {
			return aerrors.NewWithCause("failed creating invite", err, "user_name", c.User.Name)
		}

		if err = inv.Save(dbCtx, appCtx.DB, false); err != nil {
			return aerrors.NewWithCause("failed saving invite to the database", err)
		}
		token, err := inv.Token()
		if err != nil {
			return aerrors.NewWithCause("failed generating invitation token", err)
		}
		timeLeft := inv.ExpiresAt.Sub(appCtx.TimeNow().UTC())
		expFmt := fmt.Sprintf("%s (%s)",
			inv.ExpiresAt.Local().Format(time.DateTime),
			xtime.FormatDuration(timeLeft, time.Second))
		_, err = fmt.Fprintf(appCtx.Stdout, `Token: %s
Expires At: %s
	`, token, expFmt)
		if err != nil {
			return aerrors.NewWithCause("failed writing to stdout", err)
		}

	case "invite list":
		var (
			statusFilter = statusFlagToFilter(c.List.Status)
			timeNow      = appCtx.TimeNow().UTC()
		)

		invites, err := models.InvitesByStatus(dbCtx, appCtx.DB, statusFilter, timeNow)
		if err != nil {
			return err
		}

		tableHeader, tableData, tableErr := invitesTable(invites, c.List.Token, timeNow)
		if tableErr != nil {
			return tableErr
		}

		if len(tableData) > 0 {
			err = renderTable(tableHeader, tableData, appCtx.Stdout)
			if err != nil {
				return aerrors.NewWithCause("failed rendering table", err)
			}
		}

	case "invite remove <id>":
		// TODO: Add a bulk deletion method?
		for _, invUUID := range c.Remove.ID {
			inv := &models.Invite{UUID: invUUID}
			if err := inv.Delete(dbCtx, appCtx.DB); err != nil {
				return err
			}
		}

	case "invite update <id>":
		inv := &models.Invite{UUID: c.Update.ID, ExpiresAt: c.Update.Expiration, SiteID: c.Update.SiteID}
		if err := inv.Save(dbCtx, appCtx.DB, true); err != nil {
			return err
		}
	}

	return nil
}

func statusFlagToFilter(status []string) map[models.InviteStatus]bool {
	filter := make(map[models.InviteStatus]bool)

	if len(status) == 0 {
		filter[models.InviteStatusActive] = true
		return filter
	}

	for _, s := range status {
		switch s {
		case "all":
			return map[models.InviteStatus]bool{
				models.InviteStatusActive:   true,
				models.InviteStatusRedeemed: true,
				models.InviteStatusExpired:  true,
			}
		case "active":
			filter[models.InviteStatusActive] = true
		case "redeemed":
			filter[models.InviteStatusRedeemed] = true
		case "expired":
			filter[models.InviteStatusExpired] = true
		}
	}

	return filter
}

func invitesTable(invites []*models.Invite, tokenFull bool, timeNow time.Time) ([]string, [][]string, error) {
	var (
		header = []string{"ID", "User", "Site ID", "Status", "Expiration", "Redeemed At", "Token"}
		data   = make([][]string, len(invites))
	)

	for i, inv := range invites {
		token, err := inv.Token()
		if err != nil {
			return nil, nil, aerrors.NewWithCause("failed generating invitation token", err)
		}

		if !tokenFull {
			token = fmt.Sprintf("%s...", token[:16])
		}

		var (
			status      = inv.Status(timeNow)
			statusTitle = status.Title()
			expFmt      = inv.ExpiresAt.Local().Format(time.DateTime)
		)
		switch status {
		case models.InviteStatusActive:
			expIn := xtime.FormatDuration(inv.ExpiresAt.Sub(timeNow), time.Second)
			expFmt = fmt.Sprintf("%s (in %s)", expFmt, expIn)
			data[i] = []string{
				inv.UUID, inv.User.Name, inv.SiteID, statusTitle, expFmt, "-", token,
			}
		case models.InviteStatusRedeemed:
			redAgo := xtime.FormatDuration(-inv.RedeemedAt.V.Sub(timeNow), time.Second)
			redFmt := fmt.Sprintf("%s (%s ago)",
				inv.RedeemedAt.V.Local().Format(time.DateTime), redAgo)
			data[i] = []string{
				inv.UUID, inv.User.Name, inv.SiteID, statusTitle, expFmt, redFmt, token,
			}
		case models.InviteStatusExpired:
			expAgo := xtime.FormatDuration(-inv.ExpiresAt.Sub(timeNow), time.Second)
			expFmt = fmt.Sprintf("%s (%s ago)", expFmt, expAgo)
			data[i] = []string{
				inv.UUID, inv.User.Name, inv.SiteID, statusTitle, expFmt, "-", token,
			}
		}
	}

	return header, data, nil
}
