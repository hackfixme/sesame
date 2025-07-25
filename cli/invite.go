package cli

import (
	"fmt"
	"slices"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/db/types"
	"go.hackfix.me/sesame/xtime"
)

// The Invite command manages invitations for remote users.
type Invite struct {
	User struct {
		Name string `arg:"" help:"The name of the user to invite."`
		//nolint:lll // Long struct tags are unavoidable.
		Expiration time.Time `default:"1h" short:"e" type:"expiration" help:"Invite expiration as a time duration from now (e.g. 5m, 1h, 3d, 1w) or a future timestamp in RFC 3339 format (e.g. %s)."`
	} `cmd:"" help:"Create a new invitation token for an existing user to access this Sesame node remotely."`
	List struct {
		All bool `short:"a" help:"Also include expired invites."`
	} `cmd:"" aliases:"ls" help:"List invites."`
	Remove struct {
		ID []string `arg:"" help:"Unique invite IDs. A short prefix can be specified as long as it is unique."`
	} `cmd:"" aliases:"rm" help:"Delete one or more invites."`
	Update struct {
		ID string `arg:"" help:"Unique invite ID. A short prefix can be specified as long as it is unique."`
		//nolint:lll // Long struct tags are unavoidable.
		Expiration time.Time `short:"e" type:"expiration" help:"Invite expiration as a time duration from now (e.g. 5m, 1h, 3d, 1w) or a future timestamp in RFC 3339 format (e.g. %s)."`
	} `cmd:"" help:"Update an invite."`
}

// Run the invite command.
//
//nolint:gocognit,funlen // A bit over the 30 max complexity, but it's fine.
func (c *Invite) Run(kctx *kong.Context, appCtx *actx.Context) error {
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Command() {
	case "invite user <name>":
		user := &models.User{Name: c.User.Name}
		if err := user.Load(dbCtx, appCtx.DB); err != nil {
			return aerrors.NewWithCause("failed loading user", err, "name", c.User.Name)
		}
		inv, err := models.NewInvite(user, c.User.Expiration, appCtx.UUIDGen())
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
		timeNow := appCtx.TimeNow().UTC()
		var filter *types.Filter
		if !c.List.All {
			filter = types.NewFilter("inv.expires_at > ?", []any{timeNow})
		}
		invites, err := models.Invites(dbCtx, appCtx.DB, filter)
		if err != nil {
			return aerrors.NewWithCause("failed listing invites", err)
		}

		expired, active := [][]string{}, [][]string{}
		for _, inv := range invites {
			timeLeft := inv.ExpiresAt.Sub(timeNow)

			var token string
			token, err = inv.Token()
			if err != nil {
				return aerrors.NewWithCause("failed generating invitation token", err)
			}

			if timeLeft > 0 {
				expFmt := fmt.Sprintf("%s (%s)",
					inv.ExpiresAt.Local().Format(time.DateTime),
					xtime.FormatDuration(timeLeft, time.Second))
				active = append(active, []string{inv.UUID, inv.User.Name, token, expFmt})
			} else {
				expFmt := fmt.Sprintf("%s (expired)",
					inv.ExpiresAt.Local().Format(time.DateTime))
				expired = append(expired, []string{inv.UUID, inv.User.Name, token, expFmt})
			}
		}

		data := active
		if len(expired) > 0 {
			if len(data) > 0 {
				data = slices.Concat(data, [][]string{{""}}, expired)
			} else {
				data = expired
			}
		}

		if len(data) > 0 {
			header := []string{"ID", "User", "Token", "Expires At"}
			err = renderTable(header, data, appCtx.Stdout)
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
		inv := &models.Invite{UUID: c.Update.ID, ExpiresAt: c.Update.Expiration}
		if err := inv.Save(dbCtx, appCtx.DB, true); err != nil {
			return err
		}
	}

	return nil
}
