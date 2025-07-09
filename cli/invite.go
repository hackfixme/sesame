package cli

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
	"go.hackfix.me/sesame/db/types"
)

// The Invite command manages invitations for remote users.
type Invite struct {
	User struct {
		Name string        `arg:"" help:"The name of the user to invite."`
		TTL  time.Duration `default:"1h" help:"Time duration the invite is valid for."`
	} `cmd:"" help:"Create a new invitation token for an existing user to access this Sesame node remotely."`
	List struct {
		All bool `help:"Also include expired invites."`
	} `cmd:"" aliases:"ls" help:"List invites."`
	Remove struct {
		UUID []string `arg:"" help:"Unique invite IDs. A short prefix can be specified as long as it's unique."`
	} `cmd:"" aliases:"rm" help:"Delete one or more invites."`
	Update struct {
		UUID string         `arg:"" help:"The unique invite ID. A short prefix can be specified as long as it's unique."`
		TTL  *time.Duration `help:"Time duration the invite is valid for."`
	} `cmd:"" help:"Update an invite to extend its validity period."`
}

// Run the invite command.
func (c *Invite) Run(kctx *kong.Context, appCtx *actx.Context) error {
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Command() {
	case "invite user <name>":
		user := &models.User{Name: c.User.Name}
		if err := user.Load(dbCtx, appCtx.DB); err != nil {
			return aerrors.NewRuntimeError(
				fmt.Sprintf("failed loading user '%s'", c.User.Name), err, "")
		}
		inv, err := models.NewInvite(user, c.User.TTL, appCtx.UUIDGen(), appCtx.TimeNow)
		if err != nil {
			return aerrors.NewRuntimeError(
				fmt.Sprintf("failed creating invite for user '%s'", c.User.Name), err, "")
		}

		if err := inv.Save(dbCtx, appCtx.DB, false); err != nil {
			return aerrors.NewRuntimeError(
				"failed saving invite to the database", err, "")
		}
		token, err := inv.Token()
		if err != nil {
			return aerrors.NewRuntimeError("failed generating invitation token", err, "")
		}
		timeLeft := inv.ExpiresAt.Sub(appCtx.TimeNow().UTC())
		expFmt := fmt.Sprintf("%s (%s)",
			inv.ExpiresAt.Local().Format(time.DateTime),
			timeLeft.Round(time.Second))
		fmt.Fprintf(appCtx.Stdout, `Token: %s
Expires: %s
	`, token, expFmt)

	case "invite list":
		timeNow := appCtx.TimeNow().UTC()
		var filter *types.Filter
		if !c.List.All {
			filter = types.NewFilter("inv.expires_at > ?", []any{timeNow})
		}
		invites, err := models.Invites(dbCtx, appCtx.DB, filter)
		if err != nil {
			return aerrors.NewRuntimeError("failed listing invites", err, "")
		}

		expired, active := [][]string{}, [][]string{}
		for _, inv := range invites {
			timeLeft := inv.ExpiresAt.Sub(timeNow)

			token, err := inv.Token()
			if err != nil {
				return aerrors.NewRuntimeError("failed generating invitation token", err, "")
			}

			if timeLeft > 0 {
				expFmt := fmt.Sprintf("%s (%s)",
					inv.ExpiresAt.Local().Format(time.DateTime),
					timeLeft.Round(time.Second))
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
			header := []string{"UUID", "User", "Token", "Expiration"}
			newTable(header, data, appCtx.Stdout).Render()
		}

	case "invite remove":
		// TODO: Add a bulk deletion method?
		for _, invUUID := range c.Remove.UUID {
			inv := &models.Invite{UUID: invUUID}
			if err := inv.Delete(dbCtx, appCtx.DB); err != nil {
				return err
			}
		}

	case "invite update":
		if c.Update.TTL == nil {
			return errors.New("must set a valid TTL")
		}

		newExpiration := appCtx.TimeNow().UTC().Add(*c.Update.TTL)
		inv := &models.Invite{UUID: c.Update.UUID, ExpiresAt: newExpiration}
		if err := inv.Save(dbCtx, appCtx.DB, true); err != nil {
			return err
		}
	}

	return nil
}
