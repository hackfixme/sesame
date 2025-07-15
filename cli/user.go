package cli

import (
	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
)

// The User command manages remote Sesame users.
type User struct {
	Add struct {
		Name string `arg:"" help:"The unique name of the user."`
	} `cmd:"" help:"Add a new user."`
	Remove struct {
		Name string `arg:"" help:"The unique name of the user."`
	} `cmd:"" aliases:"rm" help:"Remove a user."`
	List struct{} `cmd:"" aliases:"ls" help:"List users."`
}

// Run the user command.
func (c *User) Run(kctx *kong.Context, appCtx *actx.Context) error {
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Command() {
	case "user add <name>":
		user := &models.User{Name: c.Add.Name}
		if err := user.Save(dbCtx, appCtx.DB, false); err != nil {
			return aerrors.NewWithCause("failed adding user", err)
		}
	case "user remove <name>":
		user := &models.User{Name: c.Remove.Name}
		if err := user.Delete(dbCtx, appCtx.DB); err != nil {
			return aerrors.NewWithCause("failed removing user", err)
		}
	case "user list":
		users, err := models.Users(dbCtx, appCtx.DB, nil)
		if err != nil {
			return aerrors.NewWithCause("failed querying users", err)
		}

		data := make([][]string, len(users))
		for i, user := range users {
			data[i] = []string{user.Name}
		}

		if len(data) > 0 {
			header := []string{"Name"}
			newTable(header, data, appCtx.Stdout).Render()
		}
	}

	return nil
}
