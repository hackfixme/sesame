package cli

import (
	"fmt"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/db/models"
)

// The User command manages remote Sesame users.
type User struct {
	Add struct {
		Name string `arg:"" help:"The unique name of the user."`
	} `kong:"cmd,help='Add a new user.'"`
	Rm struct {
		Name string `arg:"" help:"The unique name of the user."`
	} `kong:"cmd,help='Remove a user.'"`
	Ls struct{} `kong:"cmd,help='List users.'"`
}

// Run the user command.
func (c *User) Run(kctx *kong.Context, appCtx *actx.Context) error {
	dbCtx := appCtx.DB.NewContext()

	switch kctx.Args[1] {
	case "add":
		user := &models.User{Name: c.Add.Name}
		if err := user.Save(dbCtx, appCtx.DB, false); err != nil {
			return aerrors.NewRuntimeError(
				fmt.Sprintf("failed adding user '%s'", c.Add.Name), err, "")
		}
	case "rm":
		user := &models.User{Name: c.Rm.Name}
		err := user.Delete(dbCtx, appCtx.DB)
		if err != nil {
			return err
		}
	case "ls":
		users, err := models.Users(dbCtx, appCtx.DB, nil)
		if err != nil {
			return aerrors.NewRuntimeError("failed listing users", err, "")
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
