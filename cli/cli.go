package cli

import (
	"log/slog"
	"strings"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
)

// CLI is the command line interface of Sesame.
type CLI struct {
	kong *kong.Kong
	kctx *kong.Context

	Serve Serve `kong:"cmd,help='Start the web server.'"`

	Log struct {
		Level slog.Level `enum:"DEBUG,INFO,WARN,ERROR" default:"INFO" help:"Set the app logging level."`
	} `embed:"" prefix:"log-"`
	Version kong.VersionFlag `kong:"help='Output Sesame version and exit.'"`
}

// New initializes the command-line interface.
func New(version string) (*CLI, error) {
	c := &CLI{}
	kparser, err := kong.New(c,
		kong.Name("sesame"),
		kong.UsageOnError(),
		kong.DefaultEnvars("SESAME"),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:             true,
			Summary:             true,
			NoExpandSubcommands: true,
		}),
		kong.Vars{
			"version": version,
		},
	)
	if err != nil {
		return nil, err
	}

	c.kong = kparser

	return c, nil
}

// Execute starts the command execution. Parse must be called before this method.
func (c *CLI) Execute(appCtx *actx.Context) error {
	if c.kctx == nil {
		panic("the CLI wasn't initialized properly")
	}
	c.kong.Stdout = appCtx.Stdout
	c.kong.Stderr = appCtx.Stderr

	return c.kctx.Run(appCtx)
}

// Parse the given command line arguments. This method must be called before
// Execute.
func (c *CLI) Parse(args []string) error {
	kctx, err := c.kong.Parse(args)
	if err != nil {
		return err
	}
	c.kctx = kctx

	return nil
}

// Command returns the full path of the executed command.
func (c *CLI) Command() string {
	if c.kctx == nil {
		panic("the CLI wasn't initialized properly")
	}
	cmdPath := []string{}
	for _, p := range c.kctx.Path {
		if p.Command != nil {
			cmdPath = append(cmdPath, p.Command.Name)
		}
	}

	return strings.Join(cmdPath, " ")
}
