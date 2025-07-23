package cli

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"go.hackfix.me/sesame/app/config"
	actx "go.hackfix.me/sesame/app/context"
)

// CLI is the command line interface of Sesame.
type CLI struct {
	Init    Init    `kong:"cmd,help='Create initial application artifacts.'"`
	Invite  Invite  `kong:"cmd,help='Manage invitations for remote users.'"`
	Open    Open    `kong:"cmd,help='Grant clients access to services.'"`
	Close   Close   `kong:"cmd,help='Deny clients access to services.'"`
	Remote  Remote  `kong:"cmd,help='Manage remote Sesame nodes.'"`
	Serve   Serve   `kong:"cmd,help='Start the web server.'"`
	Service Service `kong:"cmd,help='Manage services.'"`
	User    User    `kong:"cmd,help='Manage remote users.'"`

	Log struct {
		Level slog.Level `enum:"DEBUG,INFO,WARN,ERROR" default:"INFO" help:"Set the app logging level."`
	} `embed:"" prefix:"log-"`
	// NOTE: I'm deliberately not using kong.ConfigFlag or its support for reading
	// values from configuration files, since I want to manage configuration
	// independently from the CLI.
	ConfigFile string           `kong:"default='${configFile}',help='Path to the Sesame configuration file.'"`
	DataDir    string           `kong:"default='${dataDir}',help='Path to the directory where Sesame data is stored.'"`
	Version    kong.VersionFlag `kong:"help='Output version and exit.'"`

	kong *kong.Kong
	kctx *kong.Context
}

// New initializes the command-line interface.
func New(appCtx *actx.Context, configFilePath, dataDir, version string) (*CLI, error) {
	c := &CLI{}
	kparser, err := kong.New(c,
		kong.Name("sesame"),
		kong.UsageOnError(),
		kong.DefaultEnvars("SESAME"),
		kong.NamedMapper("expiration", &ExpirationMapper{timeNow: appCtx.TimeNow}),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:             true,
			Summary:             true,
			NoExpandSubcommands: true,
		}),
		kong.ValueFormatter(func(value *kong.Value) string {
			if value.Name == "expiration" {
				y, m, d := appCtx.TimeNow().Date()
				exampleExp := time.Date(y, m, d+1, 0, 0, 0, 0, appCtx.TimeNow().Location())
				value.Help = fmt.Sprintf(value.OrigHelp, exampleExp.Format(time.RFC3339))
			}
			return value.Help
		}),
		kong.Vars{
			"configFile": configFilePath,
			"dataDir":    dataDir,
			"version":    version,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating the Kong parser: %w", err)
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

	//nolint:wrapcheck // This is fine.
	return c.kctx.Run(appCtx)
}

// Parse the given command line arguments. This method must be called before
// Execute.
func (c *CLI) Parse(args []string) error {
	kctx, err := c.kong.Parse(args)
	if err != nil {
		return fmt.Errorf("failed parsing CLI arguments: %w", err)
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

// ApplyConfig applies configuration values to the CLI, but only if they weren't
// already set.
func (c *CLI) ApplyConfig(cfg *config.Config) {
	if c.Serve.Address == "" && cfg.Server.Address.Valid {
		c.Serve.Address = cfg.Server.Address.V
	}
}
