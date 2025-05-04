package cli

import (
	"log/slog"
	"strings"

	"github.com/alecthomas/kong"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/models"
)

// CLI is the command line interface of Sesame.
type CLI struct {
	kong *kong.Kong
	kctx *kong.Context

	Serve Serve `kong:"cmd,help='Start the web server.'"`

	Log struct {
		Level slog.Level `enum:"DEBUG,INFO,WARN,ERROR" default:"INFO" help:"Set the app logging level."`
	} `embed:"" prefix:"log-"`
	// NOTE: I'm deliberately not using kong.ConfigFlag or its support for reading
	// values from configuration files, since I want to manage configuration
	// independently from the CLI.
	ConfigFile string           `kong:"default='${configFile}',help='Path to the configuration file.'"`
	Version    kong.VersionFlag `kong:"help='Output version and exit.'"`
}

// New initializes the command-line interface.
func New(configFilePath, version string) (*CLI, error) {
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
			"configFile": configFilePath,
			"version":    version,
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

// ApplyConfig applies configuration values to the CLI, but only if they weren't
// already set.
func (cli *CLI) ApplyConfig(cfg *models.Config) {
	if cli.Serve.Address == "" && cfg.Server.Address.Valid {
		cli.Serve.Address = cfg.Server.Address.V
	}
	if cli.Serve.TLSCertFile == "" && cfg.Server.TLSCertFile.Valid {
		cli.Serve.TLSCertFile = cfg.Server.TLSCertFile.V
	}
	if cli.Serve.TLSKeyFile == "" && cfg.Server.TLSKeyFile.Valid {
		cli.Serve.TLSKeyFile = cfg.Server.TLSKeyFile.V
	}
}
