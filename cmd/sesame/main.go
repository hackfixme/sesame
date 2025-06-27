// Package main contains the entrypoint for the application.
package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
	"github.com/mandelsoft/vfs/pkg/osfs"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"

	"go.hackfix.me/sesame/app"
	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	ftypes "go.hackfix.me/sesame/firewall/types"
)

func main() {
	a, err := app.New("sesame",
		filepath.Join(xdg.ConfigHome, "sesame", "config.json"),
		app.WithTimeNow(time.Now),
		app.WithEnv(osEnv{}),
		app.WithFDs(
			os.Stdin,
			colorable.NewColorable(os.Stdout),
			colorable.NewColorable(os.Stderr),
		),
		app.WithFS(osfs.New()),
		app.WithLogger(
			isatty.IsTerminal(os.Stdout.Fd()),
			isatty.IsTerminal(os.Stderr.Fd()),
		),
		app.WithFirewall(ftypes.FirewallNFTables),
	)
	if err != nil {
		aerrors.Errorf(err)
		os.Exit(1)
	}
	if err = a.Run(os.Args[1:]); err != nil {
		aerrors.Errorf(err)
		os.Exit(1)
	}
}

type osEnv struct{}

var _ actx.Environment = (*osEnv)(nil)

func (e osEnv) Get(key string) string {
	return os.Getenv(key)
}

func (e osEnv) Set(key, val string) error {
	//nolint:wrapcheck // This is fine.
	return os.Setenv(key, val)
}
