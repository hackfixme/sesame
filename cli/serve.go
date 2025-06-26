package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mandelsoft/vfs/pkg/vfs"

	actx "go.hackfix.me/sesame/app/context"
	aerrors "go.hackfix.me/sesame/app/errors"
	"go.hackfix.me/sesame/web/server"
)

// Serve starts the web server.
type Serve struct {
	Address     string `help:"[host]:port to listen on"`
	TLSCertFile string `help:"Path to a TLS certificate file"`
	TLSKeyFile  string `help:"Path to a TLS private key file"`
}

// Run the serve command.
func (c *Serve) Run(appCtx *actx.Context) error {
	var tlsCert []byte
	if c.TLSCertFile != "" {
		var err error
		tlsCert, err = vfs.ReadFile(appCtx.FS, c.TLSCertFile)
		if err != nil {
			return aerrors.NewRuntimeError(
				fmt.Sprintf("failed reading TLS certificate file '%s'", c.TLSCertFile), err, "")
		}
	}

	var tlsKey []byte
	if c.TLSKeyFile != "" {
		var err error
		tlsKey, err = vfs.ReadFile(appCtx.FS, c.TLSKeyFile)
		if err != nil {
			return aerrors.NewRuntimeError(
				fmt.Sprintf("failed reading TLS private key file '%s'", c.TLSKeyFile), err, "")
		}
	}

	srv, err := server.New(appCtx, c.Address, tlsCert, tlsKey)
	if err != nil {
		return err
	}

	// Gracefully shutdown the server if a process signal is received, or the
	// main context is done.
	// See https://dev.to/mokiat/proper-http-shutdown-in-go-3fji
	srvDone := make(chan error)
	go func() {
		srvErr := srv.ListenAndServe()
		slog.Debug("web server shutdown")
		srvDone <- srvErr
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sigCh:
		slog.Debug("process received signal", "signal", s)
	case <-appCtx.Ctx.Done():
		slog.Debug("app context is done")
	case srvErr := <-srvDone:
		if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			return fmt.Errorf("web server error: %w", srvErr)
		}
		return nil
	}

	if err = srv.Shutdown(appCtx.Ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("failed shutting down web server: %w", err)
	}

	return nil
}
