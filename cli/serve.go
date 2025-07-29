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

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/web/server"
	stypes "go.hackfix.me/sesame/web/server/types"
)

// Serve starts the web server.
type Serve struct {
	Address string `arg:"" help:"[host]:port to listen on"`
	//nolint:lll // Long struct tags are unavoidable.
	ErrorLevel stypes.ErrorLevel `default:"none" enum:"none,minimal,full" help:"Detail level of error messages returned to clients from untrusted HTTP endpoints (e.g. /join), in order to avoid leaking sensitive information. This doesn't affect response status codes. Valid values: ${enum} \n none: hide all error messages; minimal: sanitize error messages; full: keep error messages intact"`
}

// Run the serve command.
func (c *Serve) Run(appCtx *actx.Context) error {
	tlsCert, err := appCtx.ServerTLSCert()
	if err != nil {
		return err
	}

	srv, err := server.New(appCtx, c.Address, &tlsCert, c.ErrorLevel)
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
