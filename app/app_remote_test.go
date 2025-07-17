package app

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	aerrors "go.hackfix.me/sesame/app/errors"
)

// Test the scenario of 2 Sesame nodes, where one creates a user and invitation
// token, and the other joins and runs the open command over the network.
// This is a very broad integration test that tests multiple commands, the
// remote authentication flow, and remote operations.
func TestAppRemoteIntegration(t *testing.T) {
	t.Parallel()

	// wg.Wait must be deferred before the test context cancellation (so that
	// it's called after it when the function returns) to avoid waiting for the
	// context timeout to be reached.
	var wg sync.WaitGroup
	defer wg.Wait()

	timeout := 5 * time.Second
	tctx, cancel, h := newTestContext(t, timeout)
	defer cancel()

	// app1 will accept remote connections
	app1, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	err = app1.Run("init", "--firewall-type=mock")
	h(assert.NoError(t, err))

	err = app1.Run("service", "add", "python", "8080")
	h(assert.NoError(t, err))

	err = app1.Run("service", "ls")
	h(assert.NoError(t, err))
	h(assert.Contains(t, app1.stdout.String(), "python  8080  1h"))

	err = app1.Run("user", "add", "newuser")
	h(assert.NoError(t, err))

	err = app1.Run("invite", "user", "newuser", "--expiration=1m")
	h(assert.NoError(t, err))

	// Extract the invite token from the output
	tokenRx := regexp.MustCompile(`^Token: (.*)\n`)
	match := tokenRx.FindStringSubmatch(app1.stdout.String())
	h(assert.Lenf(t, match, 2, "token not found in output:\n%s", app1.stdout.String()))

	token := match[1]

	// Start the web server on app1
	addrCh := make(chan string)
	app1.stderr.waitFor(`started listener.*address=(.*)\n`, 1, addrCh)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = app1.Run("serve", "--log-level=DEBUG", ":0")
		h(assert.NoError(t, err))
	}()

	var srvAddress string
	select {
	case srvAddress = <-addrCh:
	case <-tctx.Done():
		t.Fatalf("timed out after %s", timeout)
	}

	// app2 is the remote client that will join app1 with the generated token
	app2, err := newTestApp(tctx)
	h(assert.NoError(t, err))

	err = app2.Run("init", "--firewall-type=mock")
	h(assert.NoError(t, err))

	err = app2.Run("remote", "add", "testremote", srvAddress, token)
	h(assert.NoError(t, err))

	// The service doesn't exist for app2 locally...
	err = app2.Run("open", "python", "10.0.0.10")
	h(assert.EqualError(t, err, "unknown service"))
	h(assert.Equal(t, "", app2.stdout.String()))

	// ... but it does exist on the remote node.
	err = app2.Run("open", "--remote=testremote", "python", "10.0.0.10", "--duration=1h")
	h(assert.NoError(t, err))
	h(assert.Equal(t, "", app2.stdout.String()))

	err = app1.flushOutputs()
	h(assert.NoError(t, err))

	// Confirm that the firewall rule was added on app1.
	var app1fwdebug string
	for line := range strings.Lines(app1.stderr.String()) {
		if strings.Contains(line, "DBG granted access") {
			app1fwdebug = line
			break
		}
	}
	h(assert.Contains(t, app1fwdebug, "user_name=newuser"))
	h(assert.Contains(t, app1fwdebug, "range=10.0.0.10-10.0.0.10"))
	h(assert.Contains(t, app1fwdebug, "port=8080"))
	h(assert.Contains(t, app1fwdebug, "duration=1h"))

	// Confirm that the invite token has been redeemed and cannot be reused.
	err = app2.Run("remote", "add", "testremote2", srvAddress, token)
	h(assert.Error(t, err))
	var serr *aerrors.StructuredError
	h(assert.ErrorAs(t, err, &serr))
	h(assert.Equal(t, http.StatusUnauthorized, serr.Metadata()["status_code"]))
}
