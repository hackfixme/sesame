package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/mandelsoft/vfs/pkg/memoryfs"

	actx "go.hackfix.me/sesame/app/context"
	"go.hackfix.me/sesame/db"
	"go.hackfix.me/sesame/db/models"
)

var timeNow = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func timeNowFn() time.Time {
	return timeNow
}

type testApp struct {
	*App
	stdin          io.Writer
	stdout, stderr *hookWriter
	env            *mockEnv
	flushOutputs   func() error
}

func newTestApp(ctx context.Context) (*testApp, error) {
	// A unique name per app, to avoid clashing of in-memory SQLite DBs.
	rndName := make([]byte, 12)
	_, err := rand.Read(rndName)
	if err != nil {
		return nil, err
	}

	// Not using just :memory: to avoid 'no such table' issue.
	// See https://github.com/mattn/go-sqlite3#faq
	d, err := db.Open(ctx,
		fmt.Sprintf("file:sesame-%x?mode=memory&cache=shared", rndName), timeNowFn)
	if err != nil {
		return nil, err
	}

	var (
		stdinR, stdinW   = io.Pipe()
		stdoutW, stderrW = newHookWriter(ctx), newHookWriter(ctx)
	)

	env := &mockEnv{env: map[string]string{}}
	opts := []Option{
		WithTimeNow(timeNowFn),
		WithEnv(env),
		WithDB(d),
		WithContext(ctx),
		WithFDs(stdinR, stdoutW, stderrW),
		WithFS(memoryfs.New()),
		WithLogger(false, false),
	}
	app, err := New("sesame", "/config.json", "/data", opts...)
	if err != nil {
		return nil, err
	}

	tapp := &testApp{
		App: app, stdout: stdoutW, stderr: stderrW,
		stdin: stdinW, env: env,
	}
	tapp.flushOutputs = func() error {
		stdoutW.Reset()
		if _, rerr := stdoutW.ReadFrom(stdoutW.tmp); rerr != nil {
			return rerr
		}
		stdoutW.tmp.Reset()

		stderrW.Reset()
		if _, rerr := stderrW.ReadFrom(stderrW.tmp); rerr != nil {
			return rerr
		}
		stderrW.tmp.Reset()

		return nil
	}

	return tapp, nil
}

func (ta *testApp) Run(args ...string) error {
	if err := ta.App.Run(args); err != nil {
		return err
	}

	if err := ta.flushOutputs(); err != nil {
		return err
	}

	return nil
}

type mockEnv struct {
	mx  sync.RWMutex
	env map[string]string
}

var _ actx.Environment = (*mockEnv)(nil)

func (me *mockEnv) Get(key string) string {
	me.mx.RLock()
	defer me.mx.RUnlock()
	return me.env[key]
}

func (me *mockEnv) Set(key, val string) error {
	me.mx.Lock()
	defer me.mx.Unlock()
	me.env[key] = val
	return nil
}

// hookWriter is an io.Writer implementation that listens for writes and
// notifies subscribers when specific text is written.
type hookWriter struct {
	*safeBuffer             // main buffer read by tests
	tmp         *safeBuffer // temp buffer written to during each command
	ctx         context.Context
	mx          sync.RWMutex
	w           chan []byte
	subs        []chan []byte
}

func newHookWriter(ctx context.Context) *hookWriter {
	hw := &hookWriter{
		safeBuffer: newSafeBuffer(),
		tmp:        newSafeBuffer(),
		ctx:        ctx,
		w:          make(chan []byte, 10),
		subs:       make([]chan []byte, 0),
	}

	go func() {
		for {
			select {
			case d := <-hw.w:
				hw.mx.RLock()
				for _, s := range hw.subs {
					s <- d
				}
				hw.mx.RUnlock()
			case <-hw.ctx.Done():
				return
			}
		}
	}()

	return hw
}

// waitFor starts a goroutine that listens to written data and writes to wCh
// if there's a match of the provided regex pattern.
// If matchIdx > 0, it writes the matched element at that index. This is useful
// for returning substrings.
func (hw *hookWriter) waitFor(rxPat string, matchIdx int, wCh chan string) {
	rx := regexp.MustCompile(rxPat)

	ch := make(chan []byte)
	hw.mx.Lock()
	hw.subs = append(hw.subs, ch)
	hw.mx.Unlock()

	go func() {
		for {
			select {
			case d := <-ch:
				match := rx.FindStringSubmatch(string(d))
				if len(match)-1 >= matchIdx {
					wCh <- match[matchIdx]
					return
				}
			case <-hw.ctx.Done():
				return
			}
		}
	}()
}

func (hw *hookWriter) Write(p []byte) (n int, err error) {
	n, err = hw.tmp.Write(p)
	if err != nil {
		return
	}
	select {
	case hw.w <- p:
	case <-hw.ctx.Done():
	}
	return
}

// newTestContext returns a context that times out after timeout, and an
// assertion handling function that cancels the context prematurely and fails
// the test if the assertion fails. This is done to avoid waiting for the
// context timeout to be reached.
func newTestContext(t *testing.T, timeout time.Duration) (
	ctx context.Context, cancelCtx func(), assertHandler func(bool),
) {
	ctx, cancelCtx = context.WithTimeout(t.Context(), timeout)
	assertHandler = func(success bool) {
		if !success {
			cancelCtx()
			t.FailNow()
		}
	}

	return
}

// safeBuffer is a thread-safe buffer.
type safeBuffer struct {
	mx  sync.RWMutex
	buf *bytes.Buffer
}

func newSafeBuffer() *safeBuffer {
	return &safeBuffer{buf: &bytes.Buffer{}}
}

func (b *safeBuffer) Read(p []byte) (n int, err error) {
	b.mx.RLock()
	defer b.mx.RUnlock()
	return b.buf.Read(p)
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.mx.Lock()
	defer b.mx.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) ReadFrom(r io.Reader) (n int64, err error) {
	b.mx.Lock()
	defer b.mx.Unlock()
	return b.buf.ReadFrom(r)
}

func (b *safeBuffer) Reset() {
	b.mx.Lock()
	defer b.mx.Unlock()
	b.buf.Reset()
}

func (b *safeBuffer) String() string {
	b.mx.RLock()
	defer b.mx.RUnlock()
	return b.buf.String()
}

func (b *safeBuffer) Bytes() []byte {
	b.mx.RLock()
	defer b.mx.RUnlock()
	return b.buf.Bytes()
}

func initTestDB(appCtx *actx.Context, services []*models.Service) error {
	logger := slog.New(slog.DiscardHandler)
	err := appCtx.DB.Init("test", []byte{}, logger)
	if err != nil {
		return err
	}

	dbCtx := appCtx.DB.NewContext()
	for _, svc := range services {
		if err = svc.Save(dbCtx, appCtx.DB, false); err != nil {
			return err
		}
	}

	return nil
}
