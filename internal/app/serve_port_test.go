package app_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
)

// freePort returns a port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// startServe runs serve with args until the test ends and returns the address it announced.
func startServe(t *testing.T, args ...string) string {
	t.Helper()
	// The database directory is made before the cleanup below is registered, so the server has
	// stopped (and closed it) by the time it is removed.
	db := filepath.Join(t.TempDir(), "x.db")
	ctx, cancel := context.WithCancel(context.Background())
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, append([]string{"serve", "--db", db}, args...), app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("server did not shut down")
		}
	})
	re := regexp.MustCompile(`UI and API on http://(\S+) `)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			return m[1]
		}
		select {
		case code := <-done:
			t.Fatalf("serve exited %d: %s", code, errb.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("serve never announced its address: %s", errb.String())
	return ""
}

func TestServeListensOnTheGivenPort(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	t.Setenv("CIPHERHORIZON_ADDR", "")
	t.Setenv("CIPHERHORIZON_PORT", "")
	p := freePort(t)
	if got, want := startServe(t, "--port", strconv.Itoa(p)), "127.0.0.1:"+strconv.Itoa(p); got != want {
		t.Errorf("--port %d: listening on %s, want %s", p, got, want)
	}
	// --port 0 picks a free port and the start-up line says which.
	if got := startServe(t, "--port", "0"); strings.HasSuffix(got, ":0") {
		t.Errorf("--port 0 announced %s, not the port actually used", got)
	}
}

func TestServeAndHealthcheckFollowThePortEnvironment(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	t.Setenv("CIPHERHORIZON_ADDR", "")
	p := freePort(t)
	t.Setenv("CIPHERHORIZON_PORT", strconv.Itoa(p))
	if got := startServe(t); got != "127.0.0.1:"+strconv.Itoa(p) {
		t.Fatalf("with CIPHERHORIZON_PORT=%d serve listens on %s", p, got)
	}
	var errb bytes.Buffer
	if code := app.Main(context.Background(), []string{"healthcheck"}, app.Env{Stdout: io.Discard, Stderr: &errb}); code != app.ExitOK {
		t.Errorf("healthcheck with CIPHERHORIZON_PORT=%d: exit %d: %s", p, code, errb.String())
	}
}

func TestHealthcheckFollowsPortEnvironment(t *testing.T) {
	t.Setenv("CIPHERHORIZON_ADDR", "0.0.0.0")
	p := freePort(t) // nothing listens there
	t.Setenv("CIPHERHORIZON_PORT", strconv.Itoa(p))
	var errb bytes.Buffer
	if code := app.Main(context.Background(), []string{"healthcheck"}, app.Env{Stdout: io.Discard, Stderr: &errb}); code == app.ExitOK {
		t.Fatal("healthcheck succeeded against a port nothing listens on")
	}
	if want := "127.0.0.1:" + strconv.Itoa(p); !strings.Contains(errb.String(), want) {
		t.Errorf("healthcheck did not probe %s (the wildcard host on loopback): %s", want, errb.String())
	}
}

func TestServeBusyPortSaysWhatToDo(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	t.Setenv("CIPHERHORIZON_ADDR", "")
	t.Setenv("CIPHERHORIZON_PORT", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup
	p := ln.Addr().(*net.TCPAddr).Port
	var errb bytes.Buffer
	code := app.Main(context.Background(), []string{"serve", "--port", strconv.Itoa(p), "--db", filepath.Join(t.TempDir(), "x.db")},
		app.Env{Stdout: io.Discard, Stderr: &errb})
	if code != app.ExitFatal {
		t.Fatalf("exit %d on a busy port, want fatal", code)
	}
	msg := errb.String()
	for _, want := range []string{"port " + strconv.Itoa(p) + " is already in use", "--port " + strconv.Itoa(p+1)} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q: %s", want, msg)
		}
	}
}
