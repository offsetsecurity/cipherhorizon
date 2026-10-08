package tlsprobe_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// A bug in a probe goroutine must fail the scan with a PanicError, not end the process:
// recover works only in the goroutine that panicked.
func TestAPanicInAProbeGoroutineFailsTheScan(t *testing.T) {
	o := opts()
	o.Dial = func(context.Context, string, string) (net.Conn, error) { panic("probe bug") }
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "127.0.0.1", Port: 443}, o)
	var pe *tlsprobe.PanicError
	if !errors.As(err, &pe) || pe.Value != "probe bug" || len(pe.Stack) == 0 {
		t.Fatalf("err = %v, want a PanicError carrying the value and a stack", err)
	}
	if rep == nil || !rep.Incomplete {
		t.Fatalf("the report should be returned and marked incomplete: %+v", rep)
	}
}

// A panic on the scan's own goroutine is recovered too.
func TestAPanicInTheScanItselfFailsTheScan(t *testing.T) {
	o := opts()
	o.LookupIP = func(context.Context, string) ([]net.IP, error) { panic("resolver bug") }
	_, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "example.invalid", Port: 443}, o)
	var pe *tlsprobe.PanicError
	if !errors.As(err, &pe) || pe.Value != "resolver bug" {
		t.Fatalf("err = %v, want a PanicError", err)
	}
}
