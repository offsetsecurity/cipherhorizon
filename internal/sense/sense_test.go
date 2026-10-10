package sense_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	"github.com/offsetsecurity/cipherhorizon/internal/sense/sensetest"
)

func registry(t *testing.T, fakes ...*sensetest.Fake) *sense.Registry {
	t.Helper()
	r := sense.NewRegistry()
	for _, f := range fakes {
		if err := r.Register(f.SensorInfo.Name, sensetest.Factory(f)); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func runs(res sense.Result) map[string]sense.Run {
	m := map[string]sense.Run{}
	for _, r := range res.Runs {
		m[r.Name] = r
	}
	return m
}

func batchOf(keys ...string) evidence.Batch {
	var b evidence.Batch
	for _, k := range keys {
		b.Observations = append(b.Observations, sensetest.Observation(k))
	}
	return b
}

func TestRegisterAndNew(t *testing.T) {
	r := sense.NewRegistry()
	if err := r.Register("apt", sensetest.Factory(&sensetest.Fake{SensorInfo: sensetest.Info("apt")})); err != nil {
		t.Fatal(err)
	}
	s, err := r.New("apt", sense.Env{})
	if err != nil || s.Info().Name != "apt" {
		t.Fatalf("New = %v, %v", s, err)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	r := sense.NewRegistry()
	f := sensetest.Factory(&sensetest.Fake{SensorInfo: sensetest.Info("apt")})
	if err := r.Register("Bad Name", f); err == nil {
		t.Error("invalid name accepted")
	}
	if err := r.Register("apt", nil); err == nil {
		t.Error("nil factory accepted")
	}
	if err := r.Register("apt", f); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("apt", f); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate: %v", err)
	}
}

func TestNamesSorted(t *testing.T) {
	r := registry(t, &sensetest.Fake{SensorInfo: sensetest.Info("rpm")}, &sensetest.Fake{SensorInfo: sensetest.Info("apt")}, &sensetest.Fake{SensorInfo: sensetest.Info("jvm")})
	if got, want := r.Names(), []string{"apt", "jvm", "rpm"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v", got)
	}
}

func TestNewChecksTheSensorReportsItsRegisteredName(t *testing.T) {
	r := sense.NewRegistry()
	_ = r.Register("apt", sensetest.Factory(&sensetest.Fake{SensorInfo: sensetest.Info("rpm")}))
	if _, err := r.New("apt", sense.Env{}); err == nil || !strings.Contains(err.Error(), "reports name") {
		t.Errorf("err = %v", err)
	}
	_ = r.Register("nomethods", sensetest.Factory(&sensetest.Fake{SensorInfo: sense.Info{Name: "nomethods", Version: "1"}}))
	if _, err := r.New("nomethods", sense.Env{}); err == nil {
		t.Error("a sensor declaring no methods was accepted")
	}
	_ = r.Register("undeclared", sensetest.Factory(&sensetest.Fake{SensorInfo: sense.Info{Name: "undeclared", Version: "1", Methods: []string{"made.up@1"}}}))
	if _, err := r.New("undeclared", sense.Env{}); err == nil {
		t.Error("a sensor using an undeclared method was accepted")
	}
}

func TestRunStatuses(t *testing.T) {
	boom := errors.New("disk on fire")
	reg := registry(t,
		&sensetest.Fake{SensorInfo: sensetest.Info("ok"), CollectFn: func(context.Context) (evidence.Batch, error) { return batchOf("a"), nil }},
		&sensetest.Fake{SensorInfo: sensetest.Info("absent"), DetectFn: func(context.Context) (bool, error) { return false, nil }},
		&sensetest.Fake{SensorInfo: sensetest.Info("detect-error"), DetectFn: func(context.Context) (bool, error) { return false, boom }},
		&sensetest.Fake{SensorInfo: sensetest.Info("partial"), CollectFn: func(context.Context) (evidence.Batch, error) { return batchOf("p"), boom }},
		&sensetest.Fake{SensorInfo: sensetest.Info("failed"), CollectFn: func(context.Context) (evidence.Batch, error) { return evidence.Batch{}, boom }},
	)
	res, err := sense.Sensors(context.Background(), reg, sense.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := runs(res)
	for name, want := range map[string]sense.Status{
		"ok": sense.StatusOK, "absent": sense.StatusSkipped, "detect-error": sense.StatusFailed,
		"partial": sense.StatusPartial, "failed": sense.StatusFailed,
	} {
		if got[name].Status != want {
			t.Errorf("%s: status %q, want %q (err=%v)", name, got[name].Status, want, got[name].Err)
		}
	}
	if !errors.Is(got["partial"].Err, boom) || !errors.Is(got["detect-error"].Err, boom) {
		t.Error("sensor errors not preserved")
	}
	total := 0
	for _, b := range res.Batches {
		total += len(b.Observations)
	}
	if total != 2 {
		t.Errorf("observations = %d, want 2 (ok's and partial's): partial results are kept", total)
	}
	if !res.Incomplete() {
		t.Error("Incomplete() = false with failed and partial sensors")
	}
	// A failed sensor is visible in coverage, not silent.
	var failedCov int
	for _, b := range res.Batches {
		for _, c := range b.Coverage {
			if c.Status == evidence.CoverageFailed {
				failedCov++
			}
		}
	}
	if failedCov < 2 {
		t.Errorf("failed coverage records = %d, want at least one per failed sensor", failedCov)
	}
}

func TestSkippedAloneIsNotIncomplete(t *testing.T) {
	reg := registry(t, &sensetest.Fake{SensorInfo: sensetest.Info("absent"), DetectFn: func(context.Context) (bool, error) { return false, nil }})
	res, _ := sense.Sensors(context.Background(), reg, sense.Options{})
	if res.Incomplete() {
		t.Error("a sensor whose ecosystem is absent must not make the run incomplete")
	}
}

func TestBudgetHitIsIncompleteButDenialsAloneAreNot(t *testing.T) {
	mk := func(reason string, denied int) *sensetest.Fake {
		return &sensetest.Fake{SensorInfo: sensetest.Info("walk"), CollectFn: func(context.Context) (evidence.Batch, error) {
			b := batchOf("a")
			b.Coverage = []evidence.Coverage{{Sensor: "walk", Scope: "s", Status: evidence.CoveragePartial, Reason: reason, Denied: denied}}
			return b, nil
		}}
	}
	res, _ := sense.Sensors(context.Background(), registry(t, mk(evidence.UnknownBudget, 0)), sense.Options{})
	if !res.Incomplete() {
		t.Error("a budget hit must make the run incomplete")
	}
	res, _ = sense.Sensors(context.Background(), registry(t, mk(evidence.UnknownPermission, 7)), sense.Options{})
	if res.Incomplete() {
		t.Error("unreadable directories alone must not make the run incomplete (they produce a privilege warning, ADR-0009)")
	}
	if res.Denied() != 7 {
		t.Errorf("Denied() = %d, want 7", res.Denied())
	}
}

func TestOnePanickingSensorDoesNotStopTheRest(t *testing.T) {
	reg := registry(t,
		&sensetest.Fake{SensorInfo: sensetest.Info("a-panics"), CollectFn: func(context.Context) (evidence.Batch, error) { panic("kaboom") }},
		&sensetest.Fake{SensorInfo: sensetest.Info("b-fine"), CollectFn: func(context.Context) (evidence.Batch, error) { return batchOf("x"), nil }},
	)
	res, err := sense.Sensors(context.Background(), reg, sense.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := runs(res)
	if got["a-panics"].Status != sense.StatusFailed || !strings.Contains(got["a-panics"].Err.Error(), "kaboom") {
		t.Errorf("panic not contained: %+v", got["a-panics"])
	}
	if got["b-fine"].Status != sense.StatusOK || got["b-fine"].Observations != 1 {
		t.Errorf("later sensor affected: %+v", got["b-fine"])
	}
}

func TestSensorTimeout(t *testing.T) {
	reg := registry(t, &sensetest.Fake{SensorInfo: sensetest.Info("slow"), CollectFn: func(ctx context.Context) (evidence.Batch, error) {
		<-ctx.Done()
		return evidence.Batch{}, ctx.Err()
	}})
	start := time.Now()
	res, _ := sense.Sensors(context.Background(), reg, sense.Options{Timeout: 20 * time.Millisecond})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("timeout not enforced: took %v", d)
	}
	r := runs(res)["slow"]
	if r.Status != sense.StatusFailed || !errors.Is(r.Err, context.DeadlineExceeded) || !strings.Contains(r.Err.Error(), "timed out") {
		t.Errorf("run = %+v", r)
	}
}

func TestSelection(t *testing.T) {
	reg := registry(t, &sensetest.Fake{SensorInfo: sensetest.Info("apt")}, &sensetest.Fake{SensorInfo: sensetest.Info("jvm")}, &sensetest.Fake{SensorInfo: sensetest.Info("rpm")})
	names := func(o sense.Options) string {
		res, err := sense.Sensors(context.Background(), reg, o)
		if err != nil {
			t.Fatal(err)
		}
		var n []string
		for _, r := range res.Runs {
			n = append(n, r.Name)
		}
		return strings.Join(n, ",")
	}
	for want, o := range map[string]sense.Options{
		"apt,jvm,rpm": {}, "apt,rpm": {Enabled: []string{"rpm", "apt"}}, "apt": {Enabled: []string{"apt", "jvm"}, Disabled: []string{"jvm"}},
	} {
		if got := names(o); got != want {
			t.Errorf("%+v: %s, want %s", o, got, want)
		}
	}
	if got := names(sense.Options{Disabled: []string{"jvm"}}); got != "apt,rpm" {
		t.Errorf("disabled: %s", got)
	}
}

func TestUnknownSensorNameIsAnError(t *testing.T) {
	reg := registry(t, &sensetest.Fake{SensorInfo: sensetest.Info("apt")})
	for _, o := range []sense.Options{{Enabled: []string{"atp"}}, {Disabled: []string{"atp"}}} {
		if _, err := sense.Sensors(context.Background(), reg, o); err == nil || !strings.Contains(err.Error(), `unknown sensor "atp"`) {
			t.Errorf("err = %v", err)
		}
	}
}

func TestFactoryFailureIsRecordedNotFatal(t *testing.T) {
	reg := sense.NewRegistry()
	_ = reg.Register("broken", func(sense.Env) (sense.Sensor, error) { return nil, errors.New("no can do") })
	res, err := sense.Sensors(context.Background(), reg, sense.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r := runs(res)["broken"]; r.Status != sense.StatusFailed {
		t.Errorf("run = %+v", r)
	}
}
