package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/collector"
	"github.com/example/cbom-scan/internal/collector/collectortest"
	"github.com/example/cbom-scan/internal/scan"
)

func asset(ref string) collector.CryptoAsset {
	return collector.CryptoAsset{Component: cdx.Component{BOMRef: ref, Name: ref, Type: cdx.ComponentTypeLibrary}}
}

func registry(t *testing.T, fakes ...*collectortest.Fake) *collector.Registry {
	t.Helper()
	r := collector.NewRegistry()
	for _, f := range fakes {
		if err := r.Register(f.Info.Name, collectortest.Factory(f)); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func runs(res scan.Result) map[string]scan.PluginRun {
	m := map[string]scan.PluginRun{}
	for _, r := range res.Runs {
		m[r.Name] = r
	}
	return m
}

func TestRunStatuses(t *testing.T) {
	boom := errors.New("disk on fire")
	reg := registry(t,
		&collectortest.Fake{Info: collectortest.Info("ok"),
			CollectFn: func(context.Context) ([]collector.CryptoAsset, error) {
				return []collector.CryptoAsset{asset("a")}, nil
			}},
		&collectortest.Fake{Info: collectortest.Info("absent"),
			DetectFn: func(context.Context) (bool, error) { return false, nil }},
		&collectortest.Fake{Info: collectortest.Info("detect-error"),
			DetectFn: func(context.Context) (bool, error) { return false, boom }},
		&collectortest.Fake{Info: collectortest.Info("partial"),
			CollectFn: func(context.Context) ([]collector.CryptoAsset, error) {
				return []collector.CryptoAsset{asset("p")}, boom
			}},
		&collectortest.Fake{Info: collectortest.Info("failed"),
			CollectFn: func(context.Context) ([]collector.CryptoAsset, error) { return nil, boom }},
	)

	res, err := scan.Run(context.Background(), reg, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := runs(res)
	for name, want := range map[string]scan.Status{
		"ok": scan.StatusOK, "absent": scan.StatusSkipped, "detect-error": scan.StatusFailed,
		"partial": scan.StatusPartial, "failed": scan.StatusFailed,
	} {
		if got[name].Status != want {
			t.Errorf("%s: status %q, want %q (err=%v)", name, got[name].Status, want, got[name].Err)
		}
	}
	if !errors.Is(got["partial"].Err, boom) || !errors.Is(got["detect-error"].Err, boom) {
		t.Error("plugin errors not preserved")
	}
	// Partial results are kept: that is the point of the contract.
	if len(res.Assets) != 2 {
		t.Errorf("assets = %d, want 2 (ok's and partial's)", len(res.Assets))
	}
	if !res.Incomplete() {
		t.Error("Incomplete() = false with failed and partial plugins")
	}
}

func TestSkippedAloneIsNotIncomplete(t *testing.T) {
	reg := registry(t, &collectortest.Fake{Info: collectortest.Info("absent"),
		DetectFn: func(context.Context) (bool, error) { return false, nil }})
	res, _ := scan.Run(context.Background(), reg, scan.Options{})
	if res.Incomplete() {
		t.Error("a plugin whose ecosystem is absent must not make the scan incomplete")
	}
}

func TestOnePanickingPluginDoesNotStopTheRest(t *testing.T) {
	reg := registry(t,
		&collectortest.Fake{Info: collectortest.Info("a-panics"),
			CollectFn: func(context.Context) ([]collector.CryptoAsset, error) { panic("kaboom") }},
		&collectortest.Fake{Info: collectortest.Info("b-fine"),
			CollectFn: func(context.Context) ([]collector.CryptoAsset, error) {
				return []collector.CryptoAsset{asset("x")}, nil
			}},
	)
	res, err := scan.Run(context.Background(), reg, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := runs(res)
	if got["a-panics"].Status != scan.StatusFailed || !strings.Contains(got["a-panics"].Err.Error(), "kaboom") {
		t.Errorf("panic not contained: %+v", got["a-panics"])
	}
	if got["b-fine"].Status != scan.StatusOK || len(res.Assets) != 1 {
		t.Errorf("later plugin affected: %+v", got["b-fine"])
	}
}

func TestPluginTimeout(t *testing.T) {
	reg := registry(t, &collectortest.Fake{Info: collectortest.Info("slow"),
		CollectFn: func(ctx context.Context) ([]collector.CryptoAsset, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	start := time.Now()
	res, _ := scan.Run(context.Background(), reg, scan.Options{Timeout: 20 * time.Millisecond})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("timeout not enforced: took %v", d)
	}
	r := runs(res)["slow"]
	if r.Status != scan.StatusFailed || !errors.Is(r.Err, context.DeadlineExceeded) || !strings.Contains(r.Err.Error(), "timed out") {
		t.Errorf("run = %+v", r)
	}
}

func TestSelection(t *testing.T) {
	reg := registry(t,
		&collectortest.Fake{Info: collectortest.Info("apt")},
		&collectortest.Fake{Info: collectortest.Info("jvm")},
		&collectortest.Fake{Info: collectortest.Info("rpm")},
	)
	names := func(o scan.Options) string {
		res, err := scan.Run(context.Background(), reg, o)
		if err != nil {
			t.Fatal(err)
		}
		var n []string
		for _, r := range res.Runs {
			n = append(n, r.Name)
		}
		return strings.Join(n, ",")
	}
	if got := names(scan.Options{}); got != "apt,jvm,rpm" {
		t.Errorf("all: %s", got)
	}
	if got := names(scan.Options{Enabled: []string{"rpm", "apt"}}); got != "apt,rpm" {
		t.Errorf("enabled: %s", got)
	}
	if got := names(scan.Options{Disabled: []string{"jvm"}}); got != "apt,rpm" {
		t.Errorf("disabled: %s", got)
	}
	if got := names(scan.Options{Enabled: []string{"apt", "jvm"}, Disabled: []string{"jvm"}}); got != "apt" {
		t.Errorf("enabled+disabled: %s", got)
	}
}

func TestUnknownPluginNameIsAnError(t *testing.T) {
	reg := registry(t, &collectortest.Fake{Info: collectortest.Info("apt")})
	for _, o := range []scan.Options{{Enabled: []string{"atp"}}, {Disabled: []string{"atp"}}} {
		if _, err := scan.Run(context.Background(), reg, o); err == nil || !strings.Contains(err.Error(), `unknown plugin "atp"`) {
			t.Errorf("err = %v", err)
		}
	}
}

func TestFactoryFailureIsRecordedNotFatal(t *testing.T) {
	reg := collector.NewRegistry()
	_ = reg.Register("broken", func(collector.Host) (collector.Collector, error) { return nil, errors.New("no can do") })
	res, err := scan.Run(context.Background(), reg, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r := runs(res)["broken"]; r.Status != scan.StatusFailed {
		t.Errorf("run = %+v", r)
	}
}
