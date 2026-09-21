package collector_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/example/cbom-scan/internal/collector"
	"github.com/example/cbom-scan/internal/collector/collectortest"
)

func TestRegisterAndNew(t *testing.T) {
	r := collector.NewRegistry()
	fake := &collectortest.Fake{Info: collectortest.Info("apt")}
	if err := r.Register("apt", collectortest.Factory(fake)); err != nil {
		t.Fatal(err)
	}

	got, err := r.New("apt", collector.Host{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Metadata().Name != "apt" {
		t.Errorf("Metadata().Name = %q", got.Metadata().Name)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	r := collector.NewRegistry()
	f := collectortest.Factory(&collectortest.Fake{Info: collectortest.Info("apt")})

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
		t.Errorf("duplicate registration: err = %v, want 'registered twice'", err)
	}
}

func TestNamesSorted(t *testing.T) {
	r := collector.NewRegistry()
	for _, n := range []string{"rpm", "apt", "jvm"} {
		if err := r.Register(n, collectortest.Factory(&collectortest.Fake{Info: collectortest.Info(n)})); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := r.Names(), []string{"apt", "jvm", "rpm"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
}

func TestNewErrors(t *testing.T) {
	r := collector.NewRegistry()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Registered under one name but reports another: the classic copy-paste bug.
	must(r.Register("apt", collectortest.Factory(&collectortest.Fake{Info: collectortest.Info("rpm")})))
	// Reports invalid metadata.
	must(r.Register("broken", collectortest.Factory(&collectortest.Fake{Info: collector.PluginInfo{Name: "broken"}})))
	// Factory returns nil.
	must(r.Register("nilc", func(collector.Host) (collector.Collector, error) { return nil, nil }))

	for _, tc := range []struct{ name, want string }{
		{"apt", `reports name "rpm"`},
		{"broken", "version is empty"},
		{"nilc", "returned nil"},
		{"missing", "unknown plugin"},
	} {
		_, err := r.New(tc.name, collector.Host{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("New(%q) err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
}

func TestDefaultRegisterPanicsOnDuplicate(t *testing.T) {
	const name = "collector-test-dup"
	f := collectortest.Factory(&collectortest.Fake{Info: collectortest.Info(name)})
	collector.Register(name, f)

	defer func() {
		if recover() == nil {
			t.Error("second Register did not panic")
		}
	}()
	collector.Register(name, f)
}
