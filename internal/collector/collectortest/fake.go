// Package collectortest provides a scriptable fake collector for testing code
// that drives collectors (the registry, the runner) without a real ecosystem.
package collectortest

import (
	"context"

	"github.com/example/cipherhorizon/internal/collector"
)

// Fake is a collector whose behaviour is set by its fields. Nil funcs behave as
// "present, no findings".
type Fake struct {
	Info      collector.PluginInfo
	DetectFn  func(context.Context) (bool, error)
	CollectFn func(context.Context) ([]collector.CryptoAsset, error)
}

var _ collector.Collector = (*Fake)(nil)

// Metadata implements collector.Collector.
func (f *Fake) Metadata() collector.PluginInfo { return f.Info }

// Detect implements collector.Collector.
func (f *Fake) Detect(ctx context.Context) (bool, error) {
	if f.DetectFn == nil {
		return true, nil
	}
	return f.DetectFn(ctx)
}

// Collect implements collector.Collector.
func (f *Fake) Collect(ctx context.Context) ([]collector.CryptoAsset, error) {
	if f.CollectFn == nil {
		return nil, nil
	}
	return f.CollectFn(ctx)
}

// Factory returns a factory that always yields f.
func Factory(f *Fake) collector.Factory {
	return func(collector.Host) (collector.Collector, error) { return f, nil }
}

// Info returns a valid PluginInfo with the given name, for terse tests.
func Info(name string) collector.PluginInfo {
	return collector.PluginInfo{Name: name, Version: "0.0.0-test", SourceType: collector.SourceOSPackage}
}
