// Package sensetest provides a scriptable fake sensor for testing code that
// drives sensors (the registry, the runner, the pipeline) without a real host.
package sensetest

import (
	"context"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/sense"
)

// Fake is a sensor whose behaviour is set by its fields. Nil funcs behave as
// "present, nothing found".
type Fake struct {
	SensorInfo sense.Info
	DetectFn   func(context.Context) (bool, error)
	CollectFn  func(context.Context) (evidence.Batch, error)
}

var _ sense.Sensor = (*Fake)(nil)

// Info implements sense.Sensor.
func (f *Fake) Info() sense.Info { return f.SensorInfo }

// Detect implements sense.Sensor.
func (f *Fake) Detect(ctx context.Context) (bool, error) {
	if f.DetectFn == nil {
		return true, nil
	}
	return f.DetectFn(ctx)
}

// Collect implements sense.Sensor.
func (f *Fake) Collect(ctx context.Context) (evidence.Batch, error) {
	if f.CollectFn == nil {
		return evidence.Batch{}, nil
	}
	return f.CollectFn(ctx)
}

// Factory returns a factory that always yields f.
func Factory(f *Fake) sense.Factory {
	return func(sense.Env) (sense.Sensor, error) { return f, nil }
}

// Info returns a valid sense.Info with the given name, for terse tests.
func Info(name string) sense.Info {
	return sense.Info{Name: name, Version: "0.0.0-test", Methods: []string{evidence.MethodDpkgStatus}}
}

// Observation returns a valid observed `present` observation for tests.
func Observation(key string) evidence.Observation {
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindPackage, Key: key, Name: key},
		Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: evidence.MethodDpkgStatus, Source: evidence.Source{Kind: "database", Location: "x"}, Privilege: "user",
	}
	evidence.Finish(&o)
	return o
}
