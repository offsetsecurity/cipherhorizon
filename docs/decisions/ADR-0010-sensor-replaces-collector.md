# ADR-0010 — `Sensor` replaces `collector.Collector`; no adapter

- **Status:** Accepted for implementation (Agent 4; resolves Agent 3's open item)
- **Date:** 2026-09-24
- **Related:** ADR-0001

## Context

Agent 3 preferred a new `Sensor` interface *with an adapter* for the existing `collector.Collector`. Agent 4
compared that with the code: one production collector (apt), plus a runner (`scan`), a registry and a test fake.

## Options considered

1. Adapter: keep `Collector`/`CryptoAsset`, wrap it into a `Sensor`.
2. Replace: new `sense` package; delete the old interface, registry, runner and the apt plugin package after porting.
3. Evolve `Collector.Collect` in place to return `Batch`.

## Evidence

- `CryptoAsset` is a finished CycloneDX component with `provides` edges added at collection time. Converting it back
  into observations is lossy (the sensor cannot tell which fields were seen and which inferred).
- The old runner's good behaviour (timeout, panic containment, Ok/Partial/Failed/Skipped) is small and portable.
- `collector.CryptoAsset` is also the input type of `cbom.Build` and the TLS builder, so it must remain.

## Decision

Option 2. New `internal/sense` holds the `Sensor` interface, registry and runner. `internal/plugins/apt` becomes
`internal/sense/debian` (sensor name **`apt`** is kept so existing `plugins.enabled/disabled` configuration keeps
working). `internal/scan`, `internal/plugins/all`, `collector.Collector`, the registry, `PluginInfo`, `SourceType`
and `collectortest` are removed; `collector.CryptoAsset` stays.

## Why

An adapter would preserve the fusion this program exists to remove. With one collector, replacement is cheaper and
clearer than two parallel paths.

## Trade-offs

A larger diff now; risk of missing a dependent. Mitigated by the full test suite, the 44-step browser journey and
the compatibility test on the existing goldens.

## Consequences

- `docs/writing-a-plugin.md` became `docs/writing-a-sensor.md`.
- Configuration keys (`plugins:`) and CLI flags are unchanged; `cipherhorizon plugins` lists sensors.
- Adding a platform or level means adding a sensor (observations only) plus knowledge/derivation rules.
