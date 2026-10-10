# Legacy goldens (frozen)

These are the host CBOMs `cipherhorizon run` produced for the Debian 13 and Ubuntu 24.04
fixtures **before** the host collector became an evidence pipeline (ADR-0001, ADR-0010).
They are **frozen**: never regenerate them.

`TestLegacyOutputIsPreserved` (internal/app) asserts that the current output has exactly the
same components, the same `provides`/`dependsOn` edges, and every property the old output had,
with the same values. The current output may only *add* properties (claim, method, coverage...).
If that test fails, the refactor changed what a package inventory says, which needs a decision,
not a golden update.
