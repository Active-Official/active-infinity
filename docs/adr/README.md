# Architecture Decision Records

Every structural decision in Active Infinity is recorded here. An ADR is
immutable once accepted: a later ADR supersedes it and says so.

| ADR | Title |
|-----|-------|
| [0001](0001-purpose.md) | Purpose of Active Infinity |
| [0002](0002-active-core-relationship.md) | Relationship to `active-core` and wire-format independence |
| [0003](0003-versioning.md) | Versioning, MSRV and the crates.io name reservation |
| [0004](0004-zero-copy.md) | Zero-copy views without `unsafe` |
| [0005](0005-canonical-form.md) | Canonical form and content addressing |
| [0006](0006-secrets.md) | Structural secrets, anti-oracle equality and locator promotion |
| [0007](0007-streaming.md) | Streaming as canonical section transport plus semantic deltas |
| [0008](0008-dependency-policy.md) | Dependency policy and supply chain |
| [0009](0009-protobuf-projection.md) | Protobuf interop projection |
| [0010](0010-no-public-secret-accessor.md) | No public secret accessor |
| [0011](0011-bakeoff-methodology.md) | Public bakeoff methodology and CI regression policy |
| [0012](0012-schema-class.md) | Schema-class companion modules and the hash boundary |
