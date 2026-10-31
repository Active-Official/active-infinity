# ADR 0011 — Bakeoff methodology

Status: accepted for AIM-PROP-2026-10 C-2.3.

## Decision

Public bakeoffs are reproducible comparisons, not leaderboard claims.

- **Hardware class:** record CPU model, physical core count, RAM, OS and kernel,
  filesystem, compiler version and CPU governor. No number without this row.
- **Workloads:** identical logical module shape across competitors; each adapter
  gets the same node count, field names, value widths and secret positions.
- **Warmup:** discard at least one full iteration set; report the configured
  warmup and measurement time.
- **Iterations:** Criterion defaults (100 samples, 3 s target) unless a workload
  needs a longer window; record any override.
- **Statistics:** publish p50 and p99 from the raw samples; never a single best
  run. State confidence interval and sample count.
- **Fairness:** encode, validate, decode and hash are separate rows. A combined
  "parse" row is not comparable and is not published.
- **No fabrication:** if an adapter cannot be built, publish the gap, not a
  projected number.
- **Privacy:** benchmark payloads contain no production secrets; the secret
  workload uses the fixed repository canary.

## CI gate

The internal matrix runs the shipped workloads and compares against the stored
baseline with a tolerance per metric. A regression beyond tolerance fails the
job unless the PR carries an ADR and a new baseline. Competitor adapters are
optional in CI; the internal path is mandatory.

## Consequences

Numbers are slower to produce but defensible. Hardware-specific results cannot
be generalized; the performance page states the class and links the raw run.
