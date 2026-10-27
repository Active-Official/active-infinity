# Contributor Code of Conduct

## Our commitment

We are building infrastructure that other people will run, store data with and
secure their agents with. That raises the bar: contributors are expected to be
precise about claims, generous with review, and honest about limits.

## Expected behaviour

- **Evidence over assertion.** A change claims what the tests show. "Works on my
  machine" is a starting point, not a result.
- **Respect for the invariants.** Secrets, budgets, determinism, units and
  capabilities are not negotiable for convenience. If an invariant blocks a
  feature, change the design, not the invariant.
- **Review in good faith.** Critique code, not people. Ask before assuming.
- **Small, explainable changes.** A large change needs an ADR and a test that
  would fail without it.

## Unacceptable behaviour

Harassment, discrimination, personal attacks, publishing private information, or
knowingly shipping code that weakens a security guarantee (silent secret logging,
budget bypass, non-canonical encodings) are grounds for removal from the project.

## Scope

This applies in the repository, in issues and pull requests, and in any space
where someone is representing the project.

## Enforcement

Report concerns to the maintainers listed in `SECURITY.md`. Reports are handled
privately. Maintainers may warn, remove a contribution, or ban a contributor;
the response is proportional and documented internally.

## Attribution

Adapted for this project from the spirit of the Contributor Covenant v2.1.
