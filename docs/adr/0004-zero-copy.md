# ADR-0004 — Zero-copy views without `unsafe`

**Status:** accepted (2026-10-27). Supersedes the scaffold's blanket conflict:
`#![forbid(unsafe_code)]` plus `rkyv` was never going to coexist.

## Context

The proposal requires zero-copy views (C-3.2, C-3.3) and the scaffold declared
`#![forbid(unsafe_code)]`. Casting a `&[u8]` to `&[Record]` needs `unsafe` for
alignment and soundness reasons, so one of the two had to give.

At the same time the format has to be safe against hostile input on every
platform, and a validator written against `unsafe` casts is exactly where
soundness bugs hide.

## Decision

Keep `#![forbid(unsafe_code)]` and define the layout so zero-copy is achievable
without casting:

1. Every fixed record is read with `u32::from_le_bytes` / `u64::from_le_bytes`
   on slices. That is a memcpy of at most eight bytes, has no alignment
   requirement, and cannot be unsound.
2. Variable-length payloads — strings, blob payloads, secrets — are returned as
   `&'a str` / `&'a [u8]` **borrowed directly from the caller's buffer**. No
   copy, no intermediate allocation.
3. A view can only be constructed from bytes that passed `validate`, and the
   view holds a shared borrow of the buffer, so the bytes cannot change while a
   view exists.
4. Node records are 32 bytes and contain no pointers: the "zero parse" property
   is preserved for the fields that matter (kind, aux, children range).

## Consequences

- Strings and blobs are true zero-copy; record access costs a few `from_le_bytes`
  reads instead of a pointer dereference. Benchmarks in
  `docs/spec/performance.md` show the difference is noise for real modules.
- The crate stays sound by construction, and `cargo miri` has nothing to find.
- A future mmap-backed segment can hand in its slice and get the same views
  without new APIs.
