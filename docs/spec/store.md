# Content-addressed store

Status: additive, AIM-PROP-2026-10 C-4.1/C-4.2.

`Store` is a local directory of canonical images keyed by their Blake3 hash.

```
Store::open(root)
Store::put(image) -> [u8;32]
Store::put_module(&module)
Store::get(&hash) -> Vec<u8>
Store::contains(&hash)
Store::len()
```

- `put` validates the image and derives the path from the hash only.
- A second put of identical bytes deduplicates; an object with the same hash but
  different bytes is refused, never overwritten.
- Writes use a temporary file in the store directory and an atomic rename.
- `get` revalidates and recomputes the hash before returning bytes.
- No secret payload is logged; errors carry `infinity/store` only.

A detached signature envelope (`SignedImage`, feature `signatures`) wraps the
same image. The signature is sidecar evidence; the content hash remains the
identity. See ADR 0013 and `docs/spec/schema.md`.
