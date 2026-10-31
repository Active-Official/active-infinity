# Content-addressed store

Status: additive, AIM-PROP-2026-10 C-4.1/C-4.2; hardened in the AMAX marathon
(I-08).

`Store` is a local directory of canonical images keyed by their Blake3 hash.

```
Store::open(root)
Store::put(image) -> [u8;32]
Store::put_module(&module)
Store::get(&hash) -> Vec<u8>
Store::contains(&hash)
Store::len() / Store::try_len()
```

- `put` proves the canonical form and derives the path from the hash only. A
  second put of identical bytes deduplicates; an object with the same key but
  different bytes is refused, never overwritten.
- Writes go to a scratch file in the store directory, which is opened with
  `O_CREAT|O_EXCL` under a per-store slot counter, then committed by a hard
  link. The link is atomic and fails when the object already exists, on Unix and
  on Windows alike; a race is resolved by comparing bytes, so identical content
  is a no-op and different content is an error. Filesystems without hard links
  fall back to a rename guarded by an existence check.
- `get` reads under the default codec ceiling *before* allocating, proves the
  canonical form (not just structural validity), and checks the result against
  the requested key. The same bound applies to a signature envelope.
- Only regular files are objects. A symbolic link at an object or envelope path
  is refused, and `Store::open` refuses a root that is a symbolic link or not a
  directory.
- One object has one envelope: re-storing the identical `SignedImage` is a
  no-op; a second envelope for the same image (another signer, another
  signature) is refused rather than replacing evidence a reader may have pinned.
- On Unix the store directory is created `0700` and objects are written `0600`.
  Secrets inside an image are in the clear at rest: anyone who can read the
  directory can read them. A shared store is a shared secret domain.
- No secret payload is logged; errors carry `infinity/store` only.
- A lookup is an existence oracle. `get` reports "object not found" and "object
  does not match its key" distinctly for local debugging, so a service that sits
  in front of a store must map every `infinity/store` failure to one response and
  must not forward `Display`. `contains` is a snapshot and does not reserve the
  object for a later `get`.
- `len` counts regular files named `<64 lowercase hex>.ainf`; `try_len` fails
  when the directory cannot be read, while `len` reports zero.

A detached signature envelope (`SignedImage`, feature `signatures`) wraps the
same image. The signature is sidecar evidence; the content hash remains the
identity. See ADR 0013 and `docs/spec/schema.md`.
