# ADR 0013 — Detached signature envelope and store trust

Status: accepted for AIM-PROP-2026-10 C-4.2.

## Decision

A store object may carry a detached Ed25519 envelope (`SignedImage`, feature
`signatures`). The envelope is:

```
AISG | version=1 | public_key[32] | signature[64] | image bytes
```

The signature covers `b"active-infinity/signed-image/v1\0" || image`. The image
is validated before signing and before verification. Verification fails closed
on a bad key, bad signature, wrong version, truncation or invalid image.

The content hash is always the Blake3 hash of the image, not of the envelope or
the signature. Signatures are supply-chain evidence; they do not replace the
hash and do not change module identity.

## Trust model

- A local store path is derived only from the hash; callers cannot choose a
  filename.
- `get` revalidates and recomputes the hash before returning bytes.
- A signature proves possession of a private key over these bytes. It does not
  prove that the key is trusted; deployments pin public keys out of band.
- Revocation of a signing key is a deployment policy, not a wire operation.

## Consequences

Envelopes are additive and optional. An unsigned store remains valid. A future
signature transparency/sigstore adapter can wrap the same `SignedImage` bytes.
