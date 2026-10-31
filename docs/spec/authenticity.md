# Authenticity: hash, proof, signature

Active Infinity has three distinct layers, and they answer different questions.
Confusing them is the most common way a consumer ends up trusting the wrong
thing.

| Layer | Question it answers | Where it lives | What it does not prove |
|---|---|---|---|
| **Content hash** (Blake3 over the canonical payload) | "Are these the bytes that hash to this address?" | header of every image; `content_hash` | who wrote them, or that the bytes are canonical |
| **Proof sidecar** (`active-infinity/proof/1`) | "Is this image canonical, and what are its counts?" | detached JSON file (`Proof`) | authorship; anyone can recompute it |
| **Signature envelope** (`AISG`) | "Did the holder of this key sign exactly these bytes?" | detached envelope (`SignedImage`) | that the key is trusted; that is the verifier's policy |

## Rules

1. **The image is the system of record.** A projection (JSON, Protobuf) is a
   view; editing it changes nothing about the address. See `projection.md` §0.
2. **A hash proves integrity, not authorship.** A party that can rewrite the
   file can rewrite the hash. Authenticity needs a signature over the bytes.
3. **A proof proves canonical form.** `Proof::verify` runs
   `validate_canonical`, so a verified image re-encodes to itself. A sidecar that
   says `canonical: false` is refused, and the sidecar is capped at 16 KiB.
4. **A signature proves key possession.** `SignedImage::verify` validates the
   image and checks Ed25519 over `DOMAIN || image`. Pin the public key
   (`Store::get_verified_with_key`, `store get --verify --key`) to turn "someone
   signed this" into "the signer I chose signed this".
5. **Order of checks.** Image validity first, then the signature, then the
   trust decision. A corrupted image is refused by validation before a
   signature is even considered (`put_signed_refuses_a_corrupted_image`).

## Using it

```bash
# Sign on the way into the store; the envelope is kept next to the object.
active-infinity-cli store put image.ainf --root ./store --sign $SEED_HEX

# Require a verified envelope; optionally pin the signer's public key.
active-infinity-cli store get $HASH --root ./store --verify --key $PUBLIC_HEX

# Inspect what the store holds for an object.
active-infinity-cli store signature $HASH --root ./store
```

```rust
use active_infinity::{SignedImage, Store};

let signed = SignedImage::sign_with_seed(image, &seed)?;   // AISG envelope
let hash = store.put_signed(&signed)?;                     // verifies, then stores
let bytes = store.get_verified_with_key(&hash, &public_key)?;
```

`Store::get` stays integrity-only (it revalidates and rechecks the hash);
`Store::get_verified` is the authenticity path. Choosing the wrong one is a
policy decision, so the names say which is which.

## Trust and key management

- The signature envelope binds bytes and key with a domain separator; it does
  not carry a certificate chain.
- A deployment distributes public keys out of band (release notes, a pinned
  allow-list, or its own CA), exactly as it distributes any other trust root.
- The CLI never prints a private key. `--sign` takes a 32-byte seed as hex; keep
  it in the environment or a secret manager, never in a repository.
- Rotating a key means signing new objects with the new key and keeping the old
  public key to verify history.

## What is still a residual

- There is no transparency log and no timestamp authority: a signature proves a
  key signed these bytes, not when. Record the timestamp in your release process.
- Store envelopes are detached files; a store backend that replicates objects
  must replicate the `.sig` files too.
