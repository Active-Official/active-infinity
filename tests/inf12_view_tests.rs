//! INF-12 fail-before / pass-after probe: `InfinityView::new` over a
//! non-canonical image must not return unredacted provenance.
//!
//! The finding (round 1, `AUDIT-REPORT.md` INF-12, verified CONFIRMED by W4
//! as `w4_inf12_view_provenance_secret`): canonical images have redacted
//! provenance (`prepare` redacts it against the module's secrets), but
//! `InfinityView::new` accepted *non-canonical* images, and a non-canonical
//! image's provenance was never redacted — it can contain a copy of a secret
//! literal in provenance text, which `provenance_entries()` then returned
//! verbatim.
//!
//! The landscape has moved since W4: INF-02 (`1fb501c`) made canonicality
//! the crate-wide default — `DecodeOpts::default().verify_canonical` is now
//! `true`, so default `decode` already refuses the patched image below —
//! and deliberately left `InfinityView::new` lenient ("view-specific
//! hardening belongs to INF-12"). At HEAD `25789e4` the view constructor is
//! the sole default-path holdout: `src/view.rs` hard-codes
//! `verify_canonical: false`. The fix (audit recommendation (a)) makes
//! `InfinityView::new` prove canonicality, so a non-canonical image is
//! refused with `infinity/not-canonical` instead of yielding a view whose
//! provenance entries leak the secret. The explicit lenient path
//! (`InfinityView::with_opts` with `verify_canonical: false`) stays
//! available for trusted/migration callers — the same deliberate,
//! auditable opt-out INF-02 documents for `decode` — and is pinned here
//! so the fix does not silently remove it.
//!
//! The surgery is W4's, unchanged: a 12-char `*`-prefixed secret
//! (`*s3cr3t-val*`, exactly `len("***SECRET***")`) so the restored copy
//! still sorts in the marker's heap position (the string heap must stay
//! strictly sorted, or validation rejects the image for that reason
//! instead), with the content hash repaired afterwards.

use active_infinity::interop::SECRET_MARKER;
use active_infinity::layout::{DecodeOpts, Header, Section};
use active_infinity::{
    decode, decode_with, encode, hash_image, InfinityModule, InfinityView, Inode, Limits,
    ProvEntry, ProvValue, Provenance, SecretBytes,
};

/// The secret literal, 12 chars == `len("***SECRET***")`, `*`-prefixed so
/// the surgically restored copy still sorts in the marker's heap position.
const SECRET: &str = "*s3cr3t-val*";

/// Build the W4 pair: the canonical image of a module whose provenance text
/// contains the secret literal, and the hand-patched non-canonical image in
/// which the secret is restored in the string heap where the redaction
/// marker sits (hash repaired, so only canonicality — not the hash — is
/// what the patched image fails).
fn secret_provenance_images() -> (Vec<u8>, Vec<u8>) {
    assert_eq!(SECRET.len(), SECRET_MARKER.len());
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new(SECRET.as_bytes().to_vec())));
    let root = module.push(Inode::Table {
        fields: vec![("s".into(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("tester".into()),
        entries: vec![ProvEntry {
            key: "note".into(),
            value: ProvValue::Text(SECRET.into()),
        }],
        ..Default::default()
    }));
    let image = encode(&module).expect("encode the secret-provenance module");

    // Surgery: restore the secret text in the string heap where the marker
    // sits (provenance text is stored by heap index, not inline).
    let header = Header::parse(&image).expect("parse the canonical header");
    let span = header.span(Section::Strings);
    let offset = span.offset as usize;
    let mut patched = image.clone();
    let region = &mut patched[offset..];
    let position = region
        .windows(SECRET.len())
        .position(|window| window == SECRET_MARKER.as_bytes())
        .expect("the redaction marker must sit in the string heap");
    region[position..position + SECRET.len()].copy_from_slice(SECRET.as_bytes());
    let hash = hash_image(&patched).expect("hash the patched image");
    patched[16..48].copy_from_slice(&hash);
    (image, patched)
}

/// Does any provenance entry carry the secret literal verbatim?
fn entries_leak_secret(entries: &[(String, ProvEntry)]) -> bool {
    entries.iter().any(|(_, entry)| match &entry.value {
        ProvValue::Text(text) => text.contains(SECRET),
        _ => false,
    })
}

#[test]
fn inf12_canonical_encode_redacts_provenance() {
    let (image, _) = secret_provenance_images();
    // Premise pin (W4): the secret legitimately lives in the SECRET heap —
    // secrets are stored, just never in a public heap. What must be
    // redacted is the copy in provenance, so the public string heap must
    // not contain the literal.
    let view = InfinityView::new(&image, Limits::default()).expect("view over canonical image");
    let mut public_leak = false;
    for i in 0..view.meta().strings {
        if view.string(i).expect("string id") == SECRET {
            public_leak = true;
        }
    }
    println!("INF-12 secret literal in public string heap: {public_leak}");
    assert!(
        !public_leak,
        "canonical encode must not leave the secret in the public heap"
    );
    // And the view over the canonical image reports the marker, not the
    // secret, through the entries accessor.
    let entries = view.provenance_entries().expect("provenance entries");
    assert!(
        !entries_leak_secret(&entries),
        "canonical view must not expose the secret through provenance_entries"
    );
    assert!(
        entries.iter().any(|(_, entry)| match &entry.value {
            ProvValue::Text(text) => text.contains(SECRET_MARKER),
            _ => false,
        }),
        "canonical view must report the redaction marker, got {entries:?}"
    );
    println!("INF-12 canonical view provenance entries carry the marker, not the secret");
}

#[test]
fn inf12_view_new_refuses_secret_provenance_image() {
    let (_, patched) = secret_provenance_images();
    // Premise: the surgery produced a *valid but non-canonical* image, not
    // a corrupt one — the lenient decode still succeeds.
    let lenient = DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    };
    let module = decode_with(&patched, lenient).expect("lenient decode of the patched image");
    assert_eq!(
        module.nodes().len(),
        2,
        "the patched image still decodes to 2 nodes"
    );
    // Premise (post-INF-02): the default decode already refuses it — the
    // view was the remaining hole, not decode.
    let default_error = decode(&patched).expect_err("default decode must refuse the patched image");
    assert_eq!(default_error.code(), "infinity/not-canonical");
    println!("INF-12 default decode of secret-provenance image: Err(infinity/not-canonical)");
    let paranoid_error =
        decode_with(&patched, DecodeOpts::paranoid()).expect_err("paranoid decode must refuse it");
    assert_eq!(paranoid_error.code(), "infinity/not-canonical");
    println!("INF-12 paranoid decode: Err(infinity/not-canonical)");

    // The fix: `InfinityView::new` refuses the non-canonical image instead
    // of yielding a view whose provenance entries leak the secret.
    let error = InfinityView::new(&patched, Limits::default())
        .expect_err("InfinityView::new must refuse a non-canonical image");
    assert_eq!(error.code(), "infinity/not-canonical");
    println!("INF-12 InfinityView::new over secret-provenance image: Err(infinity/not-canonical)");
}

#[test]
fn inf12_lenient_view_opt_out_still_reads_raw_provenance() {
    let (_, patched) = secret_provenance_images();
    // Pin: the explicit lenient path is unchanged by the fix. A caller that
    // deliberately opts out of the canonical proof (`with_opts` with
    // `verify_canonical: false`) still gets a view, and that view still
    // reports the stored entries verbatim — the caller owns redaction there
    // and must use `interop::provenance_json` for output that leaves the
    // process. This is the deliberate, auditable opt-out INF-02 documents
    // for `decode`, not a second default.
    let lenient = DecodeOpts {
        verify_canonical: false,
        ..DecodeOpts::default()
    };
    let view = InfinityView::with_opts(&patched, lenient).expect("lenient view");
    let entries = view.provenance_entries().expect("provenance entries");
    assert!(
        entries_leak_secret(&entries),
        "the explicit lenient view still exposes the stored secret verbatim"
    );
    println!("INF-12 lenient with_opts view provenance_entries() returns secret verbatim: true");
}
