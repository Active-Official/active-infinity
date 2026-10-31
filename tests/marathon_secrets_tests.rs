//! Marathon section I-03, secret-path findings: locator promotion and the
//! redaction marker.
//!
//! The invariant under test is the one in `docs/spec/security.md` (I-3): secret
//! material never appears in the public projections of an image. A secret's
//! bytes live in the secrets section by design; the *strings* section is the part
//! projections read.

use active_infinity::layout::{Header, Section};
use active_infinity::{
    encode, InfinityModule, Inode, ProvEntry, ProvValue, Provenance, SecretBytes,
};

/// The bytes of the public string heap (table entries excluded).
fn public_string_heap(image: &[u8]) -> Vec<u8> {
    let header = Header::parse(image).expect("header");
    let span = header.span(Section::Strings);
    if span.count == 0 {
        return Vec::new();
    }
    let table = span.offset as usize;
    let count = span.count as usize;
    let heap_len = active_infinity::layout::read_u32(image, table + count * 4).expect("heap len");
    let heap = table + (count + 1) * 4;
    image[heap..heap + heap_len as usize].to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

const FALLBACK: &str = "fallback-canary-9137";

/// `secret(env.TOKEN ?: "<fallback>")`: the fallback literal is the value the
/// secret takes when the variable is unset, so it is secret material.
fn module_with_env_default() -> InfinityModule {
    let mut module = InfinityModule::new();
    let fallback = module.push(Inode::Str(FALLBACK.to_string()));
    let env = module.push(Inode::Env {
        name: "ACTIVE_TOKEN".to_string(),
        default: Some(fallback),
    });
    let secret = module.push(Inode::SecretRef { locator: env });
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn an_env_default_under_a_secret_stays_out_of_the_public_heap() {
    // The promotion rule only looked at a node's direct dependents, so the
    // fallback string under the (non-secret) Env node stayed public while the
    // secret it feeds was hidden.
    let image = encode(&module_with_env_default()).expect("encode");
    let public = public_string_heap(&image);
    assert!(
        !contains(&public, FALLBACK.as_bytes()),
        "the fallback literal is in the public string heap: {:?}",
        String::from_utf8_lossy(&public)
    );
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the image is canonical");
}

#[test]
fn an_interpolated_default_under_a_secret_stays_out_of_the_public_heap() {
    // The same shape one level deeper: the fallback is reached through an
    // interpolation, so the exposure rule has to stop descending at the secret,
    // not at its direct child.
    let mut module = InfinityModule::new();
    let literal = module.push(Inode::Str(FALLBACK.to_string()));
    let expression = module.push(Inode::Interpolate {
        parts: vec![
            active_infinity::InterpPart::Literal(String::new()),
            active_infinity::InterpPart::Expr(literal),
        ],
    });
    let env = module.push(Inode::Env {
        name: "ACTIVE_TOKEN".to_string(),
        default: Some(expression),
    });
    let secret = module.push(Inode::SecretRef { locator: env });
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));

    let image = encode(&module).expect("encode");
    let public = public_string_heap(&image);
    assert!(
        !contains(&public, FALLBACK.as_bytes()),
        "the interpolated fallback is in the public string heap"
    );
}

#[test]
fn a_secret_inside_the_redaction_marker_is_refused_rather_than_published() {
    // `SEC` is a substring of `***SECRET***`. Redacting a producer that contains
    // it would publish the secret as part of the marker, so the encode refuses.
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("SEC")));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("built by the SEC team".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: vec![ProvEntry {
            key: "run".to_string(),
            value: ProvValue::Text("nightly".to_string()),
        }],
    }));
    let error = encode(&module).expect_err("the marker cannot carry a secret");
    assert_eq!(error.code(), "infinity/encode", "{error:?}");
}

#[test]
fn a_marker_colliding_secret_without_redacted_text_still_encodes() {
    // The refusal is about publishing the marker, not about the secret existing:
    // a module with no text to redact encodes normally.
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("SEC")));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("no text needs redaction");
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the image is canonical");
}

#[test]
fn ordinary_redaction_still_works() {
    // The common case: a text that contains a secret (not inside the marker) is
    // replaced by the marker and the image validates.
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from("hunter2-canary")));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("built with hunter2-canary".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: Vec::new(),
    }));
    let image = encode(&module).expect("encode");
    let public = public_string_heap(&image);
    assert!(
        !contains(&public, b"hunter2-canary"),
        "the secret is in the public string heap"
    );
    active_infinity::validate_canonical(&image, active_infinity::Limits::default())
        .expect("the image is canonical");
}
