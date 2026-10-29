//! Canonical codec facade for `active-infinity`.
//!
//! Re-exports the crate root: encode, decode, validate, content hashing,
//! modules, inodes and the wire types.

pub use active_infinity::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_facade_round_trips_a_real_image() {
        let module = InfinityModule::new();
        let image = encode(&module).expect("encode");
        validate(&image).expect("validate");
        let decoded = decode(&image).expect("decode");
        assert_eq!(decoded.node_count(), module.node_count());
        assert_eq!(content_hash(&image).expect("hash").len(), 32);
    }
}
