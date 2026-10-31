//! C-3.4 zero-copy audit: a string view borrows the validated image rather
//! than materialising a decoded module.

use active_infinity::view::InfinityView;
use active_infinity::{encode, InfinityModule, Inode, Limits};

#[test]
fn string_views_borrow_the_validated_buffer() {
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("zero-copy-borrow".into()));
    module.set_root(Some(text));
    let image = encode(&module).expect("encode");

    let view = InfinityView::new(&image, Limits::default()).expect("view");
    let borrowed = view.string(0).expect("string view");
    let start = image.as_ptr() as usize;
    let end = start + image.len();
    let ptr = borrowed.as_ptr() as usize;
    assert!(
        ptr >= start && ptr < end,
        "string view points outside the image"
    );
    assert_eq!(borrowed, "zero-copy-borrow");
    assert!(view.node_count() > 0);
}
