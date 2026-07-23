use super::*;

#[test]
fn attributes_skip_padding_and_mask_flags() {
    let mut bytes = Vec::new();
    push_attribute(&mut bytes, 0x8003, &[1, 2, 3]);
    push_u32(&mut bytes, 4, 42);
    let parsed = attributes(&bytes);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].kind, 3);
    assert_eq!(parsed[0].value, [1, 2, 3]);
    assert_eq!(read_u32(parsed[1].value), Some(42));
}

#[test]
fn malformed_attribute_stops_without_panicking() {
    assert!(attributes(&[20, 0, 1, 0, 1]).is_empty());
    assert!(attributes(&[2, 0, 1, 0]).is_empty());
}
