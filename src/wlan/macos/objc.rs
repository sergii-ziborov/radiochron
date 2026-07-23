use core::ffi::{c_char, c_void};

pub(super) type Id = *mut c_void;
pub(super) type Sel = *mut c_void;

#[link(name = "objc")]
extern "C" {
    pub(super) fn objc_getClass(name: *const c_char) -> Id;
    pub(super) fn sel_registerName(name: *const c_char) -> Sel;
    pub(super) fn objc_autoreleasePoolPush() -> Id;
    pub(super) fn objc_autoreleasePoolPop(pool: Id);

    #[link_name = "objc_msgSend"]
    pub(super) fn send_id(receiver: Id, selector: Sel) -> Id;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_id_index(receiver: Id, selector: Sel, index: usize) -> Id;
    #[link_name = "objc_msgSend"]
    #[cfg(feature = "scan")]
    pub(super) fn send_scan(receiver: Id, selector: Sel, name: Id, error: *mut Id) -> Id;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_bool(receiver: Id, selector: Sel) -> bool;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_bool_id(receiver: Id, selector: Sel, value: Id) -> bool;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_isize(receiver: Id, selector: Sel) -> isize;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_usize(receiver: Id, selector: Sel) -> usize;
    #[link_name = "objc_msgSend"]
    pub(super) fn send_ptr(receiver: Id, selector: Sel) -> *const c_void;
}

// Merely linking the framework loads the Objective-C classes used above.
#[link(name = "CoreWLAN", kind = "framework")]
extern "C" {}
#[link(name = "Foundation", kind = "framework")]
extern "C" {}

pub(super) struct AutoreleasePool(Id);

impl AutoreleasePool {
    pub(super) fn new() -> Self {
        Self(unsafe { objc_autoreleasePoolPush() })
    }
}

impl Drop for AutoreleasePool {
    fn drop(&mut self) {
        unsafe { objc_autoreleasePoolPop(self.0) }
    }
}
pub(super) fn collection_objects(collection: Id) -> Vec<Id> {
    // NSSet (scan results) offers allObjects; NSArray simply does not. Asking
    // an object whether it responds avoids assuming which collection Apple
    // returns on a particular SDK revision.
    let responds = unsafe {
        let selector_object = selector(b"allObjects\0");
        send_bool_id(
            collection,
            selector(b"respondsToSelector:\0"),
            // SEL and object pointers have the same machine representation.
            selector_object,
        )
    };
    let array = if responds {
        unsafe { send_id(collection, selector(b"allObjects\0")) }
    } else {
        collection
    };
    if array.is_null() {
        return Vec::new();
    }
    let count = unsafe { send_usize(array, selector(b"count\0")) };
    (0..count)
        .filter_map(|index| {
            let object = unsafe { send_id_index(array, selector(b"objectAtIndex:\0"), index) };
            (!object.is_null()).then_some(object)
        })
        .collect()
}

pub(super) fn string_property(object: Id, name: &'static [u8]) -> Option<String> {
    if object.is_null() {
        return None;
    }
    let string = unsafe { send_id(object, selector(name)) };
    if string.is_null() {
        return None;
    }
    let bytes = unsafe { send_ptr(string, selector(b"UTF8String\0")) }.cast::<c_char>();
    if bytes.is_null() {
        return None;
    }
    let value = unsafe { std::ffi::CStr::from_ptr(bytes) }
        .to_string_lossy()
        .into_owned();
    (!value.is_empty()).then_some(value)
}

#[cfg(feature = "scan")]
pub(super) fn data_property(object: Id, name: &'static [u8]) -> Option<Vec<u8>> {
    let data = unsafe { send_id(object, selector(name)) };
    if data.is_null() {
        return None;
    }
    let len = unsafe { send_usize(data, selector(b"length\0")) };
    let bytes = unsafe { send_ptr(data, selector(b"bytes\0")) }.cast::<u8>();
    if len == 0 {
        return Some(Vec::new());
    }
    if bytes.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec())
}

pub(super) fn bool_property(object: Id, name: &'static [u8]) -> bool {
    unsafe { send_bool(object, selector(name)) }
}

pub(super) fn integer_property(object: Id, name: &'static [u8]) -> isize {
    unsafe { send_isize(object, selector(name)) }
}

pub(super) fn selector(name: &'static [u8]) -> Sel {
    debug_assert_eq!(name.last(), Some(&0));
    unsafe { sel_registerName(name.as_ptr().cast()) }
}
