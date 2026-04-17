use std::ffi::{CStr, c_char};

/// Convert `c` to a `&CStr`
///
/// Returns `None` if `c` is null.
///
/// # Safety
///
/// `c` must either null or nul-terminated and valid for reads up to the nul-terminator.
pub unsafe fn cstr<'a>(c: *const c_char) -> Option<&'a CStr> {
    if !c.is_null() {
        // SAFETY: ensured by function safety precondition.
        Some(unsafe { CStr::from_ptr(c) })
    } else {
        None
    }
}

/// Convert `c` to a `&str`.
///
/// Returns `None` if c is null or not valid UTF-8.
///
/// # Safety
///
/// `c` must either null or nul-terminated and valid for reads up to the nul-terminator.
pub unsafe fn str<'a>(c: *const c_char) -> Option<&'a str> {
    // SAFETY: ensured by function safety precondition.
    unsafe { cstr(c) }.and_then(|cstr| cstr.to_str().ok())
}
