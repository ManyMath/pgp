use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn to_uppercase(input: *const c_char) -> *mut c_char {
    let s = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
    CString::new(s.to_uppercase()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

pub struct StringBuilder {
    parts: Vec<String>,
}

#[no_mangle]
pub extern "C" fn string_builder_new() -> *mut StringBuilder {
    Box::into_raw(Box::new(StringBuilder { parts: Vec::new() }))
}

#[no_mangle]
pub extern "C" fn string_builder_append(ptr: *mut StringBuilder, s: *const c_char) {
    let builder = unsafe { &mut *ptr };
    let part = unsafe { CStr::from_ptr(s) }.to_str().unwrap_or("");
    builder.parts.push(part.to_string());
}

#[no_mangle]
pub extern "C" fn string_builder_count(ptr: *const StringBuilder) -> i32 {
    let builder = unsafe { &*ptr };
    builder.parts.len() as i32
}

#[no_mangle]
pub extern "C" fn string_builder_build(ptr: *const StringBuilder, separator: *const c_char) -> *mut c_char {
    let builder = unsafe { &*ptr };
    let sep = unsafe { CStr::from_ptr(separator) }.to_str().unwrap_or("");
    let result = builder.parts.join(sep);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn string_builder_free(ptr: *mut StringBuilder) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
    }
}
