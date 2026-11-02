use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

#[no_mangle]
pub extern "C" fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
pub extern "C" fn create_point(x: f64, y: f64) -> Point {
    Point { x, y }
}

#[no_mangle]
pub extern "C" fn distance(a: Point, b: Point) -> f64 {
    ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt()
}

#[no_mangle]
pub extern "C" fn reverse_string(input: *const c_char) -> *mut c_char {
    let s = unsafe { CStr::from_ptr(input) }.to_str().unwrap_or("");
    let reversed: String = s.chars().rev().collect();
    CString::new(reversed).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}
