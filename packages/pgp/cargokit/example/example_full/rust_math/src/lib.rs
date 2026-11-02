use std::os::raw::c_int;

#[repr(C)]
pub struct Vec2 {
    pub x: f64,
    pub y: f64,
}

#[no_mangle]
pub extern "C" fn vec2_add(a: Vec2, b: Vec2) -> Vec2 {
    Vec2 { x: a.x + b.x, y: a.y + b.y }
}

#[no_mangle]
pub extern "C" fn vec2_length(v: Vec2) -> f64 {
    (v.x * v.x + v.y * v.y).sqrt()
}

#[no_mangle]
pub extern "C" fn sort_array(
    arr: *mut i32,
    len: c_int,
    cmp: extern "C" fn(i32, i32) -> i32,
) {
    let slice = unsafe { std::slice::from_raw_parts_mut(arr, len as usize) };
    slice.sort_by(|a, b| {
        let result = cmp(*a, *b);
        result.cmp(&0)
    });
}

/// Returns 0 on success, -1 if divisor is zero.
#[no_mangle]
pub extern "C" fn safe_divide(a: f64, b: f64, result: *mut f64) -> c_int {
    if b == 0.0 {
        return -1;
    }
    unsafe { *result = a / b; }
    0
}
