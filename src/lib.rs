use sequoia_openpgp::{
    cert::{Cert as SequoiaCert, CertBuilder},
    parse::Parse,
    packet::{
        Key as SequoiaKey,
        key::{UnspecifiedParts, UnspecifiedRole},
        UserID as SequoiaUserID,
    },
    Result,
};
use std::ffi::CStr;
use std::io::Cursor;

#[repr(i32)]
pub enum FFIError {
    Ok = 0,
    Null = -1,
    Invalid = -2,
    Failed = -3,
}

pub struct Certificate(*mut SequoiaCert);
pub struct Key(*mut SequoiaKey<UnspecifiedParts, UnspecifiedRole>);
pub struct UserID(*mut SequoiaUserID);

/// # Safety
/// `cert` must be non-null and from a `pgp_certificate_*` constructor.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_free(cert: *mut Certificate) {
    if !cert.is_null() {
        let wrapper = Box::from_raw(cert);
        if !wrapper.0.is_null() {
            drop(Box::from_raw(wrapper.0));
        }
    }
}

/// # Safety
/// `key` must be non-null and from a `pgp_key_*` constructor.
#[no_mangle]
pub unsafe extern "C" fn pgp_key_free(key: *mut Key) {
    if !key.is_null() {
        let wrapper = Box::from_raw(key);
        if !wrapper.0.is_null() {
            drop(Box::from_raw(wrapper.0));
        }
    }
}

/// # Safety
/// `user_id` must be non-null and from a `pgp_user_id_*` constructor.
#[no_mangle]
pub unsafe extern "C" fn pgp_user_id_free(user_id: *mut UserID) {
    if !user_id.is_null() {
        let wrapper = Box::from_raw(user_id);
        if !wrapper.0.is_null() {
            drop(Box::from_raw(wrapper.0));
        }
    }
}

/// Parse an ASCII-armored PGP cert into `*cert`.
///
/// # Safety
/// `armored` and `cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_from_armored(
    armored: *const libc::c_char,
    cert: *mut *mut Certificate,
) -> i32 {
    if armored.is_null() || cert.is_null() {
        return FFIError::Null as i32;
    }

    let c_str = CStr::from_ptr(armored);
    let armored_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let cursor = Cursor::new(armored_str);
    let result: Result<SequoiaCert> = SequoiaCert::from_reader(cursor);

    match result {
        Ok(sequoia_cert) => {
            let inner = Box::into_raw(Box::new(sequoia_cert));
            *cert = Box::into_raw(Box::new(Certificate(inner)));
            FFIError::Ok as i32
        }
        Err(_) => FFIError::Invalid as i32,
    }
}

/// Generate a new certificate with the given user ID.
///
/// # Safety
/// `user_id` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_key_generate(
    user_id: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if user_id.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }

    let c_str = CStr::from_ptr(user_id);
    let user_id_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let result = CertBuilder::new()
        .add_userid(user_id_str)
        .add_transport_encryption_subkey()
        .generate();

    match result {
        Ok((cert, _revocation)) => {
            let inner = Box::into_raw(Box::new(cert));
            *new_cert = Box::into_raw(Box::new(Certificate(inner)));
            FFIError::Ok as i32
        }
        Err(_) => FFIError::Failed as i32,
    }
}
