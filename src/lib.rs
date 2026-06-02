use sequoia_openpgp::{
    armor,
    cert::{Cert as SequoiaCert, CertBuilder},
    cert::prelude::*,
    parse::Parse,
    packet::{
        Key as SequoiaKey,
        key::{UnspecifiedParts, UnspecifiedRole},
        UserID as SequoiaUserID,
    },
    policy::StandardPolicy,
    serialize::stream::{Armorer, Message},
    serialize::Serialize,
    types::{KeyFlags, ReasonForRevocation},
    Result,
};
use std::ffi::CStr;
use std::io::Cursor;
use std::ptr;

#[repr(i32)]
pub enum FFIError {
    Ok = 0,
    Null = -1,
    Invalid = -2,
    Failed = -3,
    NotFound = -4,
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

/// Export the certificate as an ASCII-armored secret key block.
/// Caller must free `*armored` with `free()`.
///
/// # Safety
/// `cert` and `armored` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_export_armored(
    cert: *const Certificate,
    armored: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || armored.is_null() {
        return FFIError::Null as i32;
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    *armored = ptr::null_mut();

    let sequoia_cert = &*wrapper.0;

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let mut armorer = match Armorer::new(message).kind(armor::Kind::SecretKey).build() {
        Ok(a) => a,
        Err(_) => return FFIError::Failed as i32,
    };

    if sequoia_cert.as_tsk().serialize(&mut armorer).is_err() {
        return FFIError::Failed as i32;
    }
    if armorer.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored_string = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let bytes = armored_string.as_bytes();
    let buf = libc::malloc(bytes.len() + 1) as *mut u8;
    if buf.is_null() {
        return FFIError::Failed as i32;
    }

    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    *buf.add(bytes.len()) = 0;
    *armored = buf as *mut libc::c_char;

    FFIError::Ok as i32
}

/// Revoke the cert and write the updated cert to `*revoked_cert`.
///
/// # Safety
/// `cert` and `revoked_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke(
    cert: *const Certificate,
    revoked_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || revoked_cert.is_null() {
        return FFIError::Null as i32;
    }
    *revoked_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = (&*wrapper.0).clone();

    let mut signer = match cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Revoked") {
        Ok(b) => match b.build(&mut signer, &cert, None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *revoked_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Add a transport-encryption subkey, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_add_transport_encryption_subkey(
    cert: *const Certificate,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = (&*wrapper.0).clone();

    let p = &StandardPolicy::new();
    let vc = match cert.with_policy(p, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match KeyBuilder::new(KeyFlags::empty().set_transport_encryption())
        .subkey(vc) {
        Ok(b) => match b.attach_cert() {
            Ok(c) => c,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Revoke the subkey at `subkey_index`, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke_subkey(
    cert: *const Certificate,
    subkey_index: u32,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = (&*wrapper.0).clone();

    let mut signer = match cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let subkey = match cert.keys().subkeys().nth(subkey_index as usize) {
        Some(s) => s,
        None => return FFIError::NotFound as i32,
    };

    let sig = match SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"Subkey revoked") {
        Ok(b) => match b.build(&mut signer, &cert, subkey.key(), None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Add `user_id` to the cert, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert`, `user_id`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_add_userid(
    cert: *const Certificate,
    user_id: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || user_id.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = (&*wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut signer = match cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let uid = SequoiaUserID::from(user_id_str);
    let sig = match uid.certify(&mut signer, &cert, None, None, None) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(vec![uid]) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };
    let updated = match updated.insert_packets(vec![sig]) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Revoke the exact-match user ID, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert`, `user_id`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke_userid(
    cert: *const Certificate,
    user_id: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || user_id.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = (&*wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let target = match cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua,
        None => return FFIError::NotFound as i32,
    };

    let mut signer = match cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"User ID revoked") {
        Ok(b) => match b.build(&mut signer, &cert, target.userid(), None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}
