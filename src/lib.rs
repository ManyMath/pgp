use sequoia_openpgp::{
    armor,
    cert::{Cert as SequoiaCert, CertBuilder},
    cert::prelude::*,
    crypto::{Password, SessionKey},
    parse::{
        stream::{
            DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder,
            MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder,
        },
        Parse,
    },
    packet::{
        Key as SequoiaKey,
        key::{UnspecifiedParts, UnspecifiedRole},
        PKESK, SKESK,
        UserID as SequoiaUserID,
    },
    policy::{Policy, StandardPolicy},
    serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message, Signer},
    serialize::Serialize,
    types::{KeyFlags, ReasonForRevocation, SymmetricAlgorithm},
    Fingerprint, KeyHandle, Result,
};
use std::ffi::CStr;
use std::io::{Cursor, Read, Write};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

unsafe fn write_c_string(value: &str, out: *mut *mut libc::c_char) -> i32 {
    let bytes = value.as_bytes();
    let buf = libc::malloc(bytes.len() + 1) as *mut u8;
    if buf.is_null() {
        return FFIError::Failed as i32;
    }

    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    *buf.add(bytes.len()) = 0;
    *out = buf as *mut libc::c_char;

    FFIError::Ok as i32
}

unsafe fn write_bytes_buffer(data: &[u8], out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let buf = libc::malloc(data.len().max(1)) as *mut u8;
    if buf.is_null() {
        return FFIError::Failed as i32;
    }
    if !data.is_empty() {
        ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    *out = buf;
    *out_len = data.len();
    FFIError::Ok as i32
}

struct DecryptOnlyHelper<'a> {
    secret: &'a SequoiaCert,
    policy: &'a dyn Policy,
}

struct VerifyHelper<'a> {
    cert: &'a SequoiaCert,
}

impl VerificationHelper for VerifyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut good = false;
        for (index, layer) in structure.into_iter().enumerate() {
            match layer {
                MessageLayer::SignatureGroup { results } if index == 0 => {
                    if results.iter().any(|result| result.is_ok()) {
                        good = true;
                    } else {
                        return Err(anyhow::anyhow!("No valid signature"));
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        if good {
            Ok(())
        } else {
            Err(anyhow::anyhow!("No signature"))
        }
    }
}

impl VerificationHelper for DecryptOnlyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for DecryptOnlyHelper<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let keys = self
            .secret
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|key| key.key().clone())
            .collect::<Vec<_>>();

        for pkesk in pkesks {
            for key in &keys {
                let mut keypair = key.clone().into_keypair()?;
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    return Ok(Some(key.fingerprint()));
                }
            }
        }

        Err(anyhow::anyhow!("No matching decryption key"))
    }
}

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
        .add_signing_subkey()
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

/// Export the certificate as an ASCII-armored public key block.
/// Caller must free `*armored` with `free()`.
///
/// # Safety
/// `cert` and `armored` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_export_public_armored(
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
    let mut armorer = match Armorer::new(message).kind(armor::Kind::PublicKey).build() {
        Ok(a) => a,
        Err(_) => return FFIError::Failed as i32,
    };

    if sequoia_cert.serialize(&mut armorer).is_err() {
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

/// Export the certificate as an ASCII-armored secret key block.
/// Caller must free `*armored` with `free()`.
///
/// # Safety
/// `cert` and `armored` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_export_secret_armored(
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
    pgp_certificate_export_secret_armored(cert, armored)
}

/// Encrypt `plaintext` to the certificate and write an ASCII-armored message to
/// `*armored_message`. Caller must free `*armored_message` with `free()`.
///
/// # Safety
/// `cert`, `plaintext`, and `armored_message` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_encrypt_string(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    let policy = &StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        return FFIError::NotFound as i32;
    }

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor2::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

/// Decrypt an ASCII-armored message using the certificate and write plaintext to
/// `*plaintext`. Caller must free `*plaintext` with `free()`.
///
/// # Safety
/// `cert`, `armored_message`, and `plaintext` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_decrypt_string(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || armored_message.is_null() || plaintext.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = DecryptOnlyHelper {
        secret: cert,
        policy,
    };
    let mut decryptor = match DecryptorBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(decryptor) => decryptor,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if decryptor.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    let text = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    write_c_string(&text, plaintext)
}

/// Sign `plaintext` with the certificate and write an ASCII-armored signed
/// message to `*armored_message`. Caller must free `*armored_message` with
/// `free()`.
///
/// # Safety
/// `cert`, `plaintext`, and `armored_message` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_sign_string(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    let policy = &StandardPolicy::new();
    let key = match cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
    {
        Some(key) => key.key().clone(),
        None => return FFIError::NotFound as i32,
    };
    let keypair = match key.into_keypair() {
        Ok(keypair) => keypair,
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Signer::new(message, keypair).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

/// Verify an ASCII-armored signed message using the certificate and write the
/// verified plaintext to `*plaintext`. Caller must free `*plaintext` with
/// `free()`.
///
/// # Safety
/// `cert`, `armored_message`, and `plaintext` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_string(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || armored_message.is_null() || plaintext.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper { cert };
    let mut verifier = match VerifierBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(verifier) => verifier,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if verifier.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    let text = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    write_c_string(&text, plaintext)
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

/// Add a signing subkey, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_add_signing_subkey(
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

    let updated = match KeyBuilder::new(KeyFlags::empty().set_signing()).subkey(vc) {
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

/// Encrypt `plaintext` to all `count` recipient certificates and write a single
/// ASCII-armored message to `*armored_message`. Any recipient whose private key
/// is available can decrypt. Returns NotFound if `count` is zero or no cert
/// has a usable transport-encryption subkey.
/// Caller must free `*armored_message` with `free()`.
///
/// # Safety
/// `certs`, `plaintext`, and `armored_message` must be non-null; each element
/// of the `certs` array must be a valid Certificate pointer.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_string_to_recipients(
    certs: *const *const Certificate,
    count: usize,
    plaintext: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if certs.is_null() || plaintext.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    if count == 0 {
        return FFIError::NotFound as i32;
    }
    *armored_message = ptr::null_mut();

    let policy = StandardPolicy::new();
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    // Clone all certs so their key data lives at a single, function-scoped
    // location. All subsequent borrows have a unified lifetime.
    let mut cert_vec: Vec<SequoiaCert> = Vec::with_capacity(count);
    for i in 0..count {
        let outer_ptr = *certs.add(i);
        if outer_ptr.is_null() {
            return FFIError::Null as i32;
        }
        let wrapper = &*outer_ptr;
        if wrapper.0.is_null() {
            return FFIError::Invalid as i32;
        }
        cert_vec.push((&*wrapper.0).clone());
    }

    // Collect all transport-encryption keys from every cert.
    let mut recipients: Vec<_> = Vec::new();
    for cert in cert_vec.iter() {
        for ka in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipients.push(ka);
        }
    }

    if recipients.is_empty() {
        return FFIError::NotFound as i32;
    }

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor2::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
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

/// Return the primary key fingerprint as an uppercase hex string.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_fingerprint(
    cert: *const Certificate,
    out: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }
    *out = ptr::null_mut();
    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let fp = (&*wrapper.0).fingerprint().to_hex();
    write_c_string(&fp, out)
}

/// Return all user IDs as a newline-delimited UTF-8 string.
/// Includes revoked and expired user IDs (raw, unfiltered).
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_userids(
    cert: *const Certificate,
    out: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }
    *out = ptr::null_mut();
    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let ids: Vec<String> = (&*wrapper.0)
        .userids()
        .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
        .collect();
    let joined = ids.join("\n");
    write_c_string(&joined, out)
}

/// Write the primary key expiration as seconds since the Unix epoch into `*out`.
/// Writes 0 if the certificate has no expiry or if the policy check fails.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_expiry_epoch(
    cert: *const Certificate,
    out: *mut i64,
) -> i32 {
    if cert.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }
    *out = 0;
    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();
    let epoch_secs: i64 = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => match vc.primary_key().key_expiration_time() {
            Some(t) => t
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            None => 0,
        },
        Err(_) => 0,
    };
    *out = epoch_secs;
    FFIError::Ok as i32
}

/// Generate a new certificate with all secret key material encrypted with
/// `passphrase`. Writes the locked certificate to `*new_cert`.
///
/// # Safety
/// `user_id`, `passphrase`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_key_generate_with_passphrase(
    user_id: *const libc::c_char,
    passphrase: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if user_id.is_null() || passphrase.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let password: Password = passphrase_str.into();
    let result = CertBuilder::new()
        .add_userid(user_id_str)
        .add_transport_encryption_subkey()
        .add_signing_subkey()
        .set_password(Some(password))
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

/// Decrypt all passphrase-protected secret key material in `cert`, writing
/// a new certificate with unencrypted secrets to `*out_cert`.
///
/// Returns `Invalid` (-2) if the passphrase is wrong for any key,
/// `NotFound` (-4) if `cert` carries no secret material.
///
/// # Safety
/// `cert`, `passphrase`, and `out_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_unlock(
    cert: *const Certificate,
    passphrase: *const libc::c_char,
    out_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || passphrase.is_null() || out_cert.is_null() {
        return FFIError::Null as i32;
    }
    *out_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = (&*wrapper.0).clone();

    // Require at least one key with secret material.
    if sequoia_cert.keys().secret().next().is_none() {
        return FFIError::NotFound as i32;
    }

    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let password: Password = passphrase_str.into();

    // Decrypt each key that has encrypted secret material and re-insert it.
    let mut packets: Vec<sequoia_openpgp::Packet> = Vec::new();
    for ka in sequoia_cert.keys().secret() {
        let key = ka.key().clone();
        if key.has_unencrypted_secret() {
            continue;
        }
        let decrypted = match key.decrypt_secret(&password) {
            Ok(k) => k,
            Err(_) => return FFIError::Invalid as i32,
        };
        let packet: sequoia_openpgp::Packet = if ka.primary() {
            decrypted.role_into_primary().into()
        } else {
            decrypted.role_into_subordinate().into()
        };
        packets.push(packet);
    }

    let updated = match sequoia_cert.insert_packets(packets) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *out_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Sign `plaintext` with the certificate and write an ASCII-armored detached
/// signature (BEGIN PGP SIGNATURE) to `*armored_sig`. The plaintext is left
/// untouched. Caller must free `*armored_sig` with `free()`.
///
/// # Safety
/// `cert`, `plaintext`, and `armored_sig` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_sign_detached(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    armored_sig: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || armored_sig.is_null() {
        return FFIError::Null as i32;
    }
    *armored_sig = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    let policy = &StandardPolicy::new();
    let key = match cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
    {
        Some(key) => key.key().clone(),
        None => return FFIError::NotFound as i32,
    };
    let keypair = match key.into_keypair() {
        Ok(kp) => kp,
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Signature).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match Signer::new(message, keypair).detached().build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let sig = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&sig, armored_sig)
}

/// Verify a detached signature `armored_sig` against `plaintext` using the
/// certificate. Returns 0 if valid, negative on failure.
///
/// # Safety
/// `cert`, `plaintext`, and `armored_sig` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_detached(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    armored_sig: *const libc::c_char,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || armored_sig.is_null() {
        return FFIError::Null as i32;
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();
    let sig_bytes = CStr::from_ptr(armored_sig).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper { cert };
    let mut verifier = match DetachedVerifierBuilder::from_bytes(sig_bytes) {
        Ok(b) => match b.with_policy(policy, None, helper) {
            Ok(v) => v,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    match verifier.verify_bytes(plaintext_bytes) {
        Ok(_) => FFIError::Ok as i32,
        Err(_) => FFIError::Failed as i32,
    }
}

/// Generate a new certificate carrying `user_id` with an optional validity
/// period. `validity_seconds == 0` means no expiry.
/// Writes the new certificate to `*new_cert`. Caller must free with
/// `pgp_certificate_free`.
///
/// # Safety
/// `user_id` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_key_generate_with_expiry(
    user_id: *const libc::c_char,
    validity_seconds: u64,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if user_id.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut builder = CertBuilder::new()
        .add_userid(user_id_str)
        .add_transport_encryption_subkey()
        .add_signing_subkey();

    if validity_seconds > 0 {
        builder = builder.set_validity_period(Duration::from_secs(validity_seconds));
    }

    match builder.generate() {
        Ok((cert, _revocation)) => {
            let inner = Box::into_raw(Box::new(cert));
            *new_cert = Box::into_raw(Box::new(Certificate(inner)));
            FFIError::Ok as i32
        }
        Err(_) => FFIError::Failed as i32,
    }
}

/// Update the expiry on every key in the certificate. `validity_seconds == 0`
/// clears the expiry. Writes the updated certificate to `*new_cert`. Caller
/// must free both the original and the returned certificate separately.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_set_expiry(
    cert: *const Certificate,
    validity_seconds: u64,
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
    let sequoia_cert = (&*wrapper.0).clone();

    // OpenPGP signature creation times have whole-second resolution, and the
    // active self-signature is selected by newest creation time. Re-signing
    // within the same second as the existing binding signatures would tie the
    // previous signature and could leave the expiry unchanged. Wait until the
    // wall clock is strictly past the newest existing self-signature so the
    // refreshed signatures deterministically win, while keeping their creation
    // time <= now so they are immediately valid when the expiry is read back.
    {
        let mut newest: Option<SystemTime> = None;
        for ka in sequoia_cert.keys() {
            for sig in ka.self_signatures() {
                if let Some(t) = sig.signature_creation_time() {
                    if newest.map_or(true, |n| t > n) {
                        newest = Some(t);
                    }
                }
            }
        }
        for uida in sequoia_cert.userids() {
            for sig in uida.self_signatures() {
                if let Some(t) = sig.signature_creation_time() {
                    if newest.map_or(true, |n| t > n) {
                        newest = Some(t);
                    }
                }
            }
        }
        if let Some(newest) = newest {
            let target = newest + Duration::from_secs(1);
            // Cap the wait so a skewed clock (signature far in the future)
            // cannot hang the call; in that abnormal case we simply proceed.
            loop {
                match target.duration_since(SystemTime::now()) {
                    Ok(remaining) if remaining <= Duration::from_secs(2) => {
                        std::thread::sleep(remaining);
                    }
                    _ => break,
                }
            }
        }
    }

    let expiry: Option<SystemTime> = if validity_seconds > 0 {
        match SystemTime::now().checked_add(Duration::from_secs(validity_seconds)) {
            Some(t) => Some(t),
            None => return FFIError::Invalid as i32,
        }
    } else {
        None
    };

    let policy = StandardPolicy::new();
    let vc = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };

    // Build primary signer from the primary key's secret material.
    let mut primary_signer = match sequoia_cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
    {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    // Collect expiry-update signatures for all keys.
    let mut all_sigs: Vec<sequoia_openpgp::Packet> = Vec::new();

    // Primary key.
    match vc.primary_key().set_expiration_time(&mut primary_signer, expiry) {
        Ok(sigs) => all_sigs.extend(sigs.into_iter().map(|s| s.into())),
        Err(_) => return FFIError::Failed as i32,
    }

    // Subkeys: signing subkeys need their own signer; others use the primary.
    for ka in vc.keys().subkeys() {
        let is_signing = ka.for_signing();
        if is_signing {
            let sub_key = match ka.key().clone().parts_into_secret() {
                Ok(k) => k,
                Err(_) => return FFIError::Invalid as i32,
            };
            let mut sub_signer = match sub_key.into_keypair() {
                Ok(kp) => kp,
                Err(_) => return FFIError::Failed as i32,
            };
            match ka.set_expiration_time(&mut primary_signer, Some(&mut sub_signer), expiry) {
                Ok(sigs) => all_sigs.extend(sigs.into_iter().map(|s| s.into())),
                Err(_) => return FFIError::Failed as i32,
            }
        } else {
            match ka.set_expiration_time(&mut primary_signer, None, expiry) {
                Ok(sigs) => all_sigs.extend(sigs.into_iter().map(|s| s.into())),
                Err(_) => return FFIError::Failed as i32,
            }
        }
    }

    let updated = match sequoia_cert.insert_packets(all_sigs) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

struct DecryptAndVerifyHelper<'a> {
    decrypt_cert: &'a SequoiaCert,
    verify_cert: &'a SequoiaCert,
    policy: &'a dyn Policy,
    signer_fp: Option<String>,
}

impl VerificationHelper for DecryptAndVerifyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(vec![self.verify_cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut found = false;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    if let Ok(good) = result {
                        self.signer_fp = Some(good.ka.fingerprint().to_hex());
                        found = true;
                        break;
                    }
                }
            }
        }
        if found {
            Ok(())
        } else {
            Err(anyhow::anyhow!("No valid signature"))
        }
    }
}

impl DecryptionHelper for DecryptAndVerifyHelper<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let keys = self
            .decrypt_cert
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .map(|key| key.key().clone())
            .collect::<Vec<_>>();

        for pkesk in pkesks {
            for key in &keys {
                let mut keypair = key.clone().into_keypair()?;
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    return Ok(Some(key.fingerprint()));
                }
            }
        }

        Err(anyhow::anyhow!("No matching decryption key"))
    }
}

// -- Feature 1: Signed+encrypted messages

/// Encrypt `plaintext` to all `count` recipient certificates and sign the
/// message with `signer_cert`. Writes a single ASCII-armored message to
/// `*armored_message`. Caller must free `*armored_message` with `free()`.
///
/// # Safety
/// All pointers must be non-null; each element of `recipient_certs` must be a
/// valid Certificate pointer.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_and_sign_string(
    signer_cert: *const Certificate,
    recipient_certs: *const *const Certificate,
    count: usize,
    plaintext: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if signer_cert.is_null()
        || recipient_certs.is_null()
        || plaintext.is_null()
        || armored_message.is_null()
    {
        return FFIError::Null as i32;
    }
    if count == 0 {
        return FFIError::NotFound as i32;
    }
    *armored_message = ptr::null_mut();

    let signer_wrapper = &*signer_cert;
    if signer_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signer_cert_ref = &*signer_wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    let policy = &StandardPolicy::new();

    let signing_key = match signer_cert_ref
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
    {
        Some(key) => key.key().clone(),
        None => return FFIError::NotFound as i32,
    };
    let keypair = match signing_key.into_keypair() {
        Ok(kp) => kp,
        Err(_) => return FFIError::Failed as i32,
    };

    let mut cert_vec: Vec<SequoiaCert> = Vec::with_capacity(count);
    for i in 0..count {
        let outer_ptr = *recipient_certs.add(i);
        if outer_ptr.is_null() {
            return FFIError::Null as i32;
        }
        let wrapper = &*outer_ptr;
        if wrapper.0.is_null() {
            return FFIError::Invalid as i32;
        }
        cert_vec.push((&*wrapper.0).clone());
    }

    let mut recipients: Vec<_> = Vec::new();
    for cert in cert_vec.iter() {
        for ka in cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipients.push(ka);
        }
    }
    if recipients.is_empty() {
        return FFIError::NotFound as i32;
    }

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor2::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Signer::new(message, keypair).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

/// Decrypt an ASCII-armored message with `decrypt_cert` and verify its
/// signature against `verify_cert`. Writes the plaintext to `*plaintext_out`
/// and the signer's fingerprint to `*fingerprint_out`. Both must be freed with
/// `free()`. Returns `Failed` (-3) if the message carries no valid signature.
///
/// # Safety
/// All pointers must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_and_verify_string(
    decrypt_cert: *const Certificate,
    verify_cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
    fingerprint_out: *mut *mut libc::c_char,
) -> i32 {
    if decrypt_cert.is_null()
        || verify_cert.is_null()
        || armored_message.is_null()
        || plaintext_out.is_null()
        || fingerprint_out.is_null()
    {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();
    *fingerprint_out = ptr::null_mut();

    let decrypt_wrapper = &*decrypt_cert;
    if decrypt_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let verify_wrapper = &*verify_cert;
    if verify_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let decrypt_cert_ref = &*decrypt_wrapper.0;
    let verify_cert_ref = &*verify_wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = DecryptAndVerifyHelper {
        decrypt_cert: decrypt_cert_ref,
        verify_cert: verify_cert_ref,
        policy,
        signer_fp: None,
    };

    let mut decryptor = match DecryptorBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(d) => d,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if decryptor.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    let text = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let helper = decryptor.into_helper();
    let fp = match helper.signer_fp {
        Some(fp) => fp,
        None => return FFIError::Failed as i32,
    };

    let r = write_c_string(&text, plaintext_out);
    if r != 0 {
        return r;
    }
    let r = write_c_string(&fp, fingerprint_out);
    if r != 0 {
        // The plaintext buffer was already handed out; free it so the caller,
        // which treats a non-zero return as "nothing was allocated", cannot
        // leak it.
        libc::free(*plaintext_out as *mut libc::c_void);
        *plaintext_out = ptr::null_mut();
    }
    r
}

// -- Feature 2: Binary data (bytes API)

/// Encrypt `data` (raw bytes, `len` long) to the certificate and write an
/// ASCII-armored message to `*armored_message`. Caller must free
/// `*armored_message` with `free()`.
///
/// # Safety
/// `cert`, `data`, and `armored_message` must be non-null; `data` must point
/// to at least `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_encrypt_bytes(
    cert: *const Certificate,
    data: *const u8,
    len: usize,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || data.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    // `from_raw_parts` requires a valid, non-dangling pointer even when
    // `len == 0`; callers commonly pass a sentinel for empty buffers, so map
    // the empty case to an explicit empty slice instead.
    let plaintext_bytes: &[u8] = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };

    let policy = &StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        return FFIError::NotFound as i32;
    }

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor2::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

/// Decrypt an ASCII-armored message using the certificate and write the raw
/// plaintext bytes to `*plaintext_out` (length in `*plaintext_len`). Caller
/// must free `*plaintext_out` with `free()`.
///
/// # Safety
/// `cert`, `armored_message`, `plaintext_out`, and `plaintext_len` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_decrypt_bytes(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext_out: *mut *mut u8,
    plaintext_len: *mut usize,
) -> i32 {
    if cert.is_null()
        || armored_message.is_null()
        || plaintext_out.is_null()
        || plaintext_len.is_null()
    {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();
    *plaintext_len = 0;

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = DecryptOnlyHelper {
        secret: cert,
        policy,
    };
    let mut decryptor = match DecryptorBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(d) => d,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if decryptor.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    write_bytes_buffer(&out, plaintext_out, plaintext_len)
}

/// Sign `data` (raw bytes, `len` long) with the certificate and write an
/// ASCII-armored signed message to `*armored_message`. Caller must free
/// `*armored_message` with `free()`.
///
/// # Safety
/// `cert`, `data`, and `armored_message` must be non-null; `data` must point
/// to at least `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_sign_bytes(
    cert: *const Certificate,
    data: *const u8,
    len: usize,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || data.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    // `from_raw_parts` requires a valid, non-dangling pointer even when
    // `len == 0`; callers commonly pass a sentinel for empty buffers, so map
    // the empty case to an explicit empty slice instead.
    let plaintext_bytes: &[u8] = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };

    let policy = &StandardPolicy::new();
    let key = match cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
    {
        Some(key) => key.key().clone(),
        None => return FFIError::NotFound as i32,
    };
    let keypair = match key.into_keypair() {
        Ok(kp) => kp,
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Signer::new(message, keypair).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

/// Verify an ASCII-armored signed message and write the verified raw bytes to
/// `*plaintext_out` (length in `*plaintext_len`). Caller must free
/// `*plaintext_out` with `free()`.
///
/// # Safety
/// `cert`, `armored_message`, `plaintext_out`, and `plaintext_len` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_bytes(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext_out: *mut *mut u8,
    plaintext_len: *mut usize,
) -> i32 {
    if cert.is_null()
        || armored_message.is_null()
        || plaintext_out.is_null()
        || plaintext_len.is_null()
    {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();
    *plaintext_len = 0;

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper { cert };
    let mut verifier = match VerifierBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(v) => v,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if verifier.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    write_bytes_buffer(&out, plaintext_out, plaintext_len)
}

/// Encrypt `data` (raw bytes, `len` long) to all `count` recipient certificates
/// and write an ASCII-armored message to `*armored_message`. Caller must free
/// `*armored_message` with `free()`.
///
/// # Safety
/// `certs`, `data`, and `armored_message` must be non-null; `data` must point
/// to at least `len` valid bytes; each element of `certs` must be a valid
/// Certificate pointer.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_bytes_to_recipients(
    certs: *const *const Certificate,
    count: usize,
    data: *const u8,
    len: usize,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if certs.is_null() || data.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    if count == 0 {
        return FFIError::NotFound as i32;
    }
    *armored_message = ptr::null_mut();

    let policy = StandardPolicy::new();
    // `from_raw_parts` requires a valid, non-dangling pointer even when
    // `len == 0`; callers commonly pass a sentinel for empty buffers, so map
    // the empty case to an explicit empty slice instead.
    let plaintext_bytes: &[u8] = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };

    let mut cert_vec: Vec<SequoiaCert> = Vec::with_capacity(count);
    for i in 0..count {
        let outer_ptr = *certs.add(i);
        if outer_ptr.is_null() {
            return FFIError::Null as i32;
        }
        let wrapper = &*outer_ptr;
        if wrapper.0.is_null() {
            return FFIError::Invalid as i32;
        }
        cert_vec.push((&*wrapper.0).clone());
    }

    let mut recipients: Vec<_> = Vec::new();
    for cert in cert_vec.iter() {
        for ka in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipients.push(ka);
        }
    }
    if recipients.is_empty() {
        return FFIError::NotFound as i32;
    }

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor2::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };

    if message.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if message.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored, armored_message)
}

// -- Feature 3: Cleartext signatures

/// Sign `plaintext` with the certificate using the Cleartext Signature
/// Framework (RFC 4880 section 7), writing a "BEGIN PGP SIGNED MESSAGE" block to
/// `*signed_message`. Caller must free `*signed_message` with `free()`.
///
/// # Safety
/// `cert`, `plaintext`, and `signed_message` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_sign_cleartext(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    signed_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || signed_message.is_null() {
        return FFIError::Null as i32;
    }
    *signed_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();

    let policy = &StandardPolicy::new();
    let key = match cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
    {
        Some(key) => key.key().clone(),
        None => return FFIError::NotFound as i32,
    };
    let keypair = match key.into_keypair() {
        Ok(kp) => kp,
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    // Cleartext mode: no Armorer, no LiteralWriter - write directly to Signer.
    let mut signer = match Signer::new(message, keypair).cleartext().build() {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    if signer.write_all(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }
    if signer.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let result = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&result, signed_message)
}

/// Verify a "BEGIN PGP SIGNED MESSAGE" cleartext-signed message using the
/// certificate. Writes the plaintext to `*plaintext_out`. Caller must free
/// `*plaintext_out` with `free()`.
///
/// # Safety
/// `cert`, `signed_message`, and `plaintext_out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_cleartext(
    cert: *const Certificate,
    signed_message: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || signed_message.is_null() || plaintext_out.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let msg_bytes = CStr::from_ptr(signed_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper { cert };
    // VerifierBuilder handles cleartext signatures transparently.
    let mut verifier = match VerifierBuilder::from_bytes(msg_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(v) => v,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let mut out = Vec::new();
    if verifier.read_to_end(&mut out).is_err() {
        return FFIError::Failed as i32;
    }

    let text = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    write_c_string(&text, plaintext_out)
}
