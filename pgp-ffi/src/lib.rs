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
    packet::{PKESK, SKESK, UserID as SequoiaUserID},
    policy::{Policy, StandardPolicy},
    serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer},
    serialize::Serialize,
    types::{
        CompressionAlgorithm, Features, HashAlgorithm, KeyFlags, ReasonForRevocation,
        RevocationKey, RevocationStatus, SymmetricAlgorithm,
    },
    KeyHandle, Result,
};
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufWriter, Cursor, Read, Write};
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

/// Borrow `message` as UTF-8 bytes for a revocation signature, or `b""` if
/// `message` is null.
unsafe fn revocation_message_bytes<'a>(
    message: *const libc::c_char,
) -> std::result::Result<&'a [u8], i32> {
    if message.is_null() {
        return Ok(b"");
    }
    match CStr::from_ptr(message).to_str() {
        Ok(s) => Ok(s.as_bytes()),
        Err(_) => Err(FFIError::Invalid as i32),
    }
}

/// Borrow a NUL-terminated C string as a UTF-8 file path.
unsafe fn path_str<'a>(path: *const libc::c_char) -> std::result::Result<&'a str, i32> {
    CStr::from_ptr(path).to_str().map_err(|_| FFIError::Invalid as i32)
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
    signer_fp: Option<String>,
    signature_creation_epoch: Option<i64>,
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
                    if let Some(good_checksum) = results.into_iter().flatten().next() {
                        self.signer_fp = Some(good_checksum.ka.key().fingerprint().to_hex());
                        self.signature_creation_epoch = good_checksum
                            .sig
                            .signature_creation_time()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64);
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
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
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
                    return Ok(Some(self.secret.clone()));
                }
            }
        }

        Err(anyhow::anyhow!("No matching decryption key"))
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Recovers a message's session key (without decrypting the message body)
/// using `secret`'s transport-encryption subkey(s). Used by
/// `pgp_message_session_key`.
struct SessionKeyHelper<'a> {
    secret: &'a SequoiaCert,
    policy: &'a dyn Policy,
    session_key_hex: Option<String>,
    algo: Option<SymmetricAlgorithm>,
}

impl VerificationHelper for SessionKeyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for SessionKeyHelper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
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
                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt(algo, &session_key) {
                        self.session_key_hex = Some(bytes_to_hex(&session_key));
                        self.algo = algo.or(sym_algo);
                        return Ok(Some(self.secret.clone()));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No matching decryption key"))
    }
}

/// Decrypts a message body given a session key directly, bypassing any
/// certificate or secret key material entirely. Used by
/// `pgp_decrypt_with_session_key`.
struct RawSessionKeyHelper {
    session_key: SessionKey,
    algo: Option<SymmetricAlgorithm>,
}

impl VerificationHelper for RawSessionKeyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for RawSessionKeyHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        _skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
        if decrypt(self.algo, &self.session_key) {
            Ok(None)
        } else {
            Err(anyhow::anyhow!("Session key did not decrypt the message"))
        }
    }
}

/// Free a string or byte buffer returned through an `out` parameter.
///
/// # Safety
/// `ptr` must be null or a buffer this library allocated, freed at most once.
#[no_mangle]
pub unsafe extern "C" fn pgp_free(ptr: *mut libc::c_void) {
    libc::free(ptr);
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

/// Maps the `cipher_suite` codes accepted by
/// `pgp_key_generate_with_cipher_suite` to Sequoia's `CipherSuite`:
/// 0 = Cv25519 (default, EdDSA/ECDH over Curve25519), 1 = RSA3k, 2 = P256,
/// 3 = P384, 4 = P521, 5 = RSA2k, 6 = RSA4k.
fn cipher_suite_from_code(code: u8) -> Option<CipherSuite> {
    match code {
        0 => Some(CipherSuite::Cv25519),
        1 => Some(CipherSuite::RSA3k),
        2 => Some(CipherSuite::P256),
        3 => Some(CipherSuite::P384),
        4 => Some(CipherSuite::P521),
        5 => Some(CipherSuite::RSA2k),
        6 => Some(CipherSuite::RSA4k),
        _ => None,
    }
}

/// Generate a new certificate with the given user ID and key algorithm,
/// using the same subkey layout as `pgp_key_generate` (a transport-encryption
/// subkey and a signing subkey). See `cipher_suite_from_code` for the
/// `cipher_suite` code mapping; an out-of-range code is rejected as Invalid.
///
/// # Safety
/// `user_id` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_key_generate_with_cipher_suite(
    user_id: *const libc::c_char,
    cipher_suite: u8,
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

    let cipher_suite = match cipher_suite_from_code(cipher_suite) {
        Some(cs) => cs,
        None => return FFIError::Invalid as i32,
    };

    let result = CertBuilder::new()
        .set_cipher_suite(cipher_suite)
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

    // `.export()`, not `.serialize()`: silently drops non-exportable
    // certifications (`pgp_certificate_certify_userid_exportable(..., false,
    // ...)`, GnuPG's "local signature") and sensitive designated-revoker
    // entries: this function's own doc/Dart comment already promises "share
    // with others", so it must honor those markers rather than leaking them.
    if sequoia_openpgp::serialize::Marshal::export(sequoia_cert, &mut armorer).is_err() {
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
    let message = match Encryptor::for_recipients(message, recipients).build() {
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

/// List the recipient key IDs an ASCII-armored encrypted message is
/// addressed to, without decrypting it and without needing any secret key
/// material: reads each top-level PKESK packet's recipient key ID. Returns
/// one 16-character uppercase hex key ID per line (RFC 4880 key IDs are the
/// low 64 bits of a fingerprint, not a full fingerprint); a hidden/wildcard
/// recipient (RFC 4880 section 5.1) is reported as the literal string `hidden`.
/// Useful for a multi-key client to determine which of its keys, if any,
/// could plausibly decrypt a message before attempting to do so.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `armored_message` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_message_recipient_key_ids(
    armored_message: *const libc::c_char,
    out: *mut *mut libc::c_char,
) -> i32 {
    if armored_message.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }
    *out = ptr::null_mut();

    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();
    let pile = match sequoia_openpgp::PacketPile::from_bytes(armored_bytes) {
        Ok(p) => p,
        Err(_) => return FFIError::Invalid as i32,
    };

    let lines: Vec<String> = pile
        .children()
        .filter_map(|packet| match packet {
            sequoia_openpgp::Packet::PKESK(pkesk) => {
                match pkesk.recipient() {
                    None => Some("hidden".to_string()),
                    // `recipient()` may hand back a full `Fingerprint`-based
                    // `KeyHandle` (e.g. for PKESKv6 packets); normalize to the
                    // low 64-bit key ID to match this function's documented
                    // 16-character-hex-key-ID contract.
                    Some(recipient) => {
                        Some(sequoia_openpgp::KeyID::from(recipient).to_hex())
                    }
                }
            }
            _ => None,
        })
        .collect();
    let joined = lines.join("\n");
    write_c_string(&joined, out)
}

/// Recovers the symmetric session key that encrypts an ASCII-armored
/// message's body, using `cert`'s transport-encryption subkey(s), *without*
/// decrypting the message body itself. Useful for archival/escrow
/// workflows: the recovered session key (as uppercase hex) can be stored or
/// handed to a third party to later decrypt the message via
/// `pgp_decrypt_with_session_key`, without ever exposing `cert`'s long-term
/// secret key material to that party. Writes the session key as an
/// uppercase-hex string to `*session_key_hex` and the RFC 4880 symmetric
/// algorithm code to `*algo` (see `pgp_decrypt_with_session_key`'s doc
/// comment for the encoding). Returns `Failed` if no PKESK packet in the
/// message can be decrypted with any of `cert`'s transport-encryption
/// subkeys.
/// Caller must free `*session_key_hex` with `free()`.
///
/// # Safety
/// `cert`, `armored_message`, `session_key_hex`, and `algo` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_message_session_key(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    session_key_hex: *mut *mut libc::c_char,
    algo: *mut u8,
) -> i32 {
    if cert.is_null() || armored_message.is_null() || session_key_hex.is_null() || algo.is_null()
    {
        return FFIError::Null as i32;
    }
    *session_key_hex = ptr::null_mut();
    *algo = 0;

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = SessionKeyHelper {
        secret: cert,
        policy,
        session_key_hex: None,
        algo: None,
    };
    let decryptor = match DecryptorBuilder::from_bytes(armored_bytes) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(decryptor) => decryptor,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let helper = decryptor.into_helper();
    let hex = match helper.session_key_hex {
        Some(hex) => hex,
        None => return FFIError::Failed as i32,
    };
    *algo = helper.algo.map(u8::from).unwrap_or(0);
    write_c_string(&hex, session_key_hex)
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

/// Decrypt an ASCII-armored message using a session key directly (e.g. one
/// recovered via `pgp_message_session_key`) instead of a certificate's
/// secret key material: no `Certificate` handle is needed at all. `algo` is
/// the RFC 4880 symmetric algorithm code the session key was generated for
/// (7 = AES128, 8 = AES192, 9 = AES256, 10 = Twofish, 3 = CAST5,
/// 4 = Blowfish, 2 = TripleDES, 1 = IDEA: Sequoia's `SymmetricAlgorithm`
/// numeric encoding; pass the value `pgp_message_session_key` wrote to its
/// own `algo` out-parameter to round-trip exactly). `session_key_hex` is an
/// uppercase- or lowercase-hex-encoded byte string of the length that
/// algorithm expects. Caller must free `*plaintext` with `free()`.
///
/// # Safety
/// `session_key_hex`, `armored_message`, and `plaintext` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_with_session_key(
    session_key_hex: *const libc::c_char,
    algo: u8,
    armored_message: *const libc::c_char,
    plaintext: *mut *mut libc::c_char,
) -> i32 {
    if session_key_hex.is_null() || armored_message.is_null() || plaintext.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext = ptr::null_mut();

    let hex_str = match CStr::from_ptr(session_key_hex).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let key_bytes = match hex_to_bytes(hex_str) {
        Some(b) => b,
        None => return FFIError::Invalid as i32,
    };
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = RawSessionKeyHelper {
        session_key: SessionKey::from(key_bytes),
        algo: if algo == 0 { None } else { Some(SymmetricAlgorithm::from(algo)) },
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
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match signer.build() {
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
/// If `signer_fingerprint` is non-null, the fingerprint of the subkey that
/// produced the valid signature is written to `*signer_fingerprint` (caller
/// must free with `free()`). Pass null if the signer identity isn't needed.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `cert`, `armored_message`, and `plaintext` must be non-null.
/// `signer_fingerprint` and `signature_creation_epoch` may be null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_string(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext: *mut *mut libc::c_char,
    signer_fingerprint: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
) -> i32 {
    if cert.is_null() || armored_message.is_null() || plaintext.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext = ptr::null_mut();
    if !signer_fingerprint.is_null() {
        *signer_fingerprint = ptr::null_mut();
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper {
        cert,
        signer_fp: None,
        signature_creation_epoch: None,
    };
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

    let r = write_c_string(&text, plaintext);
    if r != 0 {
        return r;
    }
    let helper = verifier.into_helper();
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }
    if !signer_fingerprint.is_null() {
        if let Some(fp) = helper.signer_fp {
            return write_c_string(&fp, signer_fingerprint);
        }
    }
    FFIError::Ok as i32
}

/// Revoke the cert and write the updated cert to `*revoked_cert`.
///
/// `reason` is an RFC 4880 reason-for-revocation code (0 = unspecified,
/// 1 = superseded, 2 = compromised, 3 = retired); other values are recorded
/// as-is. `message` is an optional human-readable explanation; pass null for
/// none.
///
/// # Safety
/// `cert` and `revoked_cert` must be non-null. `message`, if non-null, must
/// be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke(
    cert: *const Certificate,
    reason: u8,
    message: *const libc::c_char,
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

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let mut signer = match cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes) {
        Ok(b) => match b.build(&mut signer, &cert, None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *revoked_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Report whether `cert` itself has been revoked (via `pgp_certificate_revoke`),
/// and if so, the reason code and message recorded on the revocation
/// signature. `pgp_certificate_subkeys` and `pgp_certificate_userids_info`
/// already report per-subkey/per-user-ID revocation; this is the
/// whole-certificate counterpart.
///
/// Writes `1`/`0` to `*out_revoked`. If revoked, writes the RFC 4880
/// reason-for-revocation code to `*out_reason` (0 otherwise) and the
/// human-readable message to `*out_message` (empty string if none or if not
/// revoked). If multiple revocation signatures are present, the most recent
/// one (Sequoia's own ordering) is reported.
/// Caller must free `*out_message` with `free()`.
///
/// # Safety
/// `cert`, `out_revoked`, `out_reason`, and `out_message` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revocation_info(
    cert: *const Certificate,
    out_revoked: *mut u8,
    out_reason: *mut u8,
    out_message: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || out_revoked.is_null() || out_reason.is_null() || out_message.is_null() {
        return FFIError::Null as i32;
    }
    *out_revoked = 0;
    *out_reason = 0;
    *out_message = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();

    let mut message = String::new();
    if let RevocationStatus::Revoked(sigs) = sequoia_cert.revocation_status(&policy, None) {
        *out_revoked = 1;
        if let Some((code, reason)) = sigs[0].reason_for_revocation() {
            *out_reason = code.into();
            message = String::from_utf8_lossy(reason).into_owned();
        }
    }
    write_c_string(&message, out_message)
}

/// Build a standalone, ASCII-armored revocation certificate for `cert`
/// *without* applying it: the `gpg --gen-revoke` workflow: generate this
/// once (e.g. right after key creation) and store it offline, so the
/// certificate can still be revoked later even if the secret key or its
/// passphrase is subsequently lost. Apply it later with
/// `pgp_certificate_apply_revocation_armored`. Uses the same reason code
/// and message conventions as `pgp_certificate_revoke`.
/// Caller must free `*armored` with `free()`.
///
/// # Safety
/// `cert` and `armored` must be non-null. `message`, if non-null, must be a
/// valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_generate_revocation_armored(
    cert: *const Certificate,
    reason: u8,
    message: *const libc::c_char,
    armored: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || armored.is_null() {
        return FFIError::Null as i32;
    }
    *armored = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = &*wrapper.0;

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let mut signer = match sequoia_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes)
    {
        Ok(b) => match b.build(&mut signer, sequoia_cert, None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let msg = Message::new(&mut out);
    let mut armorer = match Armorer::new(msg).kind(armor::Kind::Signature).build() {
        Ok(a) => a,
        Err(_) => return FFIError::Failed as i32,
    };
    if sequoia_openpgp::serialize::Marshal::serialize(&sig, &mut armorer).is_err() {
        return FFIError::Failed as i32;
    }
    if armorer.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored_string = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored_string, armored)
}

/// Apply a standalone revocation certificate (produced by
/// `pgp_certificate_generate_revocation_armored`, or any other RFC 4880
/// certificate-revocation signature in ASCII armor) to `cert`, writing the
/// now-revoked certificate to `*new_cert`. `cert` itself is left unmodified.
/// Unlike `pgp_certificate_revoke`, this needs no secret key material at
/// all: the signature was already produced when the revocation
/// certificate was generated.
///
/// # Safety
/// `cert`, `revocation_armored`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_apply_revocation_armored(
    cert: *const Certificate,
    revocation_armored: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || revocation_armored.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = (&*wrapper.0).clone();

    let armored_str = match CStr::from_ptr(revocation_armored).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let dearmored = armor::Reader::from_reader(Cursor::new(armored_str), None);
    let sig = match sequoia_openpgp::packet::Signature::from_reader(dearmored) {
        Ok(sig) => sig,
        Err(_) => return FFIError::Invalid as i32,
    };

    let updated = match sequoia_cert.insert_packets(sig) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Designate `revoker_cert` as authorized to revoke `cert` on its behalf:
/// RFC 4880's designated-revoker mechanism (the `gpg --edit-key addrevoker`
/// workflow), a recovery path for when `cert`'s own secret key or
/// passphrase is later lost or compromised. Writes the updated cert,
/// carrying an updated direct-key self-signature listing `revoker_cert` as
/// an authorized revoker, to `*new_cert`; `cert` itself is left unmodified.
/// Once this is applied and published, `revoker_cert`'s own secret key can
/// later revoke `cert` via `pgp_certificate_generate_revocation_armored_by`
/// even without access to `cert`'s secret key at all. `cert`'s
/// certification-capable secret key material must be present and
/// unencrypted; `revoker_cert` need not have any secret key material (only
/// its public key and fingerprint are recorded). Returns `Failed` if `cert`
/// has no direct-key signature to template from: every certificate
/// produced by this library's own `pgp_key_generate*` functions has one.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `cert`, `revoker_cert`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_add_designated_revoker(
    cert: *const Certificate,
    revoker_cert: *const Certificate,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || revoker_cert.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    let revoker_wrapper = &*revoker_cert;
    if wrapper.0.is_null() || revoker_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = (&*wrapper.0).clone();
    let revoker = &*revoker_wrapper.0;

    let policy = StandardPolicy::new();
    let vc = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };
    let template: sequoia_openpgp::packet::signature::SignatureBuilder =
        match vc.direct_key_signature() {
            Ok(sig) => sig.clone().into(),
            Err(_) => return FFIError::Failed as i32,
        };

    let mut signer = match sequoia_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match template
        .set_signature_creation_time(SystemTime::now())
        .and_then(|b| b.set_revocation_key(RevocationKey::from(revoker)))
    {
        Ok(b) => match b.sign_direct_key(&mut signer, None) {
            Ok(s) => s,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match sequoia_cert.insert_packets(sig) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Return one line per designated revoker configured on `cert` (via
/// `pgp_certificate_add_designated_revoker`): `fingerprint\tsensitive`,
/// where `sensitive` is `1`/`0`: RFC 4880's "sensitive revocation key"
/// flag, a hint that implementations should not publish the relationship
/// to keyservers. The list is deduplicated (same convention as Sequoia's
/// own `Cert::revocation_keys`). Writes an empty string if none are
/// configured.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revocation_keys(
    cert: *const Certificate,
    out: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();

    let lines: Vec<String> = sequoia_cert
        .revocation_keys(&policy)
        .map(|rk| {
            let (_, fp) = rk.revoker();
            format!("{}\t{}", fp, if rk.sensitive() { 1 } else { 0 })
        })
        .collect();
    write_c_string(&lines.join("\n"), out)
}

/// Build a standalone, ASCII-armored revocation certificate for
/// `target_cert`, signed by `revoker_cert` rather than by `target_cert`
/// itself: the counterpart to `pgp_certificate_generate_revocation_armored`
/// for a designated revoker (`pgp_certificate_add_designated_revoker`) to
/// use when `target_cert`'s own secret key or passphrase has been lost or
/// compromised. `revoker_cert`'s certification-capable secret key material
/// must be present and unencrypted; `target_cert` need not have any secret
/// key material at all. Apply the resulting signature with the existing
/// `pgp_certificate_apply_revocation_armored`, exactly as with a
/// self-generated revocation certificate: that function does not care who
/// produced the signature, only that it verifies. Uses the same reason code
/// and message conventions as `pgp_certificate_revoke`. This function does
/// not check that `target_cert` actually lists `revoker_cert` as a
/// designated revoker (that check happens on verification, when the
/// revocation is applied and validated against `target_cert`'s own
/// `revocation_keys()`); it only produces the signature.
/// Caller must free `*armored` with `free()`.
///
/// # Safety
/// `revoker_cert`, `target_cert`, and `armored` must be non-null. `message`,
/// if non-null, must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_generate_revocation_armored_by(
    revoker_cert: *const Certificate,
    target_cert: *const Certificate,
    reason: u8,
    message: *const libc::c_char,
    armored: *mut *mut libc::c_char,
) -> i32 {
    if revoker_cert.is_null() || target_cert.is_null() || armored.is_null() {
        return FFIError::Null as i32;
    }
    *armored = ptr::null_mut();

    let revoker_wrapper = &*revoker_cert;
    let target_wrapper = &*target_cert;
    if revoker_wrapper.0.is_null() || target_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let revoker = &*revoker_wrapper.0;
    let target = &*target_wrapper.0;

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let mut signer = match revoker.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes)
    {
        Ok(b) => match b.build(&mut signer, target, None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let mut out = Vec::new();
    let msg = Message::new(&mut out);
    let mut armorer = match Armorer::new(msg).kind(armor::Kind::Signature).build() {
        Ok(a) => a,
        Err(_) => return FFIError::Failed as i32,
    };
    if sequoia_openpgp::serialize::Marshal::serialize(&sig, &mut armorer).is_err() {
        return FFIError::Failed as i32;
    }
    if armorer.finalize().is_err() {
        return FFIError::Failed as i32;
    }

    let armored_string = match String::from_utf8(out) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    write_c_string(&armored_string, armored)
}

/// Cryptographically verify a designated-revoker revocation applied to
/// `target_cert` (e.g. via `pgp_certificate_apply_revocation_armored` with a
/// signature from `pgp_certificate_generate_revocation_armored_by`).
///
/// A revocation signed by a key other than `target_cert`'s own primary key
/// lands in Sequoia's "unconfirmed" revocation bucket (`RevocationStatus::
/// CouldBe`, *not* `Revoked`): `pgp_certificate_revocation_info` and
/// `pgp_certificate_revoke`'s own bookkeeping deliberately do not surface it
/// as revoked, since blindly trusting a signature merely because it claims a
/// given issuer would let anyone forge a "revocation" from a fingerprint they
/// don't control. This function does the two checks needed to actually trust
/// one: (1) `revoker_cert`'s fingerprint is genuinely listed among
/// `target_cert`'s own designated revokers (`pgp_certificate_revocation_keys`
/// / `pgp_certificate_add_designated_revoker`), and (2) the revocation
/// signature verifies cryptographically against `revoker_cert`'s own primary
/// key. Writes `1`/`0` to `*out_verified`. Returns `NotFound` if
/// `target_cert` carries no unconfirmed revocation signature issued by
/// `revoker_cert`'s fingerprint at all.
///
/// # Safety
/// `target_cert`, `revoker_cert`, and `out_verified` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_designated_revocation(
    target_cert: *const Certificate,
    revoker_cert: *const Certificate,
    out_verified: *mut u8,
) -> i32 {
    if target_cert.is_null() || revoker_cert.is_null() || out_verified.is_null() {
        return FFIError::Null as i32;
    }
    *out_verified = 0;

    let target_wrapper = &*target_cert;
    let revoker_wrapper = &*revoker_cert;
    if target_wrapper.0.is_null() || revoker_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let target = &*target_wrapper.0;
    let revoker = &*revoker_wrapper.0;

    let policy = StandardPolicy::new();
    let revoker_handle = KeyHandle::from(revoker.fingerprint());
    let is_designated = target
        .revocation_keys(&policy)
        .any(|rk| *rk.revoker().1 == revoker.fingerprint());
    if !is_designated {
        return FFIError::NotFound as i32;
    }

    let sig = match target.revocation_status(&policy, None) {
        RevocationStatus::CouldBe(sigs) | RevocationStatus::Revoked(sigs) => sigs
            .into_iter()
            .find(|sig| sig.get_issuers().iter().any(|kh| kh.aliases(&revoker_handle))),
        RevocationStatus::NotAsFarAsWeKnow => None,
    };
    let sig = match sig {
        Some(sig) => sig,
        None => return FFIError::NotFound as i32,
    };

    let verified = sig
        .verify_primary_key_revocation(revoker.primary_key().key(), target.primary_key().key())
        .is_ok();
    *out_verified = verified as u8;
    FFIError::Ok as i32
}

/// Set `cert`'s algorithm-preference and features self-signature subpackets
/// (RFC 4880 5.2.3.7-9/17), writing the updated cert to `*new_cert`; `cert`
/// itself is left unmodified. These tell other implementations which
/// symmetric/hash/compression algorithms `cert` supports when they encrypt
/// or sign for it, and which optional OpenPGP features (e.g. SEIPDv2/AEAD)
/// it understands: this crate's own `pgp_key_generate*` functions rely on
/// Sequoia's own defaults for these subpackets, so this is the first way to
/// override them. `sym_algos`/`hash_algos`/`compression_algos` are each a
/// pointer to `*_len` raw one-byte RFC 4880 algorithm codes (Sequoia's
/// `SymmetricAlgorithm`/`HashAlgorithm`/`CompressionAlgorithm` numbering); a
/// zero length is valid and records an empty preference list (distinct from
/// the subpacket being absent). `features` is the raw first octet of the
/// Features subpacket (bit 0 = SEIPDv1, bit 1 = AEAD, bit 2 = SEIPDv2, per
/// Sequoia's `Features` bitfield). All four are set together as one refreshed
/// direct-key self-signature, following the same "template the existing
/// direct-key signature, add subpackets, re-sign" technique as
/// `pgp_certificate_add_designated_revoker`. Returns `Failed` if `cert` has
/// no direct-key signature to template from: every certificate produced by
/// this library's own `pgp_key_generate*` functions has one. `cert`'s
/// certification-capable secret key material must be present and unencrypted.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `cert` and `new_cert` must be non-null. `sym_algos`/`hash_algos`/
/// `compression_algos` must each be non-null with at least `*_len` valid
/// bytes, unless the corresponding length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_set_preferences(
    cert: *const Certificate,
    sym_algos: *const u8,
    sym_algos_len: usize,
    hash_algos: *const u8,
    hash_algos_len: usize,
    compression_algos: *const u8,
    compression_algos_len: usize,
    features: u8,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if cert.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    if (sym_algos.is_null() && sym_algos_len > 0)
        || (hash_algos.is_null() && hash_algos_len > 0)
        || (compression_algos.is_null() && compression_algos_len > 0)
    {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = (&*wrapper.0).clone();

    let raw_slice = |ptr: *const u8, len: usize| -> &[u8] {
        if len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(ptr, len)
        }
    };
    let sym_prefs: Vec<SymmetricAlgorithm> = raw_slice(sym_algos, sym_algos_len)
        .iter()
        .map(|&b| SymmetricAlgorithm::from(b))
        .collect();
    let hash_prefs: Vec<HashAlgorithm> = raw_slice(hash_algos, hash_algos_len)
        .iter()
        .map(|&b| HashAlgorithm::from(b))
        .collect();
    let compression_prefs: Vec<CompressionAlgorithm> = raw_slice(compression_algos, compression_algos_len)
        .iter()
        .map(|&b| CompressionAlgorithm::from(b))
        .collect();

    let policy = StandardPolicy::new();
    let vc = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };
    let template: sequoia_openpgp::packet::signature::SignatureBuilder =
        match vc.direct_key_signature() {
            Ok(sig) => sig.clone().into(),
            Err(_) => return FFIError::Failed as i32,
        };

    let mut signer = match sequoia_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match template
        .set_signature_creation_time(SystemTime::now())
        .and_then(|b| b.set_preferred_symmetric_algorithms(sym_prefs))
        .and_then(|b| b.set_preferred_hash_algorithms(hash_prefs))
        .and_then(|b| b.set_preferred_compression_algorithms(compression_prefs))
        .and_then(|b| b.set_features(Features::new([features])))
    {
        Ok(b) => match b.sign_direct_key(&mut signer, None) {
            Ok(s) => s,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match sequoia_cert.insert_packets(sig) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Read back `cert`'s algorithm-preference and features subpackets (as set by
/// `pgp_certificate_set_preferences`, or Sequoia's own defaults from
/// `pgp_key_generate*` if that has never been called): one line,
/// `sym_algos_csv\thash_algos_csv\tcompression_algos_csv\tfeatures`, where
/// each `*_csv` is a comma-separated list of raw one-byte algorithm codes
/// (empty string if the subpacket is absent or its list is empty) and
/// `features` is the raw Features-subpacket first octet (`0` if absent).
/// Reads from `cert`'s current direct-key signature, so needs no policy
/// decisions beyond validity (same policy/`None`-reference-time convention as
/// every other inspection function in this module).
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_preferences(
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
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();

    let vc = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };
    let sig = match vc.direct_key_signature() {
        Ok(sig) => sig,
        Err(_) => return FFIError::Failed as i32,
    };

    let sym_csv = sig
        .preferred_symmetric_algorithms()
        .map(|algos| {
            algos
                .iter()
                .map(|a| u8::from(*a).to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let hash_csv = sig
        .preferred_hash_algorithms()
        .map(|algos| {
            algos
                .iter()
                .map(|a| u8::from(*a).to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let compression_csv = sig
        .preferred_compression_algorithms()
        .map(|algos| {
            algos
                .iter()
                .map(|a| u8::from(*a).to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let features = sig
        .features()
        .map(|f| f.as_bitfield().as_bytes().first().copied().unwrap_or(0))
        .unwrap_or(0);

    write_c_string(
        &format!("{}\t{}\t{}\t{}", sym_csv, hash_csv, compression_csv, features),
        out,
    )
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

/// Add an authentication subkey, writing the updated cert to `*new_cert`.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_add_authentication_subkey(
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

    let updated = match KeyBuilder::new(KeyFlags::empty().set_authentication()).subkey(vc) {
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
/// `reason` is an RFC 4880 reason-for-revocation code (0 = unspecified,
/// 1 = superseded, 2 = compromised, 3 = retired); other values are recorded
/// as-is. `message` is an optional human-readable explanation; pass null for
/// none.
///
/// # Safety
/// `cert` and `new_cert` must be non-null. `message`, if non-null, must be a
/// valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke_subkey(
    cert: *const Certificate,
    subkey_index: u32,
    reason: u8,
    message: *const libc::c_char,
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

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
    };

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
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes) {
        Ok(b) => match b.build(&mut signer, &cert, subkey.key(), None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok((c, _)) => c,
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
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };
    let updated = match updated.insert_packets(vec![sig]) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Have `signing_cert` certify `user_id` on `target_cert` (a third-party
/// certification, e.g. "Alice vouches that this user ID belongs to Bob"),
/// writing the updated copy of `target_cert`: now carrying `signing_cert`'s
/// certification signature on that user ID: to `*new_cert`. `target_cert`
/// itself is left unmodified; `signing_cert`'s certification-capable secret
/// key material must be present and unencrypted. Returns NotFound if
/// `user_id` is not present on `target_cert`.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `signing_cert`, `target_cert`, `user_id`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_certify_userid(
    signing_cert: *const Certificate,
    target_cert: *const Certificate,
    user_id: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if signing_cert.is_null()
        || target_cert.is_null()
        || user_id.is_null()
        || new_cert.is_null()
    {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let signing_wrapper = &*signing_cert;
    let target_wrapper = &*target_cert;
    if signing_wrapper.0.is_null() || target_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signing_cert = &*signing_wrapper.0;
    let target_cert = (&*target_wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let target_uid = match target_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua.userid().clone(),
        None => return FFIError::NotFound as i32,
    };

    let mut signer = match signing_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match target_uid.certify(&mut signer, &target_cert, None, None, None) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match target_cert.insert_packets(vec![sig]) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Like `pgp_certificate_certify_userid`, but attaches an RFC 4880 Trust
/// Signature subpacket recording delegated trust rather than plain direct
/// certification: the mechanism that lets a certifier be trusted not just
/// to vouch for a user ID, but to introduce *other* trusted certifiers
/// (a certificate authority hierarchy), the piece `certify_userid` alone
/// cannot express. `trust_depth` is the RFC 4880 trust level (0 = the
/// signer isn't trusted to certify further; 1 = the signer is a trusted
/// introducer whose own certifications should be honored; 2+ = the signer
/// can in turn designate further trusted introducers at depth-1). `trust_amount`
/// is the degree of confidence out of 255 (120 conventionally means "fully
/// trusted", 60 "marginally trusted" per the usual "three marginals make one
/// full" web-of-trust convention: but this library does not itself
/// interpret either value, only records and later reports them via
/// `pgp_certificate_userid_certifications`). Otherwise behaves exactly like
/// `pgp_certificate_certify_userid`: writes an updated copy of `target_cert`
/// to `*new_cert`, which is itself left unmodified.
///
/// # Safety
/// `signing_cert`, `target_cert`, `user_id`, and `new_cert` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_certify_userid_with_trust(
    signing_cert: *const Certificate,
    target_cert: *const Certificate,
    user_id: *const libc::c_char,
    trust_depth: u8,
    trust_amount: u8,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if signing_cert.is_null()
        || target_cert.is_null()
        || user_id.is_null()
        || new_cert.is_null()
    {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let signing_wrapper = &*signing_cert;
    let target_wrapper = &*target_cert;
    if signing_wrapper.0.is_null() || target_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signing_cert = &*signing_wrapper.0;
    let target_cert = (&*target_wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let target_uid = match target_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua.userid().clone(),
        None => return FFIError::NotFound as i32,
    };

    let mut signer = match signing_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig_builder = match sequoia_openpgp::packet::signature::SignatureBuilder::new(
        sequoia_openpgp::types::SignatureType::GenericCertification,
    )
    .set_trust_signature(trust_depth, trust_amount)
    {
        Ok(b) => b,
        Err(_) => return FFIError::Failed as i32,
    };
    let sig = match target_uid.bind(&mut signer, &target_cert, sig_builder) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match target_cert.insert_packets(vec![sig]) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Like `pgp_certificate_certify_userid`, but attaches an RFC 4880
/// Exportable Certification subpacket recording whether the certification
/// may be published: GnuPG's `--lsign-key` "local certification" concept.
/// When `exportable` is `0`, `pgp_certificate_export_public_armored` (the
/// entry point meant for sharing a certificate with others) silently omits
/// this certification from its output, while it remains fully present and
/// inspectable (via `pgp_certificate_userid_certifications`) on the
/// in-memory certificate returned here or reloaded from
/// `pgp_certificate_export_secret_armored`. Useful for vouching for a key
/// only within a private, local trust database without that endorsement
/// leaking onto a keyserver. A plain `pgp_certificate_certify_userid`
/// certification is always exportable (RFC 4880 defaults to exportable when
/// the subpacket is absent), so existing callers are unaffected. Otherwise
/// behaves exactly like `pgp_certificate_certify_userid`: writes an updated
/// copy of `target_cert` to `*new_cert`, which is itself left unmodified.
///
/// # Safety
/// `signing_cert`, `target_cert`, `user_id`, and `new_cert` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_certify_userid_exportable(
    signing_cert: *const Certificate,
    target_cert: *const Certificate,
    user_id: *const libc::c_char,
    exportable: u8,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if signing_cert.is_null()
        || target_cert.is_null()
        || user_id.is_null()
        || new_cert.is_null()
    {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let signing_wrapper = &*signing_cert;
    let target_wrapper = &*target_cert;
    if signing_wrapper.0.is_null() || target_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signing_cert = &*signing_wrapper.0;
    let target_cert = (&*target_wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let target_uid = match target_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua.userid().clone(),
        None => return FFIError::NotFound as i32,
    };

    let mut signer = match signing_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig_builder = match sequoia_openpgp::packet::signature::SignatureBuilder::new(
        sequoia_openpgp::types::SignatureType::GenericCertification,
    )
    .set_exportable_certification(exportable != 0)
    {
        Ok(b) => b,
        Err(_) => return FFIError::Failed as i32,
    };
    let sig = match target_uid.bind(&mut signer, &target_cert, sig_builder) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match target_cert.insert_packets(vec![sig]) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Have `signing_cert` revoke its own earlier third-party certification of
/// `user_id` on `target_cert` (the counterpart to
/// `pgp_certificate_certify_userid`), writing the updated copy of
/// `target_cert`: now carrying `signing_cert`'s certification-revocation
/// signature on that user ID: to `*new_cert`. `target_cert` itself is left
/// unmodified; `signing_cert`'s certification-capable secret key material
/// must be present and unencrypted. `reason` is an RFC 4880
/// reason-for-revocation code; `message` is an optional human-readable
/// explanation (pass null for none). Returns NotFound if `user_id` is not
/// present on `target_cert`.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `signing_cert`, `target_cert`, `user_id`, and `new_cert` must be
/// non-null. `message`, if non-null, must be a valid NUL-terminated C
/// string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke_userid_certification(
    signing_cert: *const Certificate,
    target_cert: *const Certificate,
    user_id: *const libc::c_char,
    reason: u8,
    message: *const libc::c_char,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if signing_cert.is_null()
        || target_cert.is_null()
        || user_id.is_null()
        || new_cert.is_null()
    {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let signing_wrapper = &*signing_cert;
    let target_wrapper = &*target_cert;
    if signing_wrapper.0.is_null() || target_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signing_cert = &*signing_wrapper.0;
    let target_cert = (&*target_wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
    };

    let target_uid = match target_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua.userid().clone(),
        None => return FFIError::NotFound as i32,
    };

    let mut signer = match signing_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig = match UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes)
    {
        Ok(b) => match b.build(&mut signer, &target_cert, &target_uid, None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match target_cert.insert_packets(sig) {
        Ok((c, _)) => c,
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
    let message = match Encryptor::for_recipients(message, recipients).build() {
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
/// `reason` is an RFC 4880 reason-for-revocation code (32 = user ID no
/// longer valid, 0 = unspecified); other values are recorded as-is.
/// `message` is an optional human-readable explanation; pass null for none.
///
/// # Safety
/// `cert`, `user_id`, and `new_cert` must be non-null. `message`, if
/// non-null, must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_revoke_userid(
    cert: *const Certificate,
    user_id: *const libc::c_char,
    reason: u8,
    message: *const libc::c_char,
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

    let message_bytes = match revocation_message_bytes(message) {
        Ok(b) => b,
        Err(code) => return code,
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
        .set_reason_for_revocation(ReasonForRevocation::from(reason), message_bytes) {
        Ok(b) => match b.build(&mut signer, &cert, target.userid(), None) {
            Ok(sig) => sig,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match cert.insert_packets(sig) {
        Ok((c, _)) => c,
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

/// Return one line per user ID: `user_id\trevoked\tprimary\texpiry_epoch`,
/// where `revoked` is `1` if that user ID is revoked (`0` otherwise),
/// `primary` is `1` for the certificate's primary user ID (`0` otherwise),
/// and `expiry_epoch` is the expiration of the user ID's *binding
/// signature* (i.e. how long the certification itself is valid for) as
/// seconds since the Unix epoch, or `0` if it doesn't expire. Includes
/// revoked user IDs, same as `pgp_certificate_userids`. `user_id` values
/// are assumed not to contain a tab or newline (true of every user ID this
/// library generates); a user ID crafted to contain one will desynchronize
/// column parsing, same tradeoff `pgp_certificate_userids` already makes.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_userids_info(
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
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();

    let primary_value: Option<Vec<u8>> = sequoia_cert
        .with_policy(&policy, None)
        .ok()
        .and_then(|vc| vc.primary_userid().ok())
        .map(|ua| ua.userid().value().to_vec());

    let lines: Vec<String> = sequoia_cert
        .userids()
        .map(|ua| {
            let user_id = String::from_utf8_lossy(ua.userid().value()).into_owned();
            let is_primary = primary_value.as_deref() == Some(ua.userid().value());
            let mut revoked = false;
            let mut expiry_epoch: i64 = 0;
            if let Ok(vua) = ua.with_policy(&policy, None) {
                revoked = matches!(vua.revocation_status(), RevocationStatus::Revoked(_));
                expiry_epoch = vua
                    .binding_signature()
                    .signature_expiration_time()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
            }
            format!(
                "{}\t{}\t{}\t{}",
                user_id, revoked as u8, is_primary as u8, expiry_epoch
            )
        })
        .collect();
    let joined = lines.join("\n");
    write_c_string(&joined, out)
}

/// Mark `user_id` as the certificate's primary user ID, writing the updated
/// cert to `*new_cert`. Primary-user-ID resolution (as used by
/// `pgp_certificate_userids_info` and every other consumer of Sequoia's
/// policy-validated view) picks the primary-flagged user ID binding with the
/// *newest* signature creation time, so this refreshes `user_id`'s own
/// binding signature with a creation time strictly after every existing user
/// ID binding on the certificate and sets its primary-user-ID flag: it does
/// not touch any other user ID's signatures. Returns NotFound if `user_id`
/// is not present on `cert`. `cert`'s certification-capable secret key
/// material must be present and unencrypted.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `cert`, `user_id`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_set_primary_userid(
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
    let sequoia_cert = (&*wrapper.0).clone();

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let policy = StandardPolicy::new();
    let vc = match sequoia_cert.with_policy(&policy, None) {
        Ok(vc) => vc,
        Err(_) => return FFIError::Failed as i32,
    };

    let ua = match vc
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua,
        None => return FFIError::NotFound as i32,
    };
    let userid = ua.userid().clone();
    let template: sequoia_openpgp::packet::signature::SignatureBuilder =
        ua.binding_signature().clone().into();

    // See the comment above: wait until strictly past every existing user
    // ID's newest binding-signature creation time so the refreshed
    // signature deterministically wins primary-user-ID resolution.
    let newest = vc
        .userids()
        .filter_map(|ua| ua.binding_signature().signature_creation_time())
        .max();
    if let Some(newest) = newest {
        let target = newest + Duration::from_secs(1);
        // Cap the wait so a skewed clock (signature far in the future)
        // cannot hang the call; in that abnormal case we simply proceed,
        // same tradeoff as `pgp_certificate_set_expiry`/`_set_subkey_expiry`.
        loop {
            match target.duration_since(SystemTime::now()) {
                Ok(remaining) if remaining <= Duration::from_secs(2) => {
                    std::thread::sleep(remaining);
                }
                _ => break,
            }
        }
    }

    let mut signer = match sequoia_cert.primary_key().key().clone().parts_into_secret() {
        Ok(k) => match k.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    let sig_builder = match template
        .set_signature_creation_time(SystemTime::now())
        .and_then(|b| b.set_primary_userid(true))
    {
        Ok(b) => b,
        Err(_) => return FFIError::Failed as i32,
    };
    let sig = match userid.bind(&mut signer, &sequoia_cert, sig_builder) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };

    let updated = match sequoia_cert.insert_packets(vec![sequoia_openpgp::Packet::from(sig)]) {
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Return one line per distinct third-party certifier of `user_id`:
/// `issuer_fingerprint\trevoked\ttrust_depth\ttrust_amount`, where
/// `issuer_fingerprint` is the certifying key's fingerprint (from
/// `pgp_certificate_certify_userid`/`_with_trust`) and `revoked` is `1` if
/// that certifier has since revoked their certification via
/// `pgp_certificate_revoke_userid_certification` (`0` otherwise).
/// `trust_depth`/`trust_amount` are the RFC 4880 Trust Signature subpacket
/// values set via `pgp_certificate_certify_userid_with_trust` (both `0` for
/// a plain `pgp_certificate_certify_userid` certification, which carries no
/// such subpacket). `exportable` is `1` unless the certification was made
/// via `pgp_certificate_certify_userid_exportable` with `exportable = 0`
/// (RFC 4880 defaults a certification to exportable when the subpacket is
/// absent). `pgp_certificate_userids_info` only reports
/// self-signature state (primary/revoked/expiry); this is the
/// third-party-certification counterpart. Reports what's attached to the
/// certificate as-is: it does not cryptographically re-verify each
/// signature against the issuer's key (the issuer's certificate isn't
/// available here), matching the trust model of every other inspection
/// function in this module. Returns NotFound if `user_id` is not present on
/// `cert`.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert`, `user_id`, and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_userid_certifications(
    cert: *const Certificate,
    user_id: *const libc::c_char,
    out: *mut *mut libc::c_char,
) -> i32 {
    if cert.is_null() || user_id.is_null() || out.is_null() {
        return FFIError::Null as i32;
    }
    *out = ptr::null_mut();
    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let sequoia_cert = &*wrapper.0;

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let ua = match sequoia_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua,
        None => return FFIError::NotFound as i32,
    };

    let revoked_fingerprints: std::collections::HashSet<String> = ua
        .other_revocations()
        .flat_map(|sig| sig.issuer_fingerprints().map(|fp| fp.to_hex()))
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut lines = Vec::new();
    for sig in ua.certifications() {
        let (trust_depth, trust_amount) = sig.trust_signature().unwrap_or((0, 0));
        let exportable = sig.exportable_certification().unwrap_or(true);
        for fp in sig.issuer_fingerprints() {
            let fp_hex = fp.to_hex();
            if seen.insert(fp_hex.clone()) {
                let revoked = revoked_fingerprints.contains(&fp_hex);
                lines.push(format!(
                    "{}\t{}\t{}\t{}\t{}",
                    fp_hex, revoked as u8, trust_depth, trust_amount, exportable as u8
                ));
            }
        }
    }
    let joined = lines.join("\n");
    write_c_string(&joined, out)
}

/// Cryptographically verify `issuer_cert`'s third-party certification of
/// `user_id` on `target_cert` (as listed by
/// `pgp_certificate_userid_certifications`, which only reports issuer
/// fingerprints without checking the signature itself). Writes `1`/`0` to
/// `*out_verified`. Returns NotFound if `user_id` isn't present on
/// `target_cert`, or if no certification issued by `issuer_cert` is attached
/// to it. Matching prefers the certification signature's `IssuerFingerprint`
/// subpacket, but falls back to the legacy bare-key-ID `Issuer` subpacket
/// (matched against `issuer_cert`'s own key ID) for certifications that
/// carry only that older subpacket and no fingerprint: every certification
/// produced by `pgp_certificate_certify_userid` always carries the
/// fingerprint subpacket, so this fallback only matters for certifications
/// imported from other, older implementations. If `issuer_cert` has
/// certified `user_id` more than once, the first matching certification
/// (Sequoia's own ordering) is the one verified, matching
/// `pgp_certificate_userid_certifications`' listing order.
///
/// # Safety
/// `target_cert`, `issuer_cert`, `user_id`, and `out_verified` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_userid_certification(
    target_cert: *const Certificate,
    issuer_cert: *const Certificate,
    user_id: *const libc::c_char,
    out_verified: *mut u8,
) -> i32 {
    if target_cert.is_null()
        || issuer_cert.is_null()
        || user_id.is_null()
        || out_verified.is_null()
    {
        return FFIError::Null as i32;
    }
    *out_verified = 0;

    let target_wrapper = &*target_cert;
    let issuer_wrapper = &*issuer_cert;
    if target_wrapper.0.is_null() || issuer_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let target_cert = &*target_wrapper.0;
    let issuer_cert = &*issuer_wrapper.0;

    let user_id_str = match CStr::from_ptr(user_id).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };

    let ua = match target_cert
        .userids()
        .find(|ua| ua.userid().value() == user_id_str.as_bytes())
    {
        Some(ua) => ua,
        None => return FFIError::NotFound as i32,
    };

    let issuer_fp = issuer_cert.fingerprint();
    let issuer_keyid = issuer_fp.clone().into();
    let issuer_key = issuer_cert.primary_key().key();
    let target_key = target_cert.primary_key().key();

    let sig = match ua.certifications().find(|sig| {
        sig.issuer_fingerprints().any(|fp| *fp == issuer_fp)
            || (sig.issuer_fingerprints().next().is_none()
                && sig.issuers().any(|keyid| *keyid == issuer_keyid))
    }) {
        Some(sig) => sig,
        None => return FFIError::NotFound as i32,
    };

    *out_verified = sig
        .verify_userid_binding(issuer_key, target_key, ua.userid())
        .is_ok() as u8;
    FFIError::Ok as i32
}

/// Return one line per subkey:
/// `index\tfingerprint\tflags\trevoked\texpiry_epoch`, where `flags` is a
/// comma-separated list of capabilities (`encryption`, `signing`), `revoked`
/// is `1` if the subkey is revoked (`0` otherwise), and `expiry_epoch` is the
/// subkey's own expiration as seconds since the Unix epoch (`0` if it has no
/// expiry, independent of the primary key's or other subkeys' expiry: see
/// `pgp_certificate_set_subkey_expiry`). `index` matches the zero-based
/// `subkey_index` accepted by `pgp_certificate_revoke_subkey` and
/// `pgp_certificate_set_subkey_expiry`, so callers no longer need to guess it.
/// Caller must free `*out` with `free()`.
///
/// # Safety
/// `cert` and `out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_subkeys(
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
    let sequoia_cert = &*wrapper.0;
    let policy = StandardPolicy::new();

    // Indexed the same way as `pgp_certificate_revoke_subkey`
    // (`cert.keys().subkeys().nth(subkey_index)`), so listing and revocation
    // agree on what `index` means.
    let lines: Vec<String> = sequoia_cert
        .keys()
        .subkeys()
        .enumerate()
        .map(|(i, ka)| {
            let fingerprint = ka.key().fingerprint().to_hex();
            let mut flags = Vec::new();
            let mut revoked = false;
            let mut expiry_epoch: i64 = 0;
            if let Ok(vka) = ka.with_policy(&policy, None) {
                if vka.for_transport_encryption() {
                    flags.push("encryption");
                }
                if vka.for_signing() {
                    flags.push("signing");
                }
                if vka.for_authentication() {
                    flags.push("authentication");
                }
                revoked = matches!(vka.revocation_status(), RevocationStatus::Revoked(_));
                expiry_epoch = vka
                    .key_expiration_time()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
            }
            format!(
                "{}\t{}\t{}\t{}\t{}",
                i,
                fingerprint,
                flags.join(","),
                revoked as u8,
                expiry_epoch
            )
        })
        .collect();
    let joined = lines.join("\n");
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
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *out_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Encrypt all currently-unencrypted secret key material in `cert` with
/// `passphrase`, writing a new certificate with locked secrets to
/// `*out_cert`: the counterpart to `pgp_certificate_unlock`. Keys that are
/// already passphrase-protected are left as-is (so this also works to add
/// protection to a mix of locked and unlocked keys), which means calling
/// `lock` again with a different passphrase does *not* change the
/// passphrase on already-locked keys; `unlock` first if you need to rotate
/// an existing passphrase.
///
/// Returns `NotFound` (-4) if `cert` carries no secret material.
///
/// # Safety
/// `cert`, `passphrase`, and `out_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_lock(
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

    // Encrypt each key that currently has unencrypted secret material and
    // re-insert it; keys that are already locked are left untouched.
    let mut packets: Vec<sequoia_openpgp::Packet> = Vec::new();
    for ka in sequoia_cert.keys().secret() {
        let key = ka.key().clone();
        if !key.has_unencrypted_secret() {
            continue;
        }
        let locked = match key.encrypt_secret(&password) {
            Ok(k) => k,
            Err(_) => return FFIError::Failed as i32,
        };
        let packet: sequoia_openpgp::Packet = if ka.primary() {
            locked.role_into_primary().into()
        } else {
            locked.role_into_subordinate().into()
        };
        packets.push(packet);
    }

    let updated = match sequoia_cert.insert_packets(packets) {
        Ok((c, _)) => c,
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
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut message = match signer.detached().build() {
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
/// If `signer_fingerprint` is non-null, the fingerprint of the subkey that
/// produced the valid signature is written to `*signer_fingerprint` (caller
/// must free with `free()`). Pass null if the signer identity isn't needed.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `cert`, `plaintext`, and `armored_sig` must be non-null.
/// `signer_fingerprint` and `signature_creation_epoch` may be null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_detached(
    cert: *const Certificate,
    plaintext: *const libc::c_char,
    armored_sig: *const libc::c_char,
    signer_fingerprint: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
) -> i32 {
    if cert.is_null() || plaintext.is_null() || armored_sig.is_null() {
        return FFIError::Null as i32;
    }
    if !signer_fingerprint.is_null() {
        *signer_fingerprint = ptr::null_mut();
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();
    let sig_bytes = CStr::from_ptr(armored_sig).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper {
        cert,
        signer_fp: None,
        signature_creation_epoch: None,
    };
    let mut verifier = match DetachedVerifierBuilder::from_bytes(sig_bytes) {
        Ok(b) => match b.with_policy(policy, None, helper) {
            Ok(v) => v,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    if verifier.verify_bytes(plaintext_bytes).is_err() {
        return FFIError::Failed as i32;
    }

    let helper = verifier.into_helper();
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }
    if !signer_fingerprint.is_null() {
        if let Some(fp) = helper.signer_fp {
            return write_c_string(&fp, signer_fingerprint);
        }
    }
    FFIError::Ok as i32
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
                    if newest.is_none_or(|n| t > n) {
                        newest = Some(t);
                    }
                }
            }
        }
        for uida in sequoia_cert.userids() {
            for sig in uida.self_signatures() {
                if let Some(t) = sig.signature_creation_time() {
                    if newest.is_none_or(|n| t > n) {
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
        Ok((c, _)) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(updated));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

/// Update the expiry on a single subkey (counting subkeys only, same indexing
/// as `pgp_certificate_revoke_subkey`/`pgp_certificate_subkeys`), leaving the
/// primary key's and every other subkey's expiry untouched.
/// `validity_seconds == 0` clears that subkey's expiry. Writes the updated
/// certificate to `*new_cert`. Caller must free both the original and the
/// returned certificate separately.
///
/// # Safety
/// `cert` and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_set_subkey_expiry(
    cert: *const Certificate,
    subkey_index: u32,
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

    // See the comment in `pgp_certificate_set_expiry`: wait until strictly
    // past the target subkey's newest existing self-signature so the
    // refreshed signature deterministically becomes the active one.
    {
        let newest = match sequoia_cert.keys().subkeys().nth(subkey_index as usize) {
            Some(ka) => ka
                .self_signatures()
                .filter_map(|sig| sig.signature_creation_time())
                .max(),
            None => return FFIError::NotFound as i32,
        };
        if let Some(newest) = newest {
            let target = newest + Duration::from_secs(1);
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

    let ka = match vc.keys().subkeys().nth(subkey_index as usize) {
        Some(ka) => ka,
        None => return FFIError::NotFound as i32,
    };

    let sigs = if ka.for_signing() {
        let sub_key = match ka.key().clone().parts_into_secret() {
            Ok(k) => k,
            Err(_) => return FFIError::Invalid as i32,
        };
        let mut sub_signer = match sub_key.into_keypair() {
            Ok(kp) => kp,
            Err(_) => return FFIError::Failed as i32,
        };
        match ka.set_expiration_time(&mut primary_signer, Some(&mut sub_signer), expiry) {
            Ok(sigs) => sigs,
            Err(_) => return FFIError::Failed as i32,
        }
    } else {
        match ka.set_expiration_time(&mut primary_signer, None, expiry) {
            Ok(sigs) => sigs,
            Err(_) => return FFIError::Failed as i32,
        }
    };

    let packets: Vec<sequoia_openpgp::Packet> =
        sigs.into_iter().map(sequoia_openpgp::Packet::from).collect();
    let updated = match sequoia_cert.insert_packets(packets) {
        Ok((c, _)) => c,
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
    signature_creation_epoch: Option<i64>,
}

impl VerificationHelper for DecryptAndVerifyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(vec![self.verify_cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut found = false;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                if let Some(good) = results.into_iter().flatten().next() {
                    self.signer_fp = Some(good.ka.key().fingerprint().to_hex());
                    self.signature_creation_epoch = good
                        .sig
                        .signature_creation_time()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64);
                    found = true;
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
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
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
                    return Ok(Some(self.decrypt_cert.clone()));
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
    let message = match Encryptor::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match signer.build() {
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
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `decrypt_cert`, `verify_cert`, `armored_message`, `plaintext_out`, and
/// `fingerprint_out` must be non-null. `signature_creation_epoch` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_and_verify_string(
    decrypt_cert: *const Certificate,
    verify_cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
    fingerprint_out: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
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
        signature_creation_epoch: None,
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
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }

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
    let message = match Encryptor::for_recipients(message, recipients).build() {
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
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match signer.build() {
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
/// If `signer_fingerprint` is non-null, the fingerprint of the subkey that
/// produced the valid signature is written to `*signer_fingerprint` (caller
/// must free with `free()`). Pass null if the signer identity isn't needed.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `cert`, `armored_message`, `plaintext_out`, and `plaintext_len` must be
/// non-null. `signer_fingerprint` and `signature_creation_epoch` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_bytes(
    cert: *const Certificate,
    armored_message: *const libc::c_char,
    plaintext_out: *mut *mut u8,
    plaintext_len: *mut usize,
    signer_fingerprint: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
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
    if !signer_fingerprint.is_null() {
        *signer_fingerprint = ptr::null_mut();
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper {
        cert,
        signer_fp: None,
        signature_creation_epoch: None,
    };
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

    let r = write_bytes_buffer(&out, plaintext_out, plaintext_len);
    if r != 0 {
        return r;
    }
    let helper = verifier.into_helper();
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }
    if !signer_fingerprint.is_null() {
        if let Some(fp) = helper.signer_fp {
            return write_c_string(&fp, signer_fingerprint);
        }
    }
    FFIError::Ok as i32
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
    let message = match Encryptor::for_recipients(message, recipients).build() {
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
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let mut signer = match signer.cleartext().build() {
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
/// If `signer_fingerprint` is non-null, the fingerprint of the subkey that
/// produced the valid signature is written to `*signer_fingerprint` (caller
/// must free with `free()`). Pass null if the signer identity isn't needed.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `cert`, `signed_message`, and `plaintext_out` must be non-null.
/// `signer_fingerprint` and `signature_creation_epoch` may be null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_verify_cleartext(
    cert: *const Certificate,
    signed_message: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
    signer_fingerprint: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
) -> i32 {
    if cert.is_null() || signed_message.is_null() || plaintext_out.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();
    if !signer_fingerprint.is_null() {
        *signer_fingerprint = ptr::null_mut();
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;
    let msg_bytes = CStr::from_ptr(signed_message).to_bytes();

    let policy = &StandardPolicy::new();
    let helper = VerifyHelper {
        cert,
        signer_fp: None,
        signature_creation_epoch: None,
    };
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
    let r = write_c_string(&text, plaintext_out);
    if r != 0 {
        return r;
    }
    let helper = verifier.into_helper();
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }
    if !signer_fingerprint.is_null() {
        if let Some(fp) = helper.signer_fp {
            return write_c_string(&fp, signer_fingerprint);
        }
    }
    FFIError::Ok as i32
}

// -- Feature 4: Symmetric encryption (passphrase-only)

struct SymmetricDecryptHelper {
    password: Password,
}

impl VerificationHelper for SymmetricDecryptHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for SymmetricDecryptHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
        for skesk in skesks {
            if let Ok((algo, session_key)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &session_key) {
                    return Ok(None);
                }
            }
        }
        Err(anyhow::anyhow!("Bad passphrase or no SKESK"))
    }
}

/// Encrypt `plaintext` with `passphrase` (no public key required), writing an
/// ASCII-armored message to `*armored_message`. Caller must free
/// `*armored_message` with `free()`.
///
/// # Safety
/// `plaintext`, `passphrase`, and `armored_message` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_string_symmetric(
    plaintext: *const libc::c_char,
    passphrase: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if plaintext.is_null() || passphrase.is_null() || armored_message.is_null() {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();
    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let password: Password = passphrase_str.into();

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor::with_passwords(message, Some(password)).build() {
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

/// Decrypt an ASCII-armored passphrase-encrypted message, writing plaintext to
/// `*plaintext_out`. Caller must free `*plaintext_out` with `free()`.
///
/// Returns `Failed` (-3) if the passphrase is wrong or the message has no SKESK.
///
/// # Safety
/// `armored_message`, `passphrase`, and `plaintext_out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_string_symmetric(
    armored_message: *const libc::c_char,
    passphrase: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
) -> i32 {
    if armored_message.is_null() || passphrase.is_null() || plaintext_out.is_null() {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();

    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();
    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let password: Password = passphrase_str.into();

    let policy = &StandardPolicy::new();
    let helper = SymmetricDecryptHelper { password };

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
    write_c_string(&text, plaintext_out)
}

struct SymmetricDecryptAndVerifyHelper<'a> {
    password: Password,
    verify_cert: &'a SequoiaCert,
    signer_fp: Option<String>,
    signature_creation_epoch: Option<i64>,
}

impl VerificationHelper for SymmetricDecryptAndVerifyHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<SequoiaCert>> {
        Ok(vec![self.verify_cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let mut found = false;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                if let Some(good) = results.into_iter().flatten().next() {
                    self.signer_fp = Some(good.ka.key().fingerprint().to_hex());
                    self.signature_creation_epoch = good
                        .sig
                        .signature_creation_time()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64);
                    found = true;
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

impl DecryptionHelper for SymmetricDecryptAndVerifyHelper<'_> {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<SequoiaCert>> {
        for skesk in skesks {
            if let Ok((algo, session_key)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &session_key) {
                    return Ok(None);
                }
            }
        }
        Err(anyhow::anyhow!("Bad passphrase or no SKESK"))
    }
}

/// Sign `plaintext` with `signer_cert` and encrypt it with `passphrase` (no
/// recipient public key required), writing a single ASCII-armored message to
/// `*armored_message`: the passphrase-only counterpart to
/// `pgp_encrypt_and_sign_string`. Caller must free `*armored_message` with
/// `free()`.
///
/// # Safety
/// `signer_cert`, `plaintext`, `passphrase`, and `armored_message` must be
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_and_sign_string_symmetric(
    signer_cert: *const Certificate,
    plaintext: *const libc::c_char,
    passphrase: *const libc::c_char,
    armored_message: *mut *mut libc::c_char,
) -> i32 {
    if signer_cert.is_null()
        || plaintext.is_null()
        || passphrase.is_null()
        || armored_message.is_null()
    {
        return FFIError::Null as i32;
    }
    *armored_message = ptr::null_mut();

    let signer_wrapper = &*signer_cert;
    if signer_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signer_cert_ref = &*signer_wrapper.0;
    let plaintext_bytes = CStr::from_ptr(plaintext).to_bytes();
    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let password: Password = passphrase_str.into();

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

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match Encryptor::with_passwords(message, Some(password)).build() {
        Ok(m) => m,
        Err(_) => return FFIError::Failed as i32,
    };
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => return FFIError::Failed as i32,
    };
    let message = match signer.build() {
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

/// Decrypt a passphrase-encrypted, signed ASCII-armored message and verify
/// its signature against `verify_cert`: the passphrase-only counterpart to
/// `pgp_decrypt_and_verify_string`. Writes the plaintext to `*plaintext_out`
/// and the signer's fingerprint to `*fingerprint_out`; both must be freed
/// with `free()`. Returns `Failed` (-3) if the passphrase is wrong, the
/// message has no SKESK, or it carries no valid signature.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `verify_cert`, `armored_message`, `passphrase`, `plaintext_out`, and
/// `fingerprint_out` must be non-null. `signature_creation_epoch` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_and_verify_string_symmetric(
    verify_cert: *const Certificate,
    armored_message: *const libc::c_char,
    passphrase: *const libc::c_char,
    plaintext_out: *mut *mut libc::c_char,
    fingerprint_out: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
) -> i32 {
    if verify_cert.is_null()
        || armored_message.is_null()
        || passphrase.is_null()
        || plaintext_out.is_null()
        || fingerprint_out.is_null()
    {
        return FFIError::Null as i32;
    }
    *plaintext_out = ptr::null_mut();
    *fingerprint_out = ptr::null_mut();

    let verify_wrapper = &*verify_cert;
    if verify_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let verify_cert_ref = &*verify_wrapper.0;
    let armored_bytes = CStr::from_ptr(armored_message).to_bytes();
    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return FFIError::Invalid as i32,
    };
    let password: Password = passphrase_str.into();

    let policy = &StandardPolicy::new();
    let helper = SymmetricDecryptAndVerifyHelper {
        password,
        verify_cert: verify_cert_ref,
        signer_fp: None,
        signature_creation_epoch: None,
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
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }

    let r = write_c_string(&text, plaintext_out);
    if r != 0 {
        return r;
    }
    let r = write_c_string(&fp, fingerprint_out);
    if r != 0 {
        libc::free(*plaintext_out as *mut libc::c_void);
        *plaintext_out = ptr::null_mut();
    }
    r
}

/// Merge updates from `other_cert` into `base_cert`: new signatures,
/// certifications, subkeys, and revocations: writing the combined
/// certificate to `*new_cert`. This is the counterpart to importing a
/// refreshed copy of a certificate (e.g. from a keyserver or a peer) without
/// discarding what's already known locally: any packet present in either
/// input ends up in the result, and duplicate signatures are collapsed by
/// Sequoia's own merge logic rather than blindly concatenated.
///
/// Both certificates must have the same primary-key fingerprint; merging two
/// unrelated certificates fails with `Failed` (-3). Secret key material on
/// `other_cert` is always discarded: this operation is meant for importing
/// data from a source that shouldn't be trusted with key material: so only
/// `base_cert`'s own secret key (if any) survives into `*new_cert`. Neither
/// input certificate is modified.
/// Caller must free `*new_cert` with `pgp_certificate_free`.
///
/// # Safety
/// `base_cert`, `other_cert`, and `new_cert` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_merge(
    base_cert: *const Certificate,
    other_cert: *const Certificate,
    new_cert: *mut *mut Certificate,
) -> i32 {
    if base_cert.is_null() || other_cert.is_null() || new_cert.is_null() {
        return FFIError::Null as i32;
    }
    *new_cert = ptr::null_mut();

    let base_wrapper = &*base_cert;
    let other_wrapper = &*other_cert;
    if base_wrapper.0.is_null() || other_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let base = (&*base_wrapper.0).clone();
    let other = (&*other_wrapper.0).clone();

    let merged = match base.merge_public(other) {
        Ok(c) => c,
        Err(_) => return FFIError::Failed as i32,
    };

    let inner = Box::into_raw(Box::new(merged));
    *new_cert = Box::into_raw(Box::new(Certificate(inner)));
    FFIError::Ok as i32
}

// -- Feature: File-based streaming operations
//
// Every other encrypt/decrypt/sign/verify entry point takes its plaintext or
// ciphertext as an in-memory string or byte buffer, requiring the whole
// message to already be resident in RAM on both sides of the FFI boundary
// (and, on the Dart side, copied into a `Uint8List`). That's fine for chat
// messages but breaks down for anything approaching the size of a file
// backup: a multi-gigabyte input would need multiple times its own size in
// spare memory just to encrypt it. These entry points instead take input and
// output file paths and stream the data straight from/to disk through
// Sequoia's own `Read`/`Write`-based streaming API, so peak memory use stays
// bounded regardless of file size.
//
// If an error occurs partway through, any output file already created is
// removed rather than left behind as a truncated, unusable partial result.

/// Remove `path` best-effort, ignoring errors (used to clean up a partially
/// written output file after a mid-stream failure).
fn remove_partial_output(path: &str) {
    let _ = std::fs::remove_file(path);
}

/// Encrypt the file at `input_path` to `cert` and write an ASCII-armored
/// message to `output_path`, streaming through the filesystem so the
/// plaintext is never held in memory as a single buffer. See the
/// "File-based streaming operations" section comment for why this exists
/// alongside `pgp_certificate_encrypt_bytes`/`_string`.
///
/// # Safety
/// `cert`, `input_path`, and `output_path` must be non-null, NUL-terminated,
/// valid UTF-8 paths.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_encrypt_file(
    cert: *const Certificate,
    input_path: *const libc::c_char,
    output_path: *const libc::c_char,
) -> i32 {
    if cert.is_null() || input_path.is_null() || output_path.is_null() {
        return FFIError::Null as i32;
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;

    let input_path = match path_str(input_path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let output_path = match path_str(output_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut input = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return FFIError::NotFound as i32,
    };
    let output = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return FFIError::Failed as i32,
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

    let message = Message::new(BufWriter::new(output));
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let message = match Encryptor::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };

    if std::io::copy(&mut input, &mut message).is_err() || message.finalize().is_err() {
        remove_partial_output(output_path);
        return FFIError::Failed as i32;
    }

    FFIError::Ok as i32
}

/// Decrypt the ASCII-armored message at `input_path` using `cert` and write
/// the raw plaintext to `output_path`, streaming through the filesystem. See
/// the "File-based streaming operations" section comment.
///
/// # Safety
/// `cert`, `input_path`, and `output_path` must be non-null, NUL-terminated,
/// valid UTF-8 paths.
#[no_mangle]
pub unsafe extern "C" fn pgp_certificate_decrypt_file(
    cert: *const Certificate,
    input_path: *const libc::c_char,
    output_path: *const libc::c_char,
) -> i32 {
    if cert.is_null() || input_path.is_null() || output_path.is_null() {
        return FFIError::Null as i32;
    }

    let wrapper = &*cert;
    if wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let cert = &*wrapper.0;

    let input_path = match path_str(input_path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let output_path = match path_str(output_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut output = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return FFIError::Failed as i32,
    };

    let policy = &StandardPolicy::new();
    let helper = DecryptOnlyHelper {
        secret: cert,
        policy,
    };
    let mut decryptor = match DecryptorBuilder::from_file(input_path) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(d) => d,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    if std::io::copy(&mut decryptor, &mut output).is_err() {
        remove_partial_output(output_path);
        return FFIError::Failed as i32;
    }

    FFIError::Ok as i32
}

/// Encrypt the file at `input_path` to all `count` recipient certificates,
/// streaming the result to `output_path`. Any recipient whose private key is
/// available can decrypt. The file-based counterpart of
/// `pgp_encrypt_string_to_recipients`; see the "File-based streaming
/// operations" section comment for why this exists alongside
/// `pgp_certificate_encrypt_file` (which only supports a single recipient).
///
/// # Safety
/// `recipient_certs`, `input_path`, and `output_path` must be non-null; each
/// element of `recipient_certs` must be a valid Certificate pointer.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_to_recipients_file(
    recipient_certs: *const *const Certificate,
    count: usize,
    input_path: *const libc::c_char,
    output_path: *const libc::c_char,
) -> i32 {
    if recipient_certs.is_null() || input_path.is_null() || output_path.is_null() {
        return FFIError::Null as i32;
    }
    if count == 0 {
        return FFIError::NotFound as i32;
    }

    let input_path = match path_str(input_path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let output_path = match path_str(output_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut input = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return FFIError::NotFound as i32,
    };
    let output = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return FFIError::Failed as i32,
    };

    let policy = &StandardPolicy::new();

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

    let message = Message::new(BufWriter::new(output));
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let message = match Encryptor::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };

    if std::io::copy(&mut input, &mut message).is_err() || message.finalize().is_err() {
        remove_partial_output(output_path);
        return FFIError::Failed as i32;
    }

    FFIError::Ok as i32
}

/// Encrypt the file at `input_path` to all `count` recipient certificates and
/// sign it with `signer_cert`, streaming the result to `output_path`. The
/// file-based counterpart of `pgp_encrypt_and_sign_string`; see the
/// "File-based streaming operations" section comment.
///
/// # Safety
/// `signer_cert`, `recipient_certs`, `input_path`, and `output_path` must be
/// non-null; each element of `recipient_certs` must be a valid Certificate
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn pgp_encrypt_and_sign_file(
    signer_cert: *const Certificate,
    recipient_certs: *const *const Certificate,
    count: usize,
    input_path: *const libc::c_char,
    output_path: *const libc::c_char,
) -> i32 {
    if signer_cert.is_null()
        || recipient_certs.is_null()
        || input_path.is_null()
        || output_path.is_null()
    {
        return FFIError::Null as i32;
    }
    if count == 0 {
        return FFIError::NotFound as i32;
    }

    let signer_wrapper = &*signer_cert;
    if signer_wrapper.0.is_null() {
        return FFIError::Invalid as i32;
    }
    let signer_cert_ref = &*signer_wrapper.0;

    let input_path = match path_str(input_path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let output_path = match path_str(output_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut input = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return FFIError::NotFound as i32,
    };
    let output = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return FFIError::Failed as i32,
    };

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

    let message = Message::new(BufWriter::new(output));
    let message = match Armorer::new(message).kind(armor::Kind::Message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let message = match Encryptor::for_recipients(message, recipients).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let signer = match Signer::new(message, keypair) {
        Ok(s) => s,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let message = match signer.build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    let mut message = match LiteralWriter::new(message).build() {
        Ok(m) => m,
        Err(_) => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };

    if std::io::copy(&mut input, &mut message).is_err() || message.finalize().is_err() {
        remove_partial_output(output_path);
        return FFIError::Failed as i32;
    }

    FFIError::Ok as i32
}

/// Decrypt the ASCII-armored message at `input_path` with `decrypt_cert` and
/// verify its signature against `verify_cert`, streaming the plaintext to
/// `output_path`. Writes the signer's fingerprint to `*fingerprint_out`
/// (caller must free with `free()`). Returns `Failed` (-3) if the message
/// carries no valid signature. The file-based counterpart of
/// `pgp_decrypt_and_verify_string`; see the "File-based streaming operations"
/// section comment.
///
/// If `signature_creation_epoch` is non-null, the signature's own creation
/// time is written to `*signature_creation_epoch` as seconds since the Unix
/// epoch (0 if absent). Pass null if not needed.
///
/// # Safety
/// `decrypt_cert`, `verify_cert`, `input_path`, `output_path`, and
/// `fingerprint_out` must be non-null. `signature_creation_epoch` may be
/// null.
#[no_mangle]
pub unsafe extern "C" fn pgp_decrypt_and_verify_file(
    decrypt_cert: *const Certificate,
    verify_cert: *const Certificate,
    input_path: *const libc::c_char,
    output_path: *const libc::c_char,
    fingerprint_out: *mut *mut libc::c_char,
    signature_creation_epoch: *mut i64,
) -> i32 {
    if decrypt_cert.is_null()
        || verify_cert.is_null()
        || input_path.is_null()
        || output_path.is_null()
        || fingerprint_out.is_null()
    {
        return FFIError::Null as i32;
    }
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

    let input_path = match path_str(input_path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let output_path = match path_str(output_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let mut output = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return FFIError::Failed as i32,
    };

    let policy = &StandardPolicy::new();
    let helper = DecryptAndVerifyHelper {
        decrypt_cert: decrypt_cert_ref,
        verify_cert: verify_cert_ref,
        policy,
        signer_fp: None,
        signature_creation_epoch: None,
    };

    let mut decryptor = match DecryptorBuilder::from_file(input_path) {
        Ok(builder) => match builder.with_policy(policy, None, helper) {
            Ok(d) => d,
            Err(_) => return FFIError::Failed as i32,
        },
        Err(_) => return FFIError::Invalid as i32,
    };

    if std::io::copy(&mut decryptor, &mut output).is_err() {
        remove_partial_output(output_path);
        return FFIError::Failed as i32;
    }

    let helper = decryptor.into_helper();
    let fp = match helper.signer_fp {
        Some(fp) => fp,
        None => {
            remove_partial_output(output_path);
            return FFIError::Failed as i32;
        }
    };
    if !signature_creation_epoch.is_null() {
        *signature_creation_epoch = helper.signature_creation_epoch.unwrap_or(0);
    }

    write_c_string(&fp, fingerprint_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe fn generate_cert(user_id: &str) -> *mut Certificate {
        let c_user_id = CString::new(user_id).unwrap();
        let mut cert: *mut Certificate = ptr::null_mut();
        let rc = pgp_key_generate(c_user_id.as_ptr(), &mut cert);
        assert_eq!(rc, FFIError::Ok as i32);
        assert!(!cert.is_null());
        cert
    }

    /// A path in the OS temp directory guaranteed unique for the lifetime of
    /// the test process, so parallel `#[test]`s never collide on the same
    /// file.
    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pgp-ffi-test-{}-{}-{}",
            std::process::id(),
            n,
            label
        ))
    }

    // --- null-pointer handling ---

    #[test]
    fn pgp_free_accepts_null_and_output_buffers() {
        unsafe {
            pgp_free(ptr::null_mut());
            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(write_c_string("x", &mut out), 0);
            pgp_free(out.cast());
        }
    }

    #[test]
    fn certificate_free_accepts_null() {
        unsafe {
            // Must not crash.
            pgp_certificate_free(ptr::null_mut());
        }
    }

    #[test]
    fn from_armored_rejects_null_armored() {
        unsafe {
            let mut cert: *mut Certificate = ptr::null_mut();
            let rc = pgp_certificate_from_armored(ptr::null(), &mut cert);
            assert_eq!(rc, FFIError::Null as i32);
        }
    }

    #[test]
    fn from_armored_rejects_null_out_param() {
        unsafe {
            let armored = CString::new("garbage").unwrap();
            let rc = pgp_certificate_from_armored(armored.as_ptr(), ptr::null_mut());
            assert_eq!(rc, FFIError::Null as i32);
        }
    }

    #[test]
    fn key_generate_rejects_null_user_id() {
        unsafe {
            let mut cert: *mut Certificate = ptr::null_mut();
            let rc = pgp_key_generate(ptr::null(), &mut cert);
            assert_eq!(rc, FFIError::Null as i32);
        }
    }

    #[test]
    fn key_generate_rejects_null_out_param() {
        unsafe {
            let user_id = CString::new("null-out@example.org").unwrap();
            let rc = pgp_key_generate(user_id.as_ptr(), ptr::null_mut());
            assert_eq!(rc, FFIError::Null as i32);
        }
    }

    #[test]
    fn key_generate_with_cipher_suite_produces_requested_algorithm() {
        unsafe {
            let user_id = CString::new("rsa-key@example.org").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_key_generate_with_cipher_suite(user_id.as_ptr(), 5, &mut cert),
                FFIError::Ok as i32
            );
            assert!(!cert.is_null());

            let sequoia_cert = &*(&*cert).0;
            assert_eq!(
                sequoia_cert.primary_key().key().pk_algo(),
                sequoia_openpgp::types::PublicKeyAlgorithm::RSAEncryptSign
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn key_generate_with_cipher_suite_defaults_match_key_generate() {
        unsafe {
            let user_id = CString::new("cv25519-key@example.org").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_key_generate_with_cipher_suite(user_id.as_ptr(), 0, &mut cert),
                FFIError::Ok as i32
            );
            assert!(!cert.is_null());

            let sequoia_cert = &*(&*cert).0;
            assert_eq!(
                sequoia_cert.primary_key().key().pk_algo(),
                sequoia_openpgp::types::PublicKeyAlgorithm::EdDSA
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn key_generate_with_cipher_suite_rejects_out_of_range_code() {
        unsafe {
            let user_id = CString::new("bad-suite@example.org").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_key_generate_with_cipher_suite(user_id.as_ptr(), 7, &mut cert),
                FFIError::Invalid as i32
            );
            assert!(cert.is_null());
        }
    }

    #[test]
    fn key_generate_with_cipher_suite_rejects_null_args() {
        unsafe {
            let user_id = CString::new("null-suite@example.org").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_key_generate_with_cipher_suite(ptr::null(), 0, &mut cert),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_key_generate_with_cipher_suite(user_id.as_ptr(), 0, ptr::null_mut()),
                FFIError::Null as i32
            );
        }
    }

    #[test]
    fn export_public_armored_rejects_null_cert() {
        unsafe {
            let mut out: *mut libc::c_char = ptr::null_mut();
            let rc = pgp_certificate_export_public_armored(ptr::null(), &mut out);
            assert_eq!(rc, FFIError::Null as i32);
        }
    }

    #[test]
    fn fingerprint_rejects_null_out_param() {
        unsafe {
            let cert = generate_cert("fingerprint-null-out@example.org");
            let rc = pgp_certificate_fingerprint(cert, ptr::null_mut());
            assert_eq!(rc, FFIError::Null as i32);
            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn encrypt_string_rejects_null_plaintext() {
        unsafe {
            let cert = generate_cert("encrypt-null@example.org");
            let mut out: *mut libc::c_char = ptr::null_mut();
            let rc = pgp_certificate_encrypt_string(cert, ptr::null(), &mut out);
            assert_eq!(rc, FFIError::Null as i32);
            pgp_certificate_free(cert);
        }
    }

    // --- error-code correctness on malformed input ---

    #[test]
    fn from_armored_rejects_garbage_text() {
        unsafe {
            let armored = CString::new("this is not a pgp certificate").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            let rc = pgp_certificate_from_armored(armored.as_ptr(), &mut cert);
            assert_eq!(rc, FFIError::Invalid as i32);
            assert!(cert.is_null());
        }
    }

    #[test]
    fn from_armored_rejects_empty_string() {
        unsafe {
            let armored = CString::new("").unwrap();
            let mut cert: *mut Certificate = ptr::null_mut();
            let rc = pgp_certificate_from_armored(armored.as_ptr(), &mut cert);
            assert_eq!(rc, FFIError::Invalid as i32);
        }
    }

    #[test]
    fn from_armored_rejects_truncated_valid_cert() {
        unsafe {
            let cert = generate_cert("truncated@example.org");
            let mut armored: *mut libc::c_char = ptr::null_mut();
            let rc = pgp_certificate_export_public_armored(cert, &mut armored);
            assert_eq!(rc, FFIError::Ok as i32);
            pgp_certificate_free(cert);

            let full = CStr::from_ptr(armored).to_str().unwrap().to_owned();
            libc::free(armored as *mut libc::c_void);

            let truncated = &full[..full.len() / 2];
            let truncated_c = CString::new(truncated).unwrap();
            let mut parsed: *mut Certificate = ptr::null_mut();
            let rc = pgp_certificate_from_armored(truncated_c.as_ptr(), &mut parsed);
            assert_eq!(rc, FFIError::Invalid as i32);
        }
    }

    #[test]
    fn key_generate_rejects_non_utf8_user_id() {
        unsafe {
            // A lone continuation byte is invalid UTF-8 but a valid, NUL-terminated
            // C string.
            let invalid_utf8 = [0x80u8, 0x00];
            let mut cert: *mut Certificate = ptr::null_mut();
            let rc = pgp_key_generate(invalid_utf8.as_ptr() as *const libc::c_char, &mut cert);
            assert_eq!(rc, FFIError::Invalid as i32);
        }
    }

    #[test]
    fn fingerprint_on_zeroed_wrapper_is_invalid() {
        unsafe {
            // A `Certificate` whose inner pointer is null (as opposed to the
            // wrapper pointer itself) should be reported as invalid, not
            // dereferenced.
            let wrapper = Box::into_raw(Box::new(Certificate(ptr::null_mut())));
            let mut out: *mut libc::c_char = ptr::null_mut();
            let rc = pgp_certificate_fingerprint(wrapper, &mut out);
            assert_eq!(rc, FFIError::Invalid as i32);
            assert!(out.is_null());
            drop(Box::from_raw(wrapper));
        }
    }

    // --- opaque Certificate handle lifecycle ---

    #[test]
    fn generate_export_reparse_free_round_trip() {
        unsafe {
            let cert = generate_cert("round-trip@example.org");

            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_export_public_armored(cert, &mut armored),
                FFIError::Ok as i32
            );
            assert!(!armored.is_null());

            let mut fingerprint_before: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(cert, &mut fingerprint_before),
                FFIError::Ok as i32
            );

            let mut reparsed: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_from_armored(armored, &mut reparsed),
                FFIError::Ok as i32
            );
            assert!(!reparsed.is_null());

            let mut fingerprint_after: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(reparsed, &mut fingerprint_after),
                FFIError::Ok as i32
            );

            assert_eq!(
                CStr::from_ptr(fingerprint_before),
                CStr::from_ptr(fingerprint_after)
            );

            libc::free(armored as *mut libc::c_void);
            libc::free(fingerprint_before as *mut libc::c_void);
            libc::free(fingerprint_after as *mut libc::c_void);
            pgp_certificate_free(cert);
            pgp_certificate_free(reparsed);
        }
    }

    #[test]
    fn freeing_one_handle_does_not_affect_independent_handles() {
        unsafe {
            let a = generate_cert("independent-a@example.org");
            let b = generate_cert("independent-b@example.org");

            pgp_certificate_free(a);

            // `b` must remain fully usable after an unrelated handle is freed.
            let mut fp: *mut libc::c_char = ptr::null_mut();
            let rc = pgp_certificate_fingerprint(b, &mut fp);
            assert_eq!(rc, FFIError::Ok as i32);
            assert!(!fp.is_null());

            libc::free(fp as *mut libc::c_void);
            pgp_certificate_free(b);
        }
    }

    /// Double-freeing a `Certificate` handle is undefined behavior by design
    /// (the FFI contract puts the burden of "free exactly once" on the
    /// caller, matching `free()`). We can't assert on UB directly, so this
    /// runs the double-free in a child process and asserts the process
    /// aborts instead of silently corrupting memory: documenting the
    /// contract without risking the test harness itself.
    #[test]
    fn double_free_aborts_child_process() {
        const CHILD_ENV: &str = "PGP_FFI_TEST_DOUBLE_FREE_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            unsafe {
                let cert = generate_cert("double-free@example.org");
                pgp_certificate_free(cert);
                pgp_certificate_free(cert);
            }
            return;
        }

        let exe = std::env::current_exe().expect("locate current test binary");
        let output = std::process::Command::new(exe)
            .args(["--test-threads=1", "double_free_aborts_child_process"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child test process");

        assert!(
            !output.status.success(),
            "expected double-free to abort the child process; it exited with {:?}",
            output.status
        );
    }

    /// Reading through a freed `Certificate` handle is undefined behavior,
    /// but unlike double-free it isn't reliably caught by the stable
    /// allocator alone: freed memory often isn't overwritten immediately,
    /// so the read can silently "succeed" and the test would be flaky.
    /// AddressSanitizer poisons freed allocations and aborts on this read
    /// deterministically, so this test is `#[ignore]`d for normal runs and
    /// only exercised by the `asan` CI job (see `pgp-ffi-release.yml`).
    #[test]
    #[ignore = "UAF reads aren't reliably caught without ASan; run via the `asan` CI job"]
    fn use_after_free_detected_under_asan() {
        unsafe {
            let cert = generate_cert("uaf@example.org");
            pgp_certificate_free(cert);

            let mut fingerprint: *mut libc::c_char = ptr::null_mut();
            let _ = pgp_certificate_fingerprint(cert, &mut fingerprint);
        }
    }

    // --- crypto round trips ---
    //
    // These exercise the actual cryptographic entry points (as opposed to
    // ABI/null-pointer handling above). The Dart integration suite
    // (`test/pgp_test.dart`) already covers these extensively against release
    // builds, but it never runs under the `asan` CI job's sanitizer
    // instrumentation. Keeping a representative round trip per operation
    // family here means memory-safety bugs reachable only through real
    // encrypt/sign/decrypt/verify code paths: not just the ABI shim get
    // caught by ASan too.

    unsafe fn to_owned_c_string(ptr: *mut libc::c_char) -> String {
        let s = CStr::from_ptr(ptr).to_str().unwrap().to_owned();
        libc::free(ptr as *mut libc::c_void);
        s
    }

    unsafe fn signing_subkey_fingerprint(cert: *mut Certificate) -> String {
        let mut subkeys: *mut libc::c_char = ptr::null_mut();
        assert_eq!(
            pgp_certificate_subkeys(cert, &mut subkeys),
            FFIError::Ok as i32
        );
        let raw = to_owned_c_string(subkeys);
        raw.lines()
            .find_map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                let flags = fields[2].split(',').collect::<Vec<_>>();
                flags.contains(&"signing").then(|| fields[1].to_string())
            })
            .expect("cert should have a signing subkey")
    }

    #[test]
    fn encrypt_decrypt_string_round_trip() {
        unsafe {
            let cert = generate_cert("crypto-encrypt@example.org");
            let plaintext = CString::new("hello from a rust test").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_decrypt_string(cert, cipher_c.as_ptr(), &mut recovered),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(recovered), "hello from a rust test");

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn message_recipient_key_ids_reports_transport_encryption_subkey() {
        unsafe {
            let cert = generate_cert("recipient-key-ids@example.org");
            let plaintext = CString::new("hello").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let mut subkeys: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(cert, &mut subkeys),
                FFIError::Ok as i32
            );
            let subkeys_str = to_owned_c_string(subkeys);
            let encryption_fp = subkeys_str
                .lines()
                .find(|l| l.split('\t').nth(2).unwrap().contains("encryption"))
                .unwrap()
                .split('\t')
                .nth(1)
                .unwrap()
                .to_string();
            let expected_key_id = &encryption_fp[encryption_fp.len() - 16..];

            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_message_recipient_key_ids(cipher, &mut out),
                FFIError::Ok as i32
            );
            let recipients = to_owned_c_string(out);
            assert_eq!(recipients.lines().count(), 1);
            assert_eq!(recipients.lines().next().unwrap(), expected_key_id);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn message_recipient_key_ids_reports_hidden_for_wildcard_recipient() {
        unsafe {
            let cert = generate_cert("hidden-recipient@example.org");
            let sequoia_cert = &*(&*cert).0;
            let policy = StandardPolicy::new();
            let recipient_key = sequoia_cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .next()
                .unwrap()
                .key()
                .clone();

            let algo = SymmetricAlgorithm::AES256;
            let session_key = SessionKey::new(32).unwrap();
            let mut pkesk = sequoia_openpgp::packet::PKESK::V3(
                sequoia_openpgp::packet::pkesk::PKESK3::for_recipient(
                    algo,
                    &session_key,
                    &recipient_key,
                )
                .unwrap(),
            );
            if let sequoia_openpgp::packet::PKESK::V3(ref mut pkesk3) = pkesk {
                pkesk3.set_recipient(None);
            }

            let mut bytes = Vec::new();
            sequoia_openpgp::Packet::from(pkesk)
                .serialize(&mut bytes)
                .unwrap();

            let mut out = Vec::new();
            {
                let message = Message::new(&mut out);
                let mut armorer =
                    Armorer::new(message).kind(armor::Kind::Message).build().unwrap();
                armorer.write_all(&bytes).unwrap();
                armorer.finalize().unwrap();
            }
            let armored = CString::new(String::from_utf8(out).unwrap()).unwrap();

            let mut recipients: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_message_recipient_key_ids(armored.as_ptr(), &mut recipients),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(recipients), "hidden");

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn message_recipient_key_ids_rejects_garbage_input() {
        unsafe {
            let garbage = CString::new("not a message").unwrap();
            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_message_recipient_key_ids(garbage.as_ptr(), &mut out),
                FFIError::Invalid as i32
            );
            assert!(out.is_null());
        }
    }

    #[test]
    fn message_recipient_key_ids_rejects_null_args() {
        unsafe {
            let msg = CString::new("placeholder").unwrap();
            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_message_recipient_key_ids(ptr::null(), &mut out),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_message_recipient_key_ids(msg.as_ptr(), ptr::null_mut()),
                FFIError::Null as i32
            );
        }
    }

    // --- session key extraction / raw session-key decrypt ---

    #[test]
    fn message_session_key_then_decrypt_with_session_key_round_trip() {
        unsafe {
            let cert = generate_cert("session-key@example.org");
            let plaintext = CString::new("session key round trip payload").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let mut session_key_hex: *mut libc::c_char = ptr::null_mut();
            let mut algo: u8 = 0;
            assert_eq!(
                pgp_message_session_key(cert, cipher, &mut session_key_hex, &mut algo),
                FFIError::Ok as i32
            );
            let session_key_hex = to_owned_c_string(session_key_hex);
            assert!(!session_key_hex.is_empty());
            assert_ne!(algo, 0);

            let session_key_hex_c = CString::new(session_key_hex).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_with_session_key(
                    session_key_hex_c.as_ptr(),
                    algo,
                    cipher,
                    &mut recovered,
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(recovered), "session key round trip payload");

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn message_session_key_rejects_wrong_certificate() {
        unsafe {
            let cert = generate_cert("session-key-wrong@example.org");
            let other = generate_cert("session-key-other@example.org");
            let plaintext = CString::new("payload").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let mut session_key_hex: *mut libc::c_char = ptr::null_mut();
            let mut algo: u8 = 0;
            assert_eq!(
                pgp_message_session_key(other, cipher, &mut session_key_hex, &mut algo),
                FFIError::Failed as i32
            );
            assert!(session_key_hex.is_null());

            pgp_certificate_free(cert);
            pgp_certificate_free(other);
        }
    }

    #[test]
    fn message_session_key_rejects_null_args() {
        unsafe {
            let cert = generate_cert("session-key-null@example.org");
            let msg = CString::new("placeholder").unwrap();
            let mut out: *mut libc::c_char = ptr::null_mut();
            let mut algo: u8 = 0;

            assert_eq!(
                pgp_message_session_key(ptr::null(), msg.as_ptr(), &mut out, &mut algo),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_message_session_key(cert, ptr::null(), &mut out, &mut algo),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_message_session_key(cert, msg.as_ptr(), ptr::null_mut(), &mut algo),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_message_session_key(cert, msg.as_ptr(), &mut out, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn decrypt_with_session_key_rejects_wrong_key() {
        unsafe {
            let cert = generate_cert("session-key-decrypt-wrong@example.org");
            let plaintext = CString::new("payload").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let bogus_key = CString::new("00".repeat(32)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_with_session_key(
                    bogus_key.as_ptr(),
                    9, // AES256
                    cipher,
                    &mut recovered,
                ),
                FFIError::Failed as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn decrypt_with_session_key_rejects_invalid_hex() {
        unsafe {
            let cert = generate_cert("session-key-decrypt-invalid@example.org");
            let plaintext = CString::new("payload").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_string(cert, plaintext.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let not_hex = CString::new("not hex").unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_with_session_key(not_hex.as_ptr(), 9, cipher, &mut recovered),
                FFIError::Invalid as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn decrypt_with_session_key_rejects_null_args() {
        unsafe {
            let key = CString::new("00".repeat(32)).unwrap();
            let msg = CString::new("placeholder").unwrap();
            let mut out: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_decrypt_with_session_key(ptr::null(), 9, msg.as_ptr(), &mut out),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_decrypt_with_session_key(key.as_ptr(), 9, ptr::null(), &mut out),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_decrypt_with_session_key(key.as_ptr(), 9, msg.as_ptr(), ptr::null_mut()),
                FFIError::Null as i32
            );
        }
    }

    #[test]
    fn sign_verify_string_round_trip() {
        unsafe {
            let cert = generate_cert("crypto-sign@example.org");
            let plaintext = CString::new("signed rust test payload").unwrap();

            let mut signed: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_sign_string(cert, plaintext.as_ptr(), &mut signed),
                FFIError::Ok as i32
            );

            let expected_fp = signing_subkey_fingerprint(cert);
            let signed_c = CString::new(to_owned_c_string(signed)).unwrap();
            let mut verified: *mut libc::c_char = ptr::null_mut();
            let mut signer_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_verify_string(
                    cert,
                    signed_c.as_ptr(),
                    &mut verified,
                    &mut signer_fp,
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(verified), "signed rust test payload");
            assert_eq!(to_owned_c_string(signer_fp), expected_fp);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn verify_string_reports_signature_creation_epoch() {
        unsafe {
            let cert = generate_cert("crypto-sign-creation-time@example.org");
            let plaintext = CString::new("signed rust test payload").unwrap();

            let mut signed: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_sign_string(cert, plaintext.as_ptr(), &mut signed),
                FFIError::Ok as i32
            );

            let signed_c = CString::new(to_owned_c_string(signed)).unwrap();
            let mut verified: *mut libc::c_char = ptr::null_mut();
            let mut creation_epoch: i64 = 0;
            assert_eq!(
                pgp_certificate_verify_string(
                    cert,
                    signed_c.as_ptr(),
                    &mut verified,
                    ptr::null_mut(),
                    &mut creation_epoch
                ),
                FFIError::Ok as i32
            );
            assert!(creation_epoch > 0);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn sign_detached_verify_detached_round_trip() {
        unsafe {
            let cert = generate_cert("crypto-detached@example.org");
            let plaintext = CString::new("detached rust test payload").unwrap();

            let mut sig: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_sign_detached(cert, plaintext.as_ptr(), &mut sig),
                FFIError::Ok as i32
            );

            let expected_fp = signing_subkey_fingerprint(cert);
            let sig_c = CString::new(to_owned_c_string(sig)).unwrap();
            let mut signer_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_verify_detached(
                    cert,
                    plaintext.as_ptr(),
                    sig_c.as_ptr(),
                    &mut signer_fp,
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(signer_fp), expected_fp);

            // A null out-param is accepted and simply skipped.
            assert_eq!(
                pgp_certificate_verify_detached(
                    cert,
                    plaintext.as_ptr(),
                    sig_c.as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn encrypt_bytes_decrypt_bytes_round_trip() {
        unsafe {
            let cert = generate_cert("crypto-bytes@example.org");
            let data: [u8; 5] = [0, 1, 255, 254, 42];

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_encrypt_bytes(cert, data.as_ptr(), data.len(), &mut cipher),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut u8 = ptr::null_mut();
            let mut recovered_len: usize = 0;
            assert_eq!(
                pgp_certificate_decrypt_bytes(
                    cert,
                    cipher_c.as_ptr(),
                    &mut recovered,
                    &mut recovered_len
                ),
                FFIError::Ok as i32
            );
            let recovered_slice = std::slice::from_raw_parts(recovered, recovered_len);
            assert_eq!(recovered_slice, &data[..]);
            libc::free(recovered as *mut libc::c_void);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn sign_bytes_verify_bytes_round_trip_reports_signer() {
        unsafe {
            let cert = generate_cert("crypto-sign-bytes@example.org");
            let data: [u8; 4] = [9, 8, 7, 6];

            let mut signed: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_sign_bytes(cert, data.as_ptr(), data.len(), &mut signed),
                FFIError::Ok as i32
            );

            let expected_fp = signing_subkey_fingerprint(cert);
            let signed_c = CString::new(to_owned_c_string(signed)).unwrap();
            let mut recovered: *mut u8 = ptr::null_mut();
            let mut recovered_len: usize = 0;
            let mut signer_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_verify_bytes(
                    cert,
                    signed_c.as_ptr(),
                    &mut recovered,
                    &mut recovered_len,
                    &mut signer_fp,
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );
            let recovered_slice = std::slice::from_raw_parts(recovered, recovered_len);
            assert_eq!(recovered_slice, &data[..]);
            assert_eq!(to_owned_c_string(signer_fp), expected_fp);
            libc::free(recovered as *mut libc::c_void);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn sign_cleartext_verify_cleartext_round_trip() {
        unsafe {
            let cert = generate_cert("crypto-cleartext@example.org");
            let plaintext = CString::new("cleartext rust test payload").unwrap();

            let mut signed: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_sign_cleartext(cert, plaintext.as_ptr(), &mut signed),
                FFIError::Ok as i32
            );

            let expected_fp = signing_subkey_fingerprint(cert);
            let signed_c = CString::new(to_owned_c_string(signed)).unwrap();
            let mut verified: *mut libc::c_char = ptr::null_mut();
            let mut signer_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_verify_cleartext(
                    cert,
                    signed_c.as_ptr(),
                    &mut verified,
                    &mut signer_fp,
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(verified), "cleartext rust test payload");
            assert_eq!(to_owned_c_string(signer_fp), expected_fp);

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn encrypt_symmetric_decrypt_symmetric_round_trip() {
        unsafe {
            let plaintext = CString::new("symmetric rust test payload").unwrap();
            let passphrase = CString::new("correct horse battery staple").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_encrypt_string_symmetric(plaintext.as_ptr(), passphrase.as_ptr(), &mut cipher),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_string_symmetric(cipher_c.as_ptr(), passphrase.as_ptr(), &mut recovered),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(recovered), "symmetric rust test payload");
        }
    }

    #[test]
    fn encrypt_and_sign_decrypt_and_verify_round_trip() {
        unsafe {
            let alice = generate_cert("crypto-alice@example.org");
            let bob = generate_cert("crypto-bob@example.org");
            let plaintext = CString::new("sign+encrypt rust test payload").unwrap();

            let recipients = [bob as *const Certificate];
            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_encrypt_and_sign_string(
                    alice,
                    recipients.as_ptr(),
                    recipients.len(),
                    plaintext.as_ptr(),
                    &mut cipher
                ),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            let mut signer_fingerprint: *mut libc::c_char = ptr::null_mut();
            let mut creation_epoch: i64 = 0;
            assert_eq!(
                pgp_decrypt_and_verify_string(
                    bob,
                    alice,
                    cipher_c.as_ptr(),
                    &mut recovered,
                    &mut signer_fingerprint,
                    &mut creation_epoch
                ),
                FFIError::Ok as i32
            );
            assert_eq!(
                to_owned_c_string(recovered),
                "sign+encrypt rust test payload"
            );
            assert!(creation_epoch > 0);
            libc::free(signer_fingerprint as *mut libc::c_void);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn encrypt_and_sign_symmetric_decrypt_and_verify_symmetric_round_trip() {
        unsafe {
            let alice = generate_cert("symmetric-sign-alice@example.org");
            let plaintext = CString::new("sign+symmetric rust test payload").unwrap();
            let passphrase = CString::new("correct horse battery staple").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    alice,
                    plaintext.as_ptr(),
                    passphrase.as_ptr(),
                    &mut cipher,
                ),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            let mut signer_fingerprint: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_and_verify_string_symmetric(
                    alice,
                    cipher_c.as_ptr(),
                    passphrase.as_ptr(),
                    &mut recovered,
                    &mut signer_fingerprint,
                    ptr::null_mut()
                ),
                FFIError::Ok as i32
            );
            assert_eq!(
                to_owned_c_string(recovered),
                "sign+symmetric rust test payload"
            );
            assert!(!signer_fingerprint.is_null());
            libc::free(signer_fingerprint as *mut libc::c_void);

            pgp_certificate_free(alice);
        }
    }

    #[test]
    fn decrypt_and_verify_symmetric_rejects_wrong_passphrase() {
        unsafe {
            let alice = generate_cert("symmetric-sign-wrong-pass@example.org");
            let plaintext = CString::new("payload").unwrap();
            let passphrase = CString::new("correct horse battery staple").unwrap();
            let wrong_passphrase = CString::new("wrong passphrase").unwrap();

            let mut cipher: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    alice,
                    plaintext.as_ptr(),
                    passphrase.as_ptr(),
                    &mut cipher,
                ),
                FFIError::Ok as i32
            );

            let cipher_c = CString::new(to_owned_c_string(cipher)).unwrap();
            let mut recovered: *mut libc::c_char = ptr::null_mut();
            let mut signer_fingerprint: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_and_verify_string_symmetric(
                    alice,
                    cipher_c.as_ptr(),
                    wrong_passphrase.as_ptr(),
                    &mut recovered,
                    &mut signer_fingerprint,
                    ptr::null_mut()
                ),
                FFIError::Failed as i32
            );

            pgp_certificate_free(alice);
        }
    }

    #[test]
    fn encrypt_and_sign_string_symmetric_rejects_null_args() {
        unsafe {
            let alice = generate_cert("symmetric-sign-null@example.org");
            let plaintext = CString::new("payload").unwrap();
            let passphrase = CString::new("pass").unwrap();
            let mut cipher: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    ptr::null(),
                    plaintext.as_ptr(),
                    passphrase.as_ptr(),
                    &mut cipher,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    alice,
                    ptr::null(),
                    passphrase.as_ptr(),
                    &mut cipher,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    alice,
                    plaintext.as_ptr(),
                    ptr::null(),
                    &mut cipher,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_encrypt_and_sign_string_symmetric(
                    alice,
                    plaintext.as_ptr(),
                    passphrase.as_ptr(),
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
        }
    }

    #[test]
    fn subkeys_lists_capabilities_and_agrees_with_revoke_subkey_indexing() {
        unsafe {
            let cert = generate_cert("subkeys@example.org");

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(cert, &mut listing),
                FFIError::Ok as i32
            );
            assert!(!listing.is_null());
            let listing_str = to_owned_c_string(listing);

            // `pgp_key_generate` produces a signing subkey and a
            // transport-encryption subkey.
            let lines: Vec<&str> = listing_str.lines().collect();
            assert_eq!(lines.len(), 2);
            let flags: Vec<&str> = lines
                .iter()
                .map(|l| l.split('\t').nth(2).unwrap())
                .collect();
            assert!(flags.contains(&"encryption"));
            assert!(flags.contains(&"signing"));
            for line in &lines {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields[1].len(), 40);
                assert_eq!(fields[3], "0");
            }

            // Revoking index 0 (as reported above) must revoke that exact
            // subkey, and the listing must then report it as revoked.
            let mut revoked_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_subkey(cert, 0, 0, ptr::null(), &mut revoked_cert),
                FFIError::Ok as i32
            );

            let mut listing_after: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(revoked_cert, &mut listing_after),
                FFIError::Ok as i32
            );
            let listing_after_str = to_owned_c_string(listing_after);
            let fields_after: Vec<&str> =
                listing_after_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields_after[3], "1");

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked_cert);
        }
    }

    #[test]
    fn subkeys_reports_signing_subkey_after_add() {
        unsafe {
            let cert = generate_cert("add-signing-subkey@example.org");

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_signing_subkey(cert, &mut updated),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(updated, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);

            // Base cert already has a signing and an encryption subkey; this
            // adds a second signing subkey, for three subkeys total.
            let lines: Vec<&str> = listing_str.lines().collect();
            assert_eq!(lines.len(), 3);
            let flags: Vec<&str> = lines
                .iter()
                .map(|l| l.split('\t').nth(2).unwrap())
                .collect();
            assert_eq!(flags.iter().filter(|f| **f == "signing").count(), 2);
            assert_eq!(flags.iter().filter(|f| **f == "encryption").count(), 1);
            for line in &lines {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields[3], "0");
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn subkeys_reports_authentication_subkey_after_add() {
        unsafe {
            let cert = generate_cert("add-auth-subkey@example.org");

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_authentication_subkey(cert, &mut updated),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(updated, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);

            // Base cert already has a signing and an encryption subkey; this
            // adds an authentication subkey, for three subkeys total.
            let lines: Vec<&str> = listing_str.lines().collect();
            assert_eq!(lines.len(), 3);
            let flags: Vec<&str> = lines
                .iter()
                .map(|l| l.split('\t').nth(2).unwrap())
                .collect();
            assert_eq!(flags.iter().filter(|f| **f == "authentication").count(), 1);
            assert_eq!(flags.iter().filter(|f| **f == "signing").count(), 1);
            assert_eq!(flags.iter().filter(|f| **f == "encryption").count(), 1);
            for line in &lines {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields[3], "0");
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn add_authentication_subkey_rejects_null_args() {
        unsafe {
            let cert = generate_cert("add-auth-subkey-null@example.org");
            let mut updated: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_add_authentication_subkey(ptr::null(), &mut updated),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_add_authentication_subkey(cert, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn subkeys_lists_expiry_epoch_as_zero_by_default() {
        unsafe {
            let cert = generate_cert("subkeys-expiry-default@example.org");

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(cert, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            for line in listing_str.lines() {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields[4], "0");
            }

            pgp_certificate_free(cert);
        }
    }

    // --- per-subkey expiry ---

    #[test]
    fn set_subkey_expiry_updates_only_the_target_subkey() {
        unsafe {
            let cert = generate_cert("subkey-expiry@example.org");

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(cert, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let target_fp = listing_str
                .lines()
                .find(|l| l.split('\t').nth(2).unwrap().contains("signing"))
                .unwrap()
                .split('\t')
                .nth(1)
                .unwrap()
                .to_string();

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_subkey_expiry(cert, 0, 3600, &mut updated),
                FFIError::Ok as i32
            );

            let mut listing_after: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(updated, &mut listing_after),
                FFIError::Ok as i32
            );
            let listing_after_str = to_owned_c_string(listing_after);

            for line in listing_after_str.lines() {
                let fields: Vec<&str> = line.split('\t').collect();
                if fields[1] == target_fp {
                    assert_ne!(fields[4], "0", "target subkey should have an expiry");
                } else {
                    assert_eq!(fields[4], "0", "other subkeys must be untouched");
                }
            }

            // The primary key's own expiry must also be untouched.
            let mut primary_expiry: i64 = -1;
            assert_eq!(
                pgp_certificate_expiry_epoch(updated, &mut primary_expiry),
                FFIError::Ok as i32
            );
            assert_eq!(primary_expiry, 0);

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn set_subkey_expiry_zero_clears_expiry() {
        unsafe {
            let cert = generate_cert("subkey-expiry-clear@example.org");

            let mut with_expiry: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_subkey_expiry(cert, 0, 3600, &mut with_expiry),
                FFIError::Ok as i32
            );

            let mut cleared: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_subkey_expiry(with_expiry, 0, 0, &mut cleared),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_subkeys(cleared, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let fields: Vec<&str> =
                listing_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields[4], "0");

            pgp_certificate_free(cert);
            pgp_certificate_free(with_expiry);
            pgp_certificate_free(cleared);
        }
    }

    #[test]
    fn set_subkey_expiry_rejects_out_of_range_index() {
        unsafe {
            let cert = generate_cert("subkey-expiry-oob@example.org");

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_subkey_expiry(cert, 99, 3600, &mut updated),
                FFIError::NotFound as i32
            );
            assert!(updated.is_null());

            pgp_certificate_free(cert);
        }
    }

    // --- revocation reason / message ---

    #[test]
    fn revoke_records_custom_reason_and_message() {
        unsafe {
            let cert = generate_cert("revoke-reason@example.org");
            let message = CString::new("key compromised on 2026-07-03").unwrap();

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke(
                    cert,
                    ReasonForRevocation::KeyCompromised.into(),
                    message.as_ptr(),
                    &mut revoked,
                ),
                FFIError::Ok as i32
            );

            let policy = StandardPolicy::new();
            let sequoia_cert = &*(&*revoked).0;
            match sequoia_cert.revocation_status(&policy, None) {
                RevocationStatus::Revoked(sigs) => {
                    let (code, reason) = sigs[0].reason_for_revocation().unwrap();
                    assert_eq!(code, ReasonForRevocation::KeyCompromised);
                    assert_eq!(reason, b"key compromised on 2026-07-03");
                }
                other => panic!("expected Revoked, got {other:?}"),
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn revoke_defaults_to_empty_message_when_null() {
        unsafe {
            let cert = generate_cert("revoke-null-message@example.org");

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke(cert, 0, ptr::null(), &mut revoked),
                FFIError::Ok as i32
            );

            let policy = StandardPolicy::new();
            let sequoia_cert = &*(&*revoked).0;
            match sequoia_cert.revocation_status(&policy, None) {
                RevocationStatus::Revoked(sigs) => {
                    let (code, reason) = sigs[0].reason_for_revocation().unwrap();
                    assert_eq!(code, ReasonForRevocation::Unspecified);
                    assert_eq!(reason, b"");
                }
                other => panic!("expected Revoked, got {other:?}"),
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn revoke_rejects_non_utf8_message() {
        unsafe {
            let cert = generate_cert("revoke-bad-message@example.org");
            let bad_message: &[u8] = b"\xff\xfe\x00";

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke(
                    cert,
                    0,
                    bad_message.as_ptr() as *const libc::c_char,
                    &mut revoked,
                ),
                FFIError::Invalid as i32
            );
            assert!(revoked.is_null());

            pgp_certificate_free(cert);
        }
    }

    // --- certificate-level revocation readback ---

    #[test]
    fn revocation_info_reports_not_revoked_for_fresh_cert() {
        unsafe {
            let cert = generate_cert("revocation-info-fresh@example.org");

            let mut revoked: u8 = 99;
            let mut reason: u8 = 99;
            let mut message: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revocation_info(cert, &mut revoked, &mut reason, &mut message),
                FFIError::Ok as i32
            );
            assert_eq!(revoked, 0);
            assert_eq!(reason, 0);
            assert!(!message.is_null());
            assert_eq!(CStr::from_ptr(message).to_str().unwrap(), "");

            libc::free(message as *mut libc::c_void);
            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn revocation_info_reports_reason_and_message_after_revoke() {
        unsafe {
            let cert = generate_cert("revocation-info-revoked@example.org");
            let revoke_message = CString::new("key compromised").unwrap();

            let mut revoked_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke(
                    cert,
                    ReasonForRevocation::KeyCompromised.into(),
                    revoke_message.as_ptr(),
                    &mut revoked_cert,
                ),
                FFIError::Ok as i32
            );

            let mut revoked: u8 = 0;
            let mut reason: u8 = 0;
            let mut message: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revocation_info(
                    revoked_cert,
                    &mut revoked,
                    &mut reason,
                    &mut message
                ),
                FFIError::Ok as i32
            );
            assert_eq!(revoked, 1);
            assert_eq!(reason, u8::from(ReasonForRevocation::KeyCompromised));
            assert_eq!(
                CStr::from_ptr(message).to_str().unwrap(),
                "key compromised"
            );

            libc::free(message as *mut libc::c_void);
            pgp_certificate_free(cert);
            pgp_certificate_free(revoked_cert);
        }
    }

    #[test]
    fn revocation_info_rejects_null_args() {
        unsafe {
            let cert = generate_cert("revocation-info-null@example.org");
            let mut revoked: u8 = 0;
            let mut reason: u8 = 0;
            let mut message: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_certificate_revocation_info(
                    ptr::null(),
                    &mut revoked,
                    &mut reason,
                    &mut message
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revocation_info(cert, ptr::null_mut(), &mut reason, &mut message),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revocation_info(cert, &mut revoked, ptr::null_mut(), &mut message),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revocation_info(cert, &mut revoked, &mut reason, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn generate_revocation_armored_produces_applicable_signature() {
        unsafe {
            let cert = generate_cert("standalone-revocation@example.org");
            let message = CString::new("lost the secret key").unwrap();

            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_generate_revocation_armored(
                    cert,
                    ReasonForRevocation::KeyCompromised.into(),
                    message.as_ptr(),
                    &mut armored,
                ),
                FFIError::Ok as i32
            );
            let armored_str = to_owned_c_string(armored);
            assert!(armored_str.contains("BEGIN PGP SIGNATURE"));

            // The source cert must be untouched by generating the certificate.
            let mut revoked_before: u8 = 1;
            let mut reason: u8 = 0;
            let mut msg: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revocation_info(cert, &mut revoked_before, &mut reason, &mut msg),
                FFIError::Ok as i32
            );
            assert_eq!(revoked_before, 0);
            libc::free(msg as *mut libc::c_void);

            let revocation_armored = CString::new(armored_str).unwrap();
            let mut new_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_apply_revocation_armored(
                    cert,
                    revocation_armored.as_ptr(),
                    &mut new_cert,
                ),
                FFIError::Ok as i32
            );
            assert!(!new_cert.is_null());

            let mut revoked: u8 = 0;
            let mut reason: u8 = 0;
            let mut message_out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revocation_info(
                    new_cert,
                    &mut revoked,
                    &mut reason,
                    &mut message_out
                ),
                FFIError::Ok as i32
            );
            assert_eq!(revoked, 1);
            assert_eq!(reason, u8::from(ReasonForRevocation::KeyCompromised));
            assert_eq!(to_owned_c_string(message_out), "lost the secret key");

            pgp_certificate_free(cert);
            pgp_certificate_free(new_cert);
        }
    }

    #[test]
    fn apply_revocation_armored_rejects_garbage_input() {
        unsafe {
            let cert = generate_cert("apply-revocation-garbage@example.org");
            let garbage = CString::new("not a signature").unwrap();

            let mut new_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_apply_revocation_armored(cert, garbage.as_ptr(), &mut new_cert),
                FFIError::Invalid as i32
            );
            assert!(new_cert.is_null());

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn generate_revocation_armored_rejects_null_args() {
        unsafe {
            let cert = generate_cert("generate-revocation-null@example.org");
            let mut armored: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_certificate_generate_revocation_armored(
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut armored,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_generate_revocation_armored(cert, 0, ptr::null(), ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn apply_revocation_armored_rejects_null_args() {
        unsafe {
            let cert = generate_cert("apply-revocation-null@example.org");
            let sig = CString::new("placeholder").unwrap();
            let mut new_cert: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_apply_revocation_armored(
                    ptr::null(),
                    sig.as_ptr(),
                    &mut new_cert,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_apply_revocation_armored(cert, ptr::null(), &mut new_cert),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_apply_revocation_armored(cert, sig.as_ptr(), ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn revoke_subkey_records_custom_reason_and_message() {
        unsafe {
            let cert = generate_cert("revoke-subkey-reason@example.org");
            let message = CString::new("superseded by new subkey").unwrap();

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_subkey(
                    cert,
                    0,
                    ReasonForRevocation::KeySuperseded.into(),
                    message.as_ptr(),
                    &mut revoked,
                ),
                FFIError::Ok as i32
            );

            let policy = StandardPolicy::new();
            let sequoia_cert = &*(&*revoked).0;
            let subkey = sequoia_cert.keys().subkeys().next().unwrap();
            match subkey.with_policy(&policy, None).unwrap().revocation_status() {
                RevocationStatus::Revoked(sigs) => {
                    let (code, reason) = sigs[0].reason_for_revocation().unwrap();
                    assert_eq!(code, ReasonForRevocation::KeySuperseded);
                    assert_eq!(reason, b"superseded by new subkey");
                }
                other => panic!("expected Revoked, got {other:?}"),
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn revoke_userid_records_custom_reason_and_message() {
        unsafe {
            let cert = generate_cert("revoke-userid-reason@example.org");
            let user_id = CString::new("revoke-userid-reason@example.org").unwrap();
            let message = CString::new("address decommissioned").unwrap();

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_userid(
                    cert,
                    user_id.as_ptr(),
                    ReasonForRevocation::UIDRetired.into(),
                    message.as_ptr(),
                    &mut revoked,
                ),
                FFIError::Ok as i32
            );

            let policy = StandardPolicy::new();
            let sequoia_cert = &*(&*revoked).0;
            let ua = sequoia_cert
                .userids()
                .find(|ua| ua.userid().value() == b"revoke-userid-reason@example.org")
                .unwrap();
            match ua.with_policy(&policy, None).unwrap().revocation_status() {
                RevocationStatus::Revoked(sigs) => {
                    let (code, reason) = sigs[0].reason_for_revocation().unwrap();
                    assert_eq!(code, ReasonForRevocation::UIDRetired);
                    assert_eq!(reason, b"address decommissioned");
                }
                other => panic!("expected Revoked, got {other:?}"),
            }

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn certify_userid_attaches_third_party_signature() {
        unsafe {
            let alice = generate_cert("alice@example.org");
            let bob = generate_cert("bob@example.org");
            let user_id = CString::new("bob@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );
            assert!(!certified.is_null());

            let mut alice_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(alice, &mut alice_fp),
                FFIError::Ok as i32
            );
            let alice_fp_owned = CStr::from_ptr(alice_fp).to_str().unwrap().to_owned();
            libc::free(alice_fp as *mut libc::c_void);
            let alice_fp = alice_fp_owned;

            let sequoia_cert = &*(&*certified).0;
            let ua = sequoia_cert
                .userids()
                .find(|ua| ua.userid().value() == b"bob@example.org")
                .unwrap();
            let sig = ua
                .certifications()
                .find(|sig| {
                    sig.issuer_fingerprints()
                        .any(|fp| fp.to_hex() == alice_fp)
                })
                .expect("third-party certification from alice not found");
            assert_eq!(sig.typ(), sequoia_openpgp::types::SignatureType::GenericCertification);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn certify_userid_leaves_target_cert_unmodified() {
        unsafe {
            let alice = generate_cert("alice-untouched@example.org");
            let bob = generate_cert("bob-untouched@example.org");
            let user_id = CString::new("bob-untouched@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let original = &*(&*bob).0;
            let ua = original
                .userids()
                .find(|ua| ua.userid().value() == b"bob-untouched@example.org")
                .unwrap();
            assert_eq!(ua.certifications().count(), 0);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn certify_userid_rejects_missing_user_id() {
        unsafe {
            let alice = generate_cert("alice-missing@example.org");
            let bob = generate_cert("bob-missing@example.org");
            let user_id = CString::new("nobody@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::NotFound as i32
            );
            assert!(certified.is_null());

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn certify_userid_rejects_null_args() {
        unsafe {
            let alice = generate_cert("alice-null@example.org");
            let bob = generate_cert("bob-null@example.org");
            let user_id = CString::new("bob-null@example.org").unwrap();
            let mut certified: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_certify_userid(
                    ptr::null(),
                    bob,
                    user_id.as_ptr(),
                    &mut certified
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid(
                    alice,
                    ptr::null(),
                    user_id.as_ptr(),
                    &mut certified
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, ptr::null(), &mut certified),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    ptr::null_mut()
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn certify_userid_with_trust_attaches_trust_signature() {
        unsafe {
            let alice = generate_cert("alice-trust@example.org");
            let bob = generate_cert("bob-trust@example.org");
            let user_id = CString::new("bob-trust@example.org").unwrap();

            let mut alice_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(alice, &mut alice_fp),
                FFIError::Ok as i32
            );
            let alice_fp = to_owned_c_string(alice_fp);

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    1,
                    120,
                    &mut certified,
                ),
                FFIError::Ok as i32
            );
            assert!(!certified.is_null());

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    certified,
                    user_id.as_ptr(),
                    &mut listing
                ),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let fields: Vec<&str> = listing_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields[0], alice_fp);
            assert_eq!(fields[1], "0");
            assert_eq!(fields[2], "1");
            assert_eq!(fields[3], "120");

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn certify_userid_exportable_false_survives_in_memory_but_not_export() {
        unsafe {
            let alice = generate_cert("alice-local-cert@example.org");
            let bob = generate_cert("bob-local-cert@example.org");
            let user_id = CString::new("bob-local-cert@example.org").unwrap();

            let mut alice_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(alice, &mut alice_fp),
                FFIError::Ok as i32
            );
            let alice_fp = to_owned_c_string(alice_fp);

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    0,
                    &mut certified,
                ),
                FFIError::Ok as i32
            );
            assert!(!certified.is_null());

            // In memory, the local certification is fully present and
            // reported as non-exportable.
            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    certified,
                    user_id.as_ptr(),
                    &mut listing
                ),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let fields: Vec<&str> = listing_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields[0], alice_fp);
            assert_eq!(fields[4], "0"); // not exportable

            // But pgp_certificate_export_public_armored (meant for sharing
            // with others) must silently drop it.
            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_export_public_armored(certified, &mut armored),
                FFIError::Ok as i32
            );
            let armored_c = CString::new(to_owned_c_string(armored)).unwrap();

            let mut reimported: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_from_armored(armored_c.as_ptr(), &mut reimported),
                FFIError::Ok as i32
            );
            let mut listing_after_export: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    reimported,
                    user_id.as_ptr(),
                    &mut listing_after_export
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(listing_after_export), "");

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
            pgp_certificate_free(reimported);
        }
    }

    #[test]
    fn certify_userid_exportable_true_survives_export() {
        unsafe {
            let alice = generate_cert("alice-exportable-cert@example.org");
            let bob = generate_cert("bob-exportable-cert@example.org");
            let user_id = CString::new("bob-exportable-cert@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    1,
                    &mut certified,
                ),
                FFIError::Ok as i32
            );

            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_export_public_armored(certified, &mut armored),
                FFIError::Ok as i32
            );
            let armored_c = CString::new(to_owned_c_string(armored)).unwrap();

            let mut reimported: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_from_armored(armored_c.as_ptr(), &mut reimported),
                FFIError::Ok as i32
            );
            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    reimported,
                    user_id.as_ptr(),
                    &mut listing
                ),
                FFIError::Ok as i32
            );
            assert_eq!(to_owned_c_string(listing).lines().count(), 1);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
            pgp_certificate_free(reimported);
        }
    }

    #[test]
    fn certify_userid_exportable_rejects_missing_user_id() {
        unsafe {
            let alice = generate_cert("alice-exportable-missing@example.org");
            let bob = generate_cert("bob-exportable-missing@example.org");
            let missing = CString::new("nobody@example.org").unwrap();
            let mut certified: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    bob,
                    missing.as_ptr(),
                    1,
                    &mut certified,
                ),
                FFIError::NotFound as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn certify_userid_exportable_rejects_null_args() {
        unsafe {
            let alice = generate_cert("alice-exportable-null@example.org");
            let bob = generate_cert("bob-exportable-null@example.org");
            let user_id = CString::new("bob-exportable-null@example.org").unwrap();
            let mut certified: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    ptr::null(),
                    bob,
                    user_id.as_ptr(),
                    1,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    ptr::null(),
                    user_id.as_ptr(),
                    1,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    bob,
                    ptr::null(),
                    1,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_exportable(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    1,
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn certify_userid_with_trust_rejects_missing_user_id() {
        unsafe {
            let alice = generate_cert("alice-trust-missing@example.org");
            let bob = generate_cert("bob-trust-missing@example.org");
            let missing = CString::new("nobody@example.org").unwrap();
            let mut certified: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    alice,
                    bob,
                    missing.as_ptr(),
                    1,
                    120,
                    &mut certified,
                ),
                FFIError::NotFound as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn certify_userid_with_trust_rejects_null_args() {
        unsafe {
            let alice = generate_cert("alice-trust-null@example.org");
            let bob = generate_cert("bob-trust-null@example.org");
            let user_id = CString::new("bob-trust-null@example.org").unwrap();
            let mut certified: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    ptr::null(),
                    bob,
                    user_id.as_ptr(),
                    1,
                    120,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    alice,
                    ptr::null(),
                    user_id.as_ptr(),
                    1,
                    120,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    alice,
                    bob,
                    ptr::null(),
                    1,
                    120,
                    &mut certified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_certify_userid_with_trust(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    1,
                    120,
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn revoke_userid_certification_attaches_revocation_signature() {
        unsafe {
            let alice = generate_cert("alice-revoker@example.org");
            let bob = generate_cert("bob-revokee@example.org");
            let user_id = CString::new("bob-revokee@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    certified,
                    user_id.as_ptr(),
                    2,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Ok as i32
            );
            assert!(!revoked.is_null());

            let mut alice_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(alice, &mut alice_fp),
                FFIError::Ok as i32
            );
            let alice_fp_owned = CStr::from_ptr(alice_fp).to_str().unwrap().to_owned();
            libc::free(alice_fp as *mut libc::c_void);
            let alice_fp = alice_fp_owned;

            let sequoia_cert = &*(&*revoked).0;
            let ua = sequoia_cert
                .userids()
                .find(|ua| ua.userid().value() == b"bob-revokee@example.org")
                .unwrap();
            // Third-party certifications and third-party
            // certification-revocations live in separate buckets
            // (`certifications` vs. `other_revocations`), so check each.
            let certification_from_alice = ua
                .certifications()
                .find(|sig| sig.issuer_fingerprints().any(|fp| fp.to_hex() == alice_fp))
                .expect("original third-party certification from alice not found");
            assert_eq!(
                certification_from_alice.typ(),
                sequoia_openpgp::types::SignatureType::GenericCertification
            );

            let revocation = ua
                .other_revocations()
                .find(|sig| sig.issuer_fingerprints().any(|fp| fp.to_hex() == alice_fp))
                .expect("certification-revocation signature from alice not found");
            assert_eq!(
                revocation.typ(),
                sequoia_openpgp::types::SignatureType::CertificationRevocation
            );
            let (code, _) = revocation.reason_for_revocation().unwrap();
            assert_eq!(code, ReasonForRevocation::KeyCompromised);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn revoke_userid_certification_leaves_target_cert_unmodified() {
        unsafe {
            let alice = generate_cert("alice-revoker-untouched@example.org");
            let bob = generate_cert("bob-revokee-untouched@example.org");
            let user_id = CString::new("bob-revokee-untouched@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    certified,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Ok as i32
            );

            let original = &*(&*certified).0;
            let ua = original
                .userids()
                .find(|ua| ua.userid().value() == b"bob-revokee-untouched@example.org")
                .unwrap();
            assert_eq!(ua.other_revocations().count(), 0);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn revoke_userid_certification_rejects_missing_user_id() {
        unsafe {
            let alice = generate_cert("alice-revoker-missing@example.org");
            let bob = generate_cert("bob-revokee-missing@example.org");
            let user_id = CString::new("nobody@example.org").unwrap();

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::NotFound as i32
            );
            assert!(revoked.is_null());

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn revoke_userid_certification_rejects_null_args() {
        unsafe {
            let alice = generate_cert("alice-revoker-null@example.org");
            let bob = generate_cert("bob-revokee-null@example.org");
            let user_id = CString::new("bob-revokee-null@example.org").unwrap();
            let mut revoked: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    ptr::null(),
                    bob,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    ptr::null(),
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    bob,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    bob,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    ptr::null_mut()
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn userids_info_reports_primary_and_unrevoked_by_default() {
        unsafe {
            let cert = generate_cert("userids-info@example.org");

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(cert, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let lines: Vec<&str> = listing_str.lines().collect();
            assert_eq!(lines.len(), 1);
            let fields: Vec<&str> = lines[0].split('\t').collect();
            assert_eq!(fields[0], "userids-info@example.org");
            assert_eq!(fields[1], "0"); // revoked
            assert_eq!(fields[2], "1"); // primary
            assert_eq!(fields[3], "0"); // expiry_epoch

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn userids_info_reports_secondary_user_id_as_non_primary() {
        unsafe {
            let cert = generate_cert("userids-info-primary@example.org");
            let user_id = CString::new("second@example.org").unwrap();

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_userid(cert, user_id.as_ptr(), &mut updated),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(updated, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let primary_flags: std::collections::HashMap<&str, &str> = listing_str
                .lines()
                .map(|l| {
                    let f: Vec<&str> = l.split('\t').collect();
                    (f[0], f[2])
                })
                .collect();
            assert_eq!(primary_flags["userids-info-primary@example.org"], "1");
            assert_eq!(primary_flags["second@example.org"], "0");

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn userids_info_agrees_with_revoke_userid() {
        unsafe {
            let cert = generate_cert("userids-info-revoke@example.org");

            let mut revoked: *mut Certificate = ptr::null_mut();
            let user_id = CString::new("userids-info-revoke@example.org").unwrap();
            assert_eq!(
                pgp_certificate_revoke_userid(
                    cert,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked,
                ),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(revoked, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let fields: Vec<&str> = listing_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields[1], "1"); // revoked

            pgp_certificate_free(cert);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn userids_info_rejects_null_args() {
        unsafe {
            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(ptr::null(), &mut out),
                FFIError::Null as i32
            );
            let cert = generate_cert("userids-info-null@example.org");
            assert_eq!(
                pgp_certificate_userids_info(cert, ptr::null_mut()),
                FFIError::Null as i32
            );
            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn set_primary_userid_switches_to_secondary_user_id() {
        unsafe {
            let cert = generate_cert("set-primary@example.org");
            let second_user_id = CString::new("second-primary@example.org").unwrap();

            let mut with_second: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_userid(cert, second_user_id.as_ptr(), &mut with_second),
                FFIError::Ok as i32
            );

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_primary_userid(
                    with_second,
                    second_user_id.as_ptr(),
                    &mut updated,
                ),
                FFIError::Ok as i32
            );
            assert!(!updated.is_null());

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(updated, &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let primary_flags: std::collections::HashMap<&str, &str> = listing_str
                .lines()
                .map(|l| {
                    let f: Vec<&str> = l.split('\t').collect();
                    (f[0], f[2])
                })
                .collect();
            assert_eq!(primary_flags["set-primary@example.org"], "0");
            assert_eq!(primary_flags["second-primary@example.org"], "1");

            // `with_second` itself must be unaffected by the update.
            let mut original_listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userids_info(with_second, &mut original_listing),
                FFIError::Ok as i32
            );
            let original_str = to_owned_c_string(original_listing);
            let original_flags: std::collections::HashMap<&str, &str> = original_str
                .lines()
                .map(|l| {
                    let f: Vec<&str> = l.split('\t').collect();
                    (f[0], f[2])
                })
                .collect();
            assert_eq!(original_flags["set-primary@example.org"], "1");
            assert_eq!(original_flags["second-primary@example.org"], "0");

            pgp_certificate_free(cert);
            pgp_certificate_free(with_second);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn set_primary_userid_rejects_missing_user_id() {
        unsafe {
            let cert = generate_cert("set-primary-missing@example.org");
            let missing = CString::new("nonexistent@example.org").unwrap();

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_primary_userid(cert, missing.as_ptr(), &mut updated),
                FFIError::NotFound as i32
            );
            assert!(updated.is_null());

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn set_primary_userid_rejects_null_args() {
        unsafe {
            let cert = generate_cert("set-primary-null@example.org");
            let user_id = CString::new("set-primary-null@example.org").unwrap();
            let mut updated: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_set_primary_userid(ptr::null(), user_id.as_ptr(), &mut updated),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_set_primary_userid(cert, ptr::null(), &mut updated),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_set_primary_userid(cert, user_id.as_ptr(), ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn lock_encrypts_unencrypted_secret_material() {
        unsafe {
            let cert = generate_cert("lock@example.org");
            let passphrase = CString::new("correct horse battery staple").unwrap();

            let mut locked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(cert, passphrase.as_ptr(), &mut locked),
                FFIError::Ok as i32
            );
            assert!(!locked.is_null());

            let sequoia_cert = &*(&*locked).0;
            assert!(sequoia_cert
                .keys()
                .secret()
                .all(|ka| !ka.key().has_unencrypted_secret()));

            pgp_certificate_free(cert);
            pgp_certificate_free(locked);
        }
    }

    #[test]
    fn lock_then_unlock_round_trips_with_same_passphrase() {
        unsafe {
            let cert = generate_cert("lock-unlock@example.org");
            let passphrase = CString::new("correct horse battery staple").unwrap();

            let mut locked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(cert, passphrase.as_ptr(), &mut locked),
                FFIError::Ok as i32
            );

            let mut unlocked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_unlock(locked, passphrase.as_ptr(), &mut unlocked),
                FFIError::Ok as i32
            );

            let sequoia_cert = &*(&*unlocked).0;
            assert!(sequoia_cert
                .keys()
                .secret()
                .all(|ka| ka.key().has_unencrypted_secret()));

            pgp_certificate_free(cert);
            pgp_certificate_free(locked);
            pgp_certificate_free(unlocked);
        }
    }

    #[test]
    fn lock_rejects_wrong_passphrase_on_unlock() {
        unsafe {
            let cert = generate_cert("lock-wrong-pass@example.org");
            let passphrase = CString::new("correct horse battery staple").unwrap();
            let wrong_passphrase = CString::new("wrong passphrase").unwrap();

            let mut locked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(cert, passphrase.as_ptr(), &mut locked),
                FFIError::Ok as i32
            );

            let mut unlocked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_unlock(locked, wrong_passphrase.as_ptr(), &mut unlocked),
                FFIError::Invalid as i32
            );
            assert!(unlocked.is_null());

            pgp_certificate_free(cert);
            pgp_certificate_free(locked);
        }
    }

    #[test]
    fn lock_returns_not_found_for_public_only_cert() {
        unsafe {
            let cert = generate_cert("lock-public-only@example.org");
            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_export_public_armored(cert, &mut armored),
                FFIError::Ok as i32
            );
            let armored_str = to_owned_c_string(armored);
            let armored_c = CString::new(armored_str).unwrap();

            let mut public_only: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_from_armored(armored_c.as_ptr(), &mut public_only),
                FFIError::Ok as i32
            );

            let passphrase = CString::new("irrelevant").unwrap();
            let mut locked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(public_only, passphrase.as_ptr(), &mut locked),
                FFIError::NotFound as i32
            );
            assert!(locked.is_null());

            pgp_certificate_free(cert);
            pgp_certificate_free(public_only);
        }
    }

    #[test]
    fn lock_leaves_already_locked_keys_untouched() {
        unsafe {
            let cert = generate_cert("lock-idempotent@example.org");
            let passphrase = CString::new("first passphrase").unwrap();
            let second_passphrase = CString::new("second passphrase").unwrap();

            let mut locked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(cert, passphrase.as_ptr(), &mut locked),
                FFIError::Ok as i32
            );

            // Locking again with a different passphrase must not change the
            // passphrase on keys that are already locked.
            let mut relocked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_lock(locked, second_passphrase.as_ptr(), &mut relocked),
                FFIError::Ok as i32
            );

            let mut unlocked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_unlock(relocked, passphrase.as_ptr(), &mut unlocked),
                FFIError::Ok as i32
            );
            assert!(!unlocked.is_null());

            pgp_certificate_free(cert);
            pgp_certificate_free(locked);
            pgp_certificate_free(relocked);
            pgp_certificate_free(unlocked);
        }
    }

    #[test]
    fn lock_rejects_null_args() {
        unsafe {
            let cert = generate_cert("lock-null@example.org");
            let passphrase = CString::new("passphrase").unwrap();
            let mut locked: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_lock(ptr::null(), passphrase.as_ptr(), &mut locked),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_lock(cert, ptr::null(), &mut locked),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_lock(cert, passphrase.as_ptr(), ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn userid_certifications_reports_certifier_and_revocation_state() {
        unsafe {
            let alice = generate_cert("alice-certifier@example.org");
            let bob = generate_cert("bob-certified@example.org");
            let user_id = CString::new("bob-certified@example.org").unwrap();

            let mut alice_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_fingerprint(alice, &mut alice_fp),
                FFIError::Ok as i32
            );
            let alice_fp = to_owned_c_string(alice_fp);

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    certified,
                    user_id.as_ptr(),
                    &mut listing
                ),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            let lines: Vec<&str> = listing_str.lines().collect();
            assert_eq!(lines.len(), 1);
            let fields: Vec<&str> = lines[0].split('\t').collect();
            assert_eq!(fields[0], alice_fp);
            assert_eq!(fields[1], "0"); // not yet revoked
            assert_eq!(fields[2], "0"); // no trust signature
            assert_eq!(fields[3], "0");
            assert_eq!(fields[4], "1"); // exportable by default

            let mut revoked: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revoke_userid_certification(
                    alice,
                    certified,
                    user_id.as_ptr(),
                    0,
                    ptr::null(),
                    &mut revoked
                ),
                FFIError::Ok as i32
            );

            let mut listing_after: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(
                    revoked,
                    user_id.as_ptr(),
                    &mut listing_after
                ),
                FFIError::Ok as i32
            );
            let listing_after_str = to_owned_c_string(listing_after);
            let fields_after: Vec<&str> =
                listing_after_str.lines().next().unwrap().split('\t').collect();
            assert_eq!(fields_after[0], alice_fp);
            assert_eq!(fields_after[1], "1"); // now revoked

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
            pgp_certificate_free(revoked);
        }
    }

    #[test]
    fn userid_certifications_is_empty_for_uncertified_userid() {
        unsafe {
            let cert = generate_cert("uncertified@example.org");
            let user_id = CString::new("uncertified@example.org").unwrap();

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(cert, user_id.as_ptr(), &mut listing),
                FFIError::Ok as i32
            );
            let listing_str = to_owned_c_string(listing);
            assert!(listing_str.is_empty());

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn userid_certifications_rejects_missing_user_id() {
        unsafe {
            let cert = generate_cert("missing-userid@example.org");
            let user_id = CString::new("nobody@example.org").unwrap();

            let mut listing: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_userid_certifications(cert, user_id.as_ptr(), &mut listing),
                FFIError::NotFound as i32
            );
            assert!(listing.is_null());

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn userid_certifications_rejects_null_args() {
        unsafe {
            let cert = generate_cert("certifications-null@example.org");
            let user_id = CString::new("certifications-null@example.org").unwrap();
            let mut listing: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_certificate_userid_certifications(
                    ptr::null(),
                    user_id.as_ptr(),
                    &mut listing
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_userid_certifications(cert, ptr::null(), &mut listing),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_userid_certifications(
                    cert,
                    user_id.as_ptr(),
                    ptr::null_mut()
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn verify_userid_certification_confirms_genuine_signature() {
        unsafe {
            let alice = generate_cert("alice-verifier@example.org");
            let bob = generate_cert("bob-verified@example.org");
            let user_id = CString::new("bob-verified@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let mut verified: u8 = 0;
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    certified,
                    alice,
                    user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::Ok as i32
            );
            assert_eq!(verified, 1);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn verify_userid_certification_falls_back_to_legacy_issuer_keyid() {
        unsafe {
            let alice = generate_cert("alice-legacy-issuer@example.org");
            let bob = generate_cert("bob-legacy-issuer@example.org");
            let user_id_str = "bob-legacy-issuer@example.org";
            let user_id = CString::new(user_id_str).unwrap();

            let alice_wrapper = &*alice;
            let bob_wrapper = &*bob;
            let alice_cert = &*alice_wrapper.0;
            let bob_cert = (&*bob_wrapper.0).clone();

            let target_uid = bob_cert
                .userids()
                .find(|ua| ua.userid().value() == user_id_str.as_bytes())
                .unwrap()
                .userid()
                .clone();

            let mut signer = alice_cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap()
                .into_keypair()
                .unwrap();

            // Build the certification with an explicit `Issuer` (bare key
            // ID) subpacket and nothing else identifying the signer.
            // `sign_hash` only auto-adds an `IssuerFingerprint` subpacket
            // when *neither* subpacket has already been set, so this
            // reproduces a certification from an implementation that never
            // emits the modern fingerprint subpacket: the fallback path
            // under test.
            let builder = sequoia_openpgp::packet::signature::SignatureBuilder::new(
                sequoia_openpgp::types::SignatureType::GenericCertification,
            )
            .set_issuer(alice_cert.fingerprint().into())
            .unwrap();
            let sig = target_uid.bind(&mut signer, &bob_cert, builder).unwrap();
            assert!(sig.issuer_fingerprints().next().is_none());
            assert!(sig.issuers().next().is_some());

            let (updated, _) = bob_cert.insert_packets(vec![sig]).unwrap();
            let inner = Box::into_raw(Box::new(updated));
            let certified = Box::into_raw(Box::new(Certificate(inner)));

            let mut verified: u8 = 0;
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    certified,
                    alice,
                    user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::Ok as i32
            );
            assert_eq!(verified, 1);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn verify_userid_certification_rejects_wrong_issuer() {
        unsafe {
            let alice = generate_cert("alice-wrong-issuer@example.org");
            let bob = generate_cert("bob-wrong-issuer@example.org");
            let mallory = generate_cert("mallory-wrong-issuer@example.org");
            let user_id = CString::new("bob-wrong-issuer@example.org").unwrap();

            let mut certified: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_certify_userid(alice, bob, user_id.as_ptr(), &mut certified),
                FFIError::Ok as i32
            );

            let mut verified: u8 = 1;
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    certified,
                    mallory,
                    user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::NotFound as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(mallory);
            pgp_certificate_free(certified);
        }
    }

    #[test]
    fn verify_userid_certification_rejects_missing_user_id() {
        unsafe {
            let alice = generate_cert("alice-missing-uid@example.org");
            let bob = generate_cert("bob-missing-uid@example.org");
            let missing_user_id = CString::new("nobody@example.org").unwrap();

            let mut verified: u8 = 0;
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    bob,
                    alice,
                    missing_user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::NotFound as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn verify_userid_certification_rejects_null_args() {
        unsafe {
            let cert = generate_cert("verify-certification-null@example.org");
            let issuer = generate_cert("verify-certification-null-issuer@example.org");
            let user_id = CString::new("verify-certification-null@example.org").unwrap();
            let mut verified: u8 = 0;

            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    ptr::null(),
                    issuer,
                    user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    cert,
                    ptr::null(),
                    user_id.as_ptr(),
                    &mut verified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    cert,
                    issuer,
                    ptr::null(),
                    &mut verified,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_verify_userid_certification(
                    cert,
                    issuer,
                    user_id.as_ptr(),
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
            pgp_certificate_free(issuer);
        }
    }

    #[test]
    fn merge_pulls_in_new_userid_from_other() {
        unsafe {
            let base = generate_cert("merge-base@example.org");
            let extra_user_id = CString::new("merge-extra@example.org").unwrap();

            let mut with_extra: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_userid(base, extra_user_id.as_ptr(), &mut with_extra),
                FFIError::Ok as i32
            );

            let mut merged: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_merge(base, with_extra, &mut merged),
                FFIError::Ok as i32
            );
            assert!(!merged.is_null());

            let merged_cert = &*(&*merged).0;
            assert!(merged_cert
                .userids()
                .any(|ua| ua.userid().value() == b"merge-extra@example.org"));

            pgp_certificate_free(base);
            pgp_certificate_free(with_extra);
            pgp_certificate_free(merged);
        }
    }

    #[test]
    fn merge_preserves_base_secret_key_material() {
        unsafe {
            let base = generate_cert("merge-secret@example.org");
            let extra_user_id = CString::new("merge-secret-extra@example.org").unwrap();

            let mut with_extra: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_userid(base, extra_user_id.as_ptr(), &mut with_extra),
                FFIError::Ok as i32
            );

            let mut merged: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_merge(base, with_extra, &mut merged),
                FFIError::Ok as i32
            );

            let merged_cert = &*(&*merged).0;
            assert!(merged_cert.primary_key().key().has_secret());

            pgp_certificate_free(base);
            pgp_certificate_free(with_extra);
            pgp_certificate_free(merged);
        }
    }

    #[test]
    fn merge_rejects_unrelated_certificates() {
        unsafe {
            let alice = generate_cert("merge-alice@example.org");
            let bob = generate_cert("merge-bob@example.org");

            let mut merged: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_merge(alice, bob, &mut merged),
                FFIError::Failed as i32
            );
            assert!(merged.is_null());

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn merge_rejects_null_args() {
        unsafe {
            let base = generate_cert("merge-null@example.org");
            let other = generate_cert("merge-null-other@example.org");
            let mut merged: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_merge(ptr::null(), other, &mut merged),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_merge(base, ptr::null(), &mut merged),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_merge(base, other, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(base);
            pgp_certificate_free(other);
        }
    }

    // --- designated revoker ---

    #[test]
    fn revocation_keys_empty_for_fresh_cert() {
        unsafe {
            let cert = generate_cert("designated-revoker-fresh@example.org");

            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_revocation_keys(cert, &mut out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(out), "");

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn add_designated_revoker_lists_revoker() {
        unsafe {
            let alice = generate_cert("designated-revoker-alice@example.org");
            let bob = generate_cert("designated-revoker-bob@example.org");

            let mut bob_fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_fingerprint(bob, &mut bob_fp), FFIError::Ok as i32);
            let bob_fp = to_owned_c_string(bob_fp);

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_designated_revoker(alice, bob, &mut updated),
                FFIError::Ok as i32
            );
            assert!(!updated.is_null());

            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_revocation_keys(updated, &mut out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(out), format!("{bob_fp}\t0"));

            // The source cert must be untouched.
            let mut alice_out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_revocation_keys(alice, &mut alice_out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(alice_out), "");

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn add_designated_revoker_rejects_null_args() {
        unsafe {
            let alice = generate_cert("designated-revoker-null@example.org");
            let bob = generate_cert("designated-revoker-null-bob@example.org");
            let mut updated: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_add_designated_revoker(ptr::null(), bob, &mut updated),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_add_designated_revoker(alice, ptr::null(), &mut updated),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_add_designated_revoker(alice, bob, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn generate_revocation_armored_by_produces_applicable_revocation() {
        unsafe {
            let alice = generate_cert("designated-revoker-flow-alice@example.org");
            let bob = generate_cert("designated-revoker-flow-bob@example.org");

            let mut alice_with_revoker: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_add_designated_revoker(alice, bob, &mut alice_with_revoker),
                FFIError::Ok as i32
            );

            let message = CString::new("alice lost her key").unwrap();
            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_generate_revocation_armored_by(
                    bob,
                    alice_with_revoker,
                    ReasonForRevocation::KeyCompromised.into(),
                    message.as_ptr(),
                    &mut armored,
                ),
                FFIError::Ok as i32
            );
            let armored_str = to_owned_c_string(armored);
            assert!(armored_str.contains("BEGIN PGP SIGNATURE"));

            let armored_c = CString::new(armored_str).unwrap();
            let mut revoked_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_apply_revocation_armored(
                    alice_with_revoker,
                    armored_c.as_ptr(),
                    &mut revoked_cert,
                ),
                FFIError::Ok as i32
            );

            // A third-party revocation lands in Sequoia's unconfirmed
            // ("CouldBe") bucket, not the plain "Revoked" status that
            // `pgp_certificate_revocation_info` reports on: trusting it
            // requires the explicit designated-revoker check below.
            let mut revoked: u8 = 1;
            let mut reason: u8 = 0;
            let mut msg: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_revocation_info(revoked_cert, &mut revoked, &mut reason, &mut msg),
                FFIError::Ok as i32
            );
            assert_eq!(revoked, 0);
            libc::free(msg as *mut libc::c_void);

            let mut verified: u8 = 0;
            assert_eq!(
                pgp_certificate_verify_designated_revocation(revoked_cert, bob, &mut verified),
                FFIError::Ok as i32
            );
            assert_eq!(verified, 1);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(alice_with_revoker);
            pgp_certificate_free(revoked_cert);
        }
    }

    #[test]
    fn verify_designated_revocation_rejects_undeclared_revoker() {
        unsafe {
            let alice = generate_cert("designated-revoker-verify-undeclared-alice@example.org");
            let bob = generate_cert("designated-revoker-verify-undeclared-bob@example.org");

            // Bob was never designated, but forges an armored revocation and
            // it gets applied anyway (e.g. by a naive caller) -- verification
            // must still reject it since Alice never authorized Bob.
            let mut armored: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_generate_revocation_armored_by(
                    bob,
                    alice,
                    0,
                    ptr::null(),
                    &mut armored,
                ),
                FFIError::Ok as i32
            );
            let armored_str = to_owned_c_string(armored);
            let armored_c = CString::new(armored_str).unwrap();

            let mut revoked_cert: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_apply_revocation_armored(alice, armored_c.as_ptr(), &mut revoked_cert),
                FFIError::Ok as i32
            );

            let mut verified: u8 = 1;
            assert_eq!(
                pgp_certificate_verify_designated_revocation(revoked_cert, bob, &mut verified),
                FFIError::NotFound as i32
            );
            assert_eq!(verified, 0);

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            pgp_certificate_free(revoked_cert);
        }
    }

    #[test]
    fn verify_designated_revocation_rejects_null_args() {
        unsafe {
            let alice = generate_cert("designated-revoker-verify-null-alice@example.org");
            let bob = generate_cert("designated-revoker-verify-null-bob@example.org");
            let mut verified: u8 = 0;

            assert_eq!(
                pgp_certificate_verify_designated_revocation(ptr::null(), bob, &mut verified),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_verify_designated_revocation(alice, ptr::null(), &mut verified),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_verify_designated_revocation(alice, bob, ptr::null_mut()),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    #[test]
    fn generate_revocation_armored_by_rejects_null_args() {
        unsafe {
            let alice = generate_cert("designated-revoker-null-flow-alice@example.org");
            let bob = generate_cert("designated-revoker-null-flow-bob@example.org");
            let mut armored: *mut libc::c_char = ptr::null_mut();

            assert_eq!(
                pgp_certificate_generate_revocation_armored_by(
                    ptr::null(),
                    alice,
                    0,
                    ptr::null(),
                    &mut armored,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_generate_revocation_armored_by(
                    bob,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut armored,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_generate_revocation_armored_by(
                    bob,
                    alice,
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
        }
    }

    // --- algorithm preferences ---

    #[test]
    fn set_preferences_round_trips_algorithms_and_features() {
        unsafe {
            let cert = generate_cert("preferences-round-trip@example.org");

            // Sequoia's `CertBuilder` sets its own default preferences; snapshot
            // them so we can confirm the source cert is untouched below without
            // hardcoding those defaults.
            let mut before: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_preferences(cert, &mut before), FFIError::Ok as i32);
            let before = to_owned_c_string(before);

            let sym: [u8; 2] = [9, 7]; // AES256, AES128
            let hash: [u8; 2] = [8, 2]; // SHA256, SHA1
            let compression: [u8; 1] = [2]; // ZLIB
            let features: u8 = 0b0000_0001; // SEIPDv1

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_preferences(
                    cert,
                    sym.as_ptr(),
                    sym.len(),
                    hash.as_ptr(),
                    hash.len(),
                    compression.as_ptr(),
                    compression.len(),
                    features,
                    &mut updated,
                ),
                FFIError::Ok as i32
            );
            assert!(!updated.is_null());

            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_preferences(updated, &mut out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(out), "9,7\t8,2\t2\t1");

            // The source cert must be untouched.
            let mut source_out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_preferences(cert, &mut source_out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(source_out), before);

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn set_preferences_allows_empty_lists() {
        unsafe {
            let cert = generate_cert("preferences-empty@example.org");

            let mut updated: *mut Certificate = ptr::null_mut();
            assert_eq!(
                pgp_certificate_set_preferences(
                    cert,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    &mut updated,
                ),
                FFIError::Ok as i32
            );
            assert!(!updated.is_null());

            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(pgp_certificate_preferences(updated, &mut out), FFIError::Ok as i32);
            assert_eq!(to_owned_c_string(out), "\t\t\t0");

            pgp_certificate_free(cert);
            pgp_certificate_free(updated);
        }
    }

    #[test]
    fn set_preferences_rejects_null_args() {
        unsafe {
            let cert = generate_cert("preferences-null@example.org");
            let sym: [u8; 1] = [9];
            let mut updated: *mut Certificate = ptr::null_mut();

            assert_eq!(
                pgp_certificate_set_preferences(
                    ptr::null(),
                    sym.as_ptr(),
                    sym.len(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    &mut updated,
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_set_preferences(
                    cert,
                    sym.as_ptr(),
                    sym.len(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );
            // Non-null length with a null pointer is rejected.
            assert_eq!(
                pgp_certificate_set_preferences(
                    cert,
                    ptr::null(),
                    2,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    0,
                    &mut updated,
                ),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn preferences_rejects_null_args() {
        unsafe {
            let mut out: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_certificate_preferences(ptr::null(), &mut out),
                FFIError::Null as i32
            );

            let cert = generate_cert("preferences-read-null@example.org");
            assert_eq!(
                pgp_certificate_preferences(cert, ptr::null_mut()),
                FFIError::Null as i32
            );
            pgp_certificate_free(cert);
        }
    }

    // --- file-based streaming operations ---

    #[test]
    fn encrypt_file_decrypt_file_round_trip() {
        unsafe {
            let cert = generate_cert("file-crypt@example.org");
            let input_path = unique_temp_path("plain.txt");
            let encrypted_path = unique_temp_path("cipher.asc");
            let decrypted_path = unique_temp_path("plain.out");
            std::fs::write(&input_path, b"streamed to disk, not memory").unwrap();

            let c_input = CString::new(input_path.to_str().unwrap()).unwrap();
            let c_encrypted = CString::new(encrypted_path.to_str().unwrap()).unwrap();
            let rc = pgp_certificate_encrypt_file(cert, c_input.as_ptr(), c_encrypted.as_ptr());
            assert_eq!(rc, FFIError::Ok as i32);
            assert!(encrypted_path.exists());

            let c_decrypted = CString::new(decrypted_path.to_str().unwrap()).unwrap();
            let rc =
                pgp_certificate_decrypt_file(cert, c_encrypted.as_ptr(), c_decrypted.as_ptr());
            assert_eq!(rc, FFIError::Ok as i32);

            let plaintext = std::fs::read(&decrypted_path).unwrap();
            assert_eq!(plaintext, b"streamed to disk, not memory");

            pgp_certificate_free(cert);
            let _ = std::fs::remove_file(&input_path);
            let _ = std::fs::remove_file(&encrypted_path);
            let _ = std::fs::remove_file(&decrypted_path);
        }
    }

    #[test]
    fn decrypt_file_rejects_missing_input_and_cleans_up_no_output() {
        unsafe {
            let cert = generate_cert("file-missing-input@example.org");
            let missing_input = unique_temp_path("does-not-exist.asc");
            let output_path = unique_temp_path("out.txt");

            let c_input = CString::new(missing_input.to_str().unwrap()).unwrap();
            let c_output = CString::new(output_path.to_str().unwrap()).unwrap();
            let rc = pgp_certificate_decrypt_file(cert, c_input.as_ptr(), c_output.as_ptr());
            assert_eq!(rc, FFIError::Invalid as i32);

            pgp_certificate_free(cert);
            let _ = std::fs::remove_file(&output_path);
        }
    }

    #[test]
    fn encrypt_file_rejects_null_args() {
        unsafe {
            let cert = generate_cert("file-null@example.org");
            let path = CString::new("/tmp/whatever").unwrap();
            assert_eq!(
                pgp_certificate_encrypt_file(ptr::null(), path.as_ptr(), path.as_ptr()),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_encrypt_file(cert, ptr::null(), path.as_ptr()),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_certificate_encrypt_file(cert, path.as_ptr(), ptr::null()),
                FFIError::Null as i32
            );
            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn encrypt_and_sign_file_decrypt_and_verify_file_round_trip() {
        unsafe {
            let signer = generate_cert("file-signer@example.org");
            let recipient = generate_cert("file-recipient@example.org");
            let input_path = unique_temp_path("sign-plain.txt");
            let encrypted_path = unique_temp_path("sign-cipher.asc");
            let decrypted_path = unique_temp_path("sign-plain.out");
            std::fs::write(&input_path, b"large signed payload streamed").unwrap();

            let c_input = CString::new(input_path.to_str().unwrap()).unwrap();
            let c_encrypted = CString::new(encrypted_path.to_str().unwrap()).unwrap();
            let recipients: [*const Certificate; 1] = [recipient];
            let rc = pgp_encrypt_and_sign_file(
                signer,
                recipients.as_ptr(),
                1,
                c_input.as_ptr(),
                c_encrypted.as_ptr(),
            );
            assert_eq!(rc, FFIError::Ok as i32);

            let c_decrypted = CString::new(decrypted_path.to_str().unwrap()).unwrap();
            let mut fingerprint_out: *mut libc::c_char = ptr::null_mut();
            let mut epoch: i64 = 0;
            let rc = pgp_decrypt_and_verify_file(
                recipient,
                signer,
                c_encrypted.as_ptr(),
                c_decrypted.as_ptr(),
                &mut fingerprint_out,
                &mut epoch,
            );
            assert_eq!(rc, FFIError::Ok as i32);
            assert!(!fingerprint_out.is_null());
            assert!(epoch > 0);

            let plaintext = std::fs::read(&decrypted_path).unwrap();
            assert_eq!(plaintext, b"large signed payload streamed");

            libc::free(fingerprint_out as *mut libc::c_void);
            pgp_certificate_free(signer);
            pgp_certificate_free(recipient);
            let _ = std::fs::remove_file(&input_path);
            let _ = std::fs::remove_file(&encrypted_path);
            let _ = std::fs::remove_file(&decrypted_path);
        }
    }

    #[test]
    fn decrypt_and_verify_file_rejects_null_args() {
        unsafe {
            let cert = generate_cert("file-verify-null@example.org");
            let path = CString::new("/tmp/whatever").unwrap();
            let mut fp: *mut libc::c_char = ptr::null_mut();
            assert_eq!(
                pgp_decrypt_and_verify_file(
                    ptr::null(),
                    cert,
                    path.as_ptr(),
                    path.as_ptr(),
                    &mut fp,
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_decrypt_and_verify_file(
                    cert,
                    cert,
                    path.as_ptr(),
                    path.as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                FFIError::Null as i32
            );
            pgp_certificate_free(cert);
        }
    }

    #[test]
    fn encrypt_to_recipients_file_round_trip_both_recipients_decrypt() {
        unsafe {
            let alice = generate_cert("recipients-file-alice@example.org");
            let bob = generate_cert("recipients-file-bob@example.org");
            let input_path = unique_temp_path("multi-plain.txt");
            let encrypted_path = unique_temp_path("multi-cipher.asc");
            let alice_out = unique_temp_path("multi-alice.out");
            let bob_out = unique_temp_path("multi-bob.out");
            std::fs::write(&input_path, b"streamed to two recipients").unwrap();

            let certs = [alice as *const Certificate, bob as *const Certificate];
            let c_input = CString::new(input_path.to_str().unwrap()).unwrap();
            let c_encrypted = CString::new(encrypted_path.to_str().unwrap()).unwrap();
            let rc = pgp_encrypt_to_recipients_file(
                certs.as_ptr(),
                certs.len(),
                c_input.as_ptr(),
                c_encrypted.as_ptr(),
            );
            assert_eq!(rc, FFIError::Ok as i32);
            assert!(encrypted_path.exists());

            let c_alice_out = CString::new(alice_out.to_str().unwrap()).unwrap();
            let rc = pgp_certificate_decrypt_file(alice, c_encrypted.as_ptr(), c_alice_out.as_ptr());
            assert_eq!(rc, FFIError::Ok as i32);
            assert_eq!(std::fs::read(&alice_out).unwrap(), b"streamed to two recipients");

            let c_bob_out = CString::new(bob_out.to_str().unwrap()).unwrap();
            let rc = pgp_certificate_decrypt_file(bob, c_encrypted.as_ptr(), c_bob_out.as_ptr());
            assert_eq!(rc, FFIError::Ok as i32);
            assert_eq!(std::fs::read(&bob_out).unwrap(), b"streamed to two recipients");

            pgp_certificate_free(alice);
            pgp_certificate_free(bob);
            let _ = std::fs::remove_file(&input_path);
            let _ = std::fs::remove_file(&encrypted_path);
            let _ = std::fs::remove_file(&alice_out);
            let _ = std::fs::remove_file(&bob_out);
        }
    }

    #[test]
    fn encrypt_to_recipients_file_rejects_zero_count_and_null_args() {
        unsafe {
            let cert = generate_cert("recipients-file-null@example.org");
            let certs = [cert as *const Certificate];
            let path = CString::new("/tmp/whatever").unwrap();

            assert_eq!(
                pgp_encrypt_to_recipients_file(certs.as_ptr(), 0, path.as_ptr(), path.as_ptr()),
                FFIError::NotFound as i32
            );
            assert_eq!(
                pgp_encrypt_to_recipients_file(ptr::null(), 1, path.as_ptr(), path.as_ptr()),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_encrypt_to_recipients_file(certs.as_ptr(), 1, ptr::null(), path.as_ptr()),
                FFIError::Null as i32
            );
            assert_eq!(
                pgp_encrypt_to_recipients_file(certs.as_ptr(), 1, path.as_ptr(), ptr::null()),
                FFIError::Null as i32
            );

            pgp_certificate_free(cert);
        }
    }
}
