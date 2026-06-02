use std::ffi::{CStr, CString};
use std::os::raw::{c_char};
use std::io::{self, Write, Cursor};

use sequoia_openpgp as openpgp;

use crate::openpgp::cert::prelude::*;
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::types::SymmetricAlgorithm;
use crate::openpgp::serialize::stream::{Armorer, Message, Encryptor2, LiteralWriter};
use crate::openpgp::parse::{Parse, stream::*};
use crate::openpgp::policy::Policy;
use crate::openpgp::policy::StandardPolicy as P;
use sequoia_openpgp::serialize::Serialize;

/// Generates an encryption-capable key.
#[no_mangle]
pub extern "C" fn generate_key() -> *const c_char {
    match generate() {
        Ok(cert) => {
            let key_string = cert.to_string();  // Converts Cert to string for now
            let c_string = CString::new(key_string).unwrap();
            let ptr = c_string.into_raw();
            ptr // No need to call std::mem::forget
        }
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Exports the generated key in ASCII-armored format.
#[no_mangle]
pub extern "C" fn export_ascii_key(cert_str: *const c_char) -> *const c_char {
    let cert_string = convert_c_char_ptr_to_string(cert_str);

    let cert = match Cert::from_reader(&mut Cursor::new(cert_string.as_bytes())) {
        Ok(cert) => cert,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    match export_ascii_armored_key(&cert) {
        Ok(armored_key) => {
            let c_string = CString::new(armored_key).unwrap();
            let ptr = c_string.into_raw();
            ptr // No need to call std::mem::forget
        }
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Encrypts a message and returns the ciphertext.
#[no_mangle]
pub extern "C" fn encrypt_message(cert_str: *const c_char, message: *const c_char) -> *const c_char {
    let cert_string = convert_c_char_ptr_to_string(cert_str);
    let plaintext = convert_c_char_ptr_to_string(message);

    let cert = match Cert::from_reader(&mut Cursor::new(cert_string.as_bytes())) {
        Ok(cert) => cert,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    let mut ciphertext = Vec::new();
    let policy = &P::new();
    match encrypt(policy, &mut ciphertext, &plaintext, &cert) {
        Ok(_) => {
            let c_string = CString::new(ciphertext).unwrap();
            let ptr = c_string.into_raw();
            ptr // No need to call std::mem::forget
        }
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Decrypts a message and returns the plaintext.
#[no_mangle]
pub extern "C" fn decrypt_message(cert_str: *const c_char, ciphertext: *const c_char) -> *const c_char {
    let cert_string = convert_c_char_ptr_to_string(cert_str);
    let ciphertext = convert_c_char_ptr_to_string(ciphertext).into_bytes();

    let cert = match Cert::from_reader(&mut Cursor::new(cert_string.as_bytes())) {
        Ok(cert) => cert,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    let mut plaintext = Vec::new();
    let policy = &P::new();
    match decrypt(policy, &mut plaintext, &ciphertext, &cert) {
        Ok(_) => {
            let c_string = CString::new(plaintext).unwrap();
            let ptr = c_string.into_raw();
            ptr // No need to call std::mem::forget
        }
        Err(_) => CString::new("").unwrap().into_raw(),
    }
}

/// Helper function: Converts a C string pointer to a Rust string.
fn convert_c_char_ptr_to_string(c_char_ptr: *const c_char) -> String {
    let c_str = unsafe {
        assert!(!c_char_ptr.is_null());
        CStr::from_ptr(c_char_ptr)
    };
    c_str.to_string_lossy().into_owned()
}

/// Generates an encryption-capable key.
fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    Ok(cert)
}

/// Exports the generated key as ASCII-armored.
fn export_ascii_armored_key(cert: &openpgp::Cert) -> openpgp::Result<String> {
    let mut armored = Vec::new();

    // Create a message object for the armorer.
    let message = Message::new(&mut armored);

    // Create the armorer and serialize the key.
    let mut armorer = Armorer::new(message).build()?;

    cert.as_tsk().serialize(&mut armorer)?;
    armorer.finalize()?;

    Ok(String::from_utf8(armored).expect("Failed to convert armored key to UTF-8"))
}

/// Encrypts the given message.
fn encrypt(
    p: &dyn Policy,
    sink: &mut (dyn Write + Send + Sync),
    plaintext: &str,
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    let recipients = recipient
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let message = Encryptor2::for_recipients(message, recipients).build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is written.
    message.finalize()?;

    Ok(())
}

/// Decrypts the given message.
fn decrypt(
    p: &dyn Policy,
    sink: &mut dyn Write,
    ciphertext: &[u8],
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    let helper = Helper {
        secret: recipient,
        policy: p,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::Cert,
    policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let key = self
            .secret
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .for_transport_encryption()
            .next()
            .unwrap()
            .key()
            .clone();

        let mut pair = key.into_keypair()?;

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}
