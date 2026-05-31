## 0.0.1-dev.7

- Add `PGP.encryptToRecipients` for multi-recipient encryption.
- Add certificate inspection: `fingerprint`, `userIds`, `expiryEpoch`, and
  `info` (returns a `CertificateInfo`).
- Add passphrase-protected private keys: `PGP.generateLockedKey` and
  `Certificate.unlock`.
- Add detached signatures: `Certificate.signDetached` and
  `Certificate.verifyDetached`.
- Add key expiration: `PGP.generateKeyWithExpiry` and
  `Certificate.setExpiry`.
- Add signed and encrypted messages: `PGP.encryptAndSign` and
  `Certificate.decryptAndVerify` (returns a `SignedPlaintext`).
- Add a binary data (bytes) API: `Certificate.encryptBytes`/`decryptBytes`,
  `Certificate.signBytes`/`verifyBytes`, and
  `PGP.encryptBytesToRecipients`.
- Add cleartext signatures: `Certificate.signCleartext` and
  `Certificate.verifyCleartext`.
- Add symmetric (passphrase-only) encryption: `PGP.encryptSymmetric` and
  `PGP.decryptSymmetric`.

## 0.0.1-dev.6

- Add common message workflows: encrypt/decrypt ASCII-armored text messages
  and sign/verify ASCII-armored text messages.
- Generate certificates with both transport-encryption and signing subkeys.
- Add explicit public and secret certificate export methods:
  `exportPublicArmored` and `exportSecretArmored`.

## 0.0.1-dev.5

- Remove native_toolchain_rust builds.  Drop the Dart Native Assets build hook 
  and the `native_assets_cli` / `native_toolchain_rust_mirror` dependencies.
  The package now loads a prebuilt `libpgp_ffi` at runtime via 
  `DynamicLibrary.open`, searching the executable and working directories plus 
  `pgp-ffi/target/release/`. Build the crate yourself with 
  `cargo build --release --manifest-path pgp-ffi/Cargo.toml`.

## 0.0.1-dev.4

- Add certificate key management following `pgp-ffi`: `exportArmored`,
  `revoke`, `addTransportEncryptionSubkey`, `revokeSubkey`, `addUserId`, and
  `revokeUserId` on `Certificate`.

## 0.0.1-dev.3

- Track `pgp-ffi` opaque certificate types.  `PGP` now returns `Certificate`
  handles from `generateKey` and `certificateFromArmored`; release them with
  `Certificate.dispose`.

## 0.0.1-dev.1

- Initial version.
