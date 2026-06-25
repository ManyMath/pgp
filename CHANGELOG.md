## Unreleased

- `SignedPlaintext` and `VerifiedBytes` gain a `signedAtEpoch` field (plus
  `hasSignedAt`/`signedAtDate` getters), populated by `verifyWithSigner`,
  `verifyBytesWithSigner`, `verifyCleartextWithSigner`, `decryptAndVerify`,
  and `decryptAndVerifySymmetric`: the signature's own creation time,
  previously discarded once the signer's fingerprint was confirmed.
- Add `Certificate.encryptAndSignSymmetric(plaintext, passphrase)` and
  `Certificate.decryptAndVerifySymmetric(message, passphrase)`: the
  passphrase-only counterpart to `PGP.encryptAndSign`/
  `Certificate.decryptAndVerify`, so a message can be passphrase-protected
  without a recipient public key while still being signed and verifiable.
- Add `Certificate.verifyUserIdCertification(issuer, userId)`,
  cryptographically confirming that `issuer` actually produced the
  third-party certification signature `userIdCertifications` reports:
  previously that listing only reported issuer fingerprints without
  verifying the signature against the issuer's key.
- Add `PGP.generateKeyWithCipherSuite(userId, cipherSuite)` and a
  `CipherSuite` enum (`cv25519` (default, matches `generateKey`), `rsa3k`,
  `p256`, `p384`, `p521`, `rsa2k`, `rsa4k`), so certificates can be
  generated with an algorithm other than the Curve25519 default: e.g. RSA
  for interoperating with targets that require it.
- Add `Certificate.generateRevocationArmored({reason, message})` and
  `Certificate.applyRevocationArmored(armored)`: the `gpg --gen-revoke`
  workflow. Generate and store a revocation certificate offline right after
  creating a key, so it can still be revoked later via
  `applyRevocationArmored` even if the secret key or its passphrase is
  subsequently lost; unlike `revoke`, applying a pre-generated revocation
  needs no secret key material at all.
- Add `Certificate.setPrimaryUserId(userId)`, promoting `userId` to the
  certificate's primary user ID (the one implementations show by default
  when a certificate has more than one): the mutation counterpart to the
  `isPrimary` flag `userIdsInfo()` already reports.
- Add `Certificate.revocationInfo()`, returning a `RevocationInfo`
  (`isRevoked`, `reasonCode`, `message`) describing whether the certificate
  itself has been revoked via `Certificate.revoke()`: the whole-certificate
  counterpart to the per-subkey/per-user-ID `isRevoked` flags already on
  `subkeys()`/`userIdsInfo()`, and the readback half of the reason/message
  `revoke()` already accepts as input.
- Add `Certificate.merge(other)`, importing updates from `other`: new
  signatures, certifications, subkeys, and revocations: into a combined
  certificate. `other` must share this certificate's primary-key fingerprint
  (an unrelated cert throws `PgpException(-3)`); `other`'s secret key
  material, if any, is always discarded, so only this certificate's own
  secret key survives into the result. Neither input is modified. This is
  the primitive for refreshing a locally-known certificate with data from a
  keyserver or a peer without losing local state.
- Add `Certificate.userIdCertifications(userId)`, returning a `CertifierInfo`
  per third-party certificate that has certified `userId` (fingerprint plus
  whether that certification has since been revoked): the inspection
  counterpart to `certifyUserId`/`revokeUserIdCertification`, which
  `userIdsInfo` didn't cover (it only reports self-signature state).
- Add `Certificate.lock(passphrase)`, the counterpart to `Certificate.unlock`:
  encrypts all currently-unencrypted secret key material with `passphrase`.
  Keys that are already passphrase-protected are left untouched; call
  `unlock` first to rotate an existing passphrase.
- Add `Certificate.revokeUserIdCertification(target, userId, {reason,
  message})`, the counterpart to `certifyUserId`: retracts this
  certificate's earlier third-party certification of `userId` on `target` by
  attaching a certification-revocation signature. `target` itself is left
  unmodified.
- Add `Certificate.addAuthenticationSubkey()`, mirroring
  `addSigningSubkey`/`addTransportEncryptionSubkey` for the third standard
  OpenPGP key-flag role (e.g. PGP-based SSH authentication). `subkeys()` and
  `SubkeyInfo` gain a `canAuthenticate` flag alongside `canEncrypt`/`canSign`.
- Add `Certificate.userIdsInfo()`, returning a `UserIdInfo` per user ID
  (revocation status, primary-user-ID flag, binding-signature expiry) using
  the same coverage as `userIds()`: closing the gap where `subkeys()` had
  rich metadata but the user ID equivalent didn't.
- Add `Certificate.certifyUserId(target, userId)`, a third-party
  certification primitive: certify another certificate's user ID with this
  certificate's key ("Alice vouches that this user ID belongs to Bob"),
  returning an updated copy of `target` carrying the new certification
  signature. `target` itself is left unmodified. This is the missing
  web-of-trust building block: previously `Certificate.addUserId` could only
  self-certify, with no way to attach a certification from a different key.
- Add `Certificate.setSubkeyExpiry(index, Duration?)` to update a single
  subkey's expiration independently of the primary key's and other subkeys'.
  `Certificate.subkeys` now reports each subkey's own `expiryEpoch` (plus
  `hasExpiry`/`expiryDate` getters).
- `Certificate.verify`, `verifyDetached`, `verifyBytes`, and `verifyCleartext`
  gain `...WithSigner`/`verifyDetachedSigner` counterparts that also return
  the fingerprint of the subkey that produced the signature (`verifyBytes`'s
  variant returns a new `VerifiedBytes`), closing a gap where only the
  sign+encrypt path (`decryptAndVerify`) exposed signer identity.
- Add subkey inspection: `Certificate.subkeys` returns a `SubkeyInfo` per
  subkey (fingerprint, capabilities, revocation status) using the same
  zero-based indexing as `revokeSubkey`, so callers no longer have to guess
  subkey indices.
- `Certificate.revoke`, `revokeSubkey`, and `revokeUserId` accept optional
  `reason` (a new `RevocationReason` enum) and `message` parameters, so the
  revocation signature records why a key, subkey, or user ID was revoked
  instead of always using a fixed, unspecified reason.

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
