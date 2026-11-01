## Unreleased

- Renamed the package from `pgp` to `pgp_dart` and moved it to
  `packages/pgp_dart` in a workspace with `pgp_flutter`, which now holds the
  `pgp-ffi` crate and builds it with cargokit. The loader also finds the
  library a Flutter app bundles, honors `PGP_DART_LIB` and
  `nativeLibraryOverridePath`, and searches the crate's build output from the
  current directory upward. Added `ensureNativeLibrary`.

- Removed secret-key export printing from the README quickstart and example,
  and added a status note: development code, no pub.dev release.

- Added `pgp_free` to `pgp-ffi` and used it for every buffer the library
  returns. Dart previously freed them with `calloc.free`, which is
  `CoTaskMemFree` on Windows and does not match libc `malloc`.

- `pgp-ffi` now selects its crypto backend with the `crypto-openssl-vendored`
  (default), `crypto-openssl`, `crypto-nettle` and `crypto-rust` features, and
  carries crates.io metadata. The default tree no longer contains the
  `crypto-bigint`, `ctutils` or `rsa` crates flagged by `cargo audit`.

- Added `SessionKeyInfo.algorithm`, a typed `SymmetricAlgorithmPreference?`
  view of `SessionKeyInfo.algo` (the existing raw RFC 4880 algorithm code,
  left unchanged), matching every other algorithm-code field in the package
  already having a typed enum. Returns `null` for a code the enum doesn't
  cover instead of throwing.

- Added `PGP.encryptToRecipientsFile(recipients, inputPath, outputPath)`, the
  multi-recipient counterpart to `Certificate.encryptFile` (which only
  supported a single recipient): the one file-based entry point missing from
  the previous release's streaming feature, since `encryptToRecipients`/
  `encryptBytesToRecipients` already supported an arbitrary recipient list in
  memory. Any recipient can decrypt the result with the existing
  `Certificate.decryptFile`.

- Added file-based streaming encrypt/decrypt/sign/verify:
  `Certificate.encryptFile(inputPath, outputPath)`,
  `Certificate.decryptFile(inputPath, outputPath)`,
  `PGP.encryptAndSignFile(signer, recipients, inputPath, outputPath)`, and
  `Certificate.decryptAndVerifyFile(inputPath, outputPath, verifyCert)`
  (returning a new `FileSignatureInfo`). Every previous encrypt/decrypt/sign
  entry point required the whole plaintext or ciphertext to already be an
  in-memory `String`/`Uint8List`, so encrypting a file larger than would
  comfortably fit in RAM (e.g. a multi-gigabyte backup) required holding
  several times its size in spare memory. The new native entry points
  (`pgp_certificate_encrypt_file`, `pgp_certificate_decrypt_file`,
  `pgp_encrypt_and_sign_file`, `pgp_decrypt_and_verify_file`) stream directly
  between files via Sequoia's `Read`/`Write`-based API, so peak memory use no
  longer scales with file size; on failure, any output file already created
  is removed rather than left behind as an unusable partial result. Added 5
  Rust unit tests, a `test.c` round-trip step, and regenerated the C header
  and Dart bindings.

- Added `Certificate.setPreferences({symmetricAlgorithms, hashAlgorithms,
  compressionAlgorithms, features})` and `Certificate.preferences()`,
  exposing the RFC 4880 algorithm-preference and Features self-signature
  subpackets that tell other OpenPGP implementations which
  symmetric/hash/compression algorithms and optional features (e.g.
  SEIPDv2/AEAD) a certificate supports. Previously these subpackets were
  never touched, leaving certificates at Sequoia's own defaults with no way
  to override or inspect them. New `SymmetricAlgorithmPreference`,
  `HashAlgorithmPreference`, and `CompressionAlgorithmPreference` enums carry
  the relevant RFC 4880 wire-format codes.

- Added `Certificate.certifyUserIdExportable(target, userId, {exportable})`,
  GnuPG's `--lsign-key` "local certification" concept: a certification with
  `exportable: false` is fully present and inspectable in memory but is
  silently dropped by `exportPublicArmored`, so it never leaks onto a
  keyserver. **Behavior fix:** `exportPublicArmored` now calls Sequoia's
  `.export()` instead of `.serialize()`, which is what actually enforces
  this (and also drops "sensitive" designated-revoker entries per RFC 4880);
  this has no effect on certificates that don't use either feature.
  `userIdCertifications` gains an additive `isExportable` field on
  `CertifierInfo` (always `true` for a plain `certifyUserId` certification).

- Added `Certificate.sessionKey(message)`, recovering a message's symmetric
  session key without decrypting the message body, and the static
  `PGP.decryptWithSessionKey(sessionKeyInfo, message)`, decrypting a message
  from a session key alone with no certificate or secret key material at
  all. Together these enable archival/escrow decryption workflows without
  exposing a long-term secret key to whoever holds the session key.

- Added `Certificate.certifyUserIdWithTrust`, a trust-signature variant of
  `certifyUserId` that records an RFC 4880 Trust Signature (delegation
  depth and confidence amount) on the certification, letting a certifier
  be trusted to introduce other trusted certifiers. `userIdCertifications`
  now also reports `trustDepth`/`trustAmount` on every `CertifierInfo`
  (both `0` for a plain `certifyUserId` certification).

- Added designated-revoker support (RFC 4880's `gpg --edit-key addrevoker`
  mechanism): `Certificate.addDesignatedRevoker` authorizes another
  certificate to revoke this one on its behalf (a recovery path for a lost
  or compromised secret key/passphrase); `Certificate.revocationKeys` lists
  configured revokers; `Certificate.generateRevocationArmoredFor` lets the
  designated revoker produce a standalone armored revocation for the target
  (applied via the existing `applyRevocationArmored`); and
  `Certificate.verifyDesignatedRevocation` cryptographically confirms such a
  revocation was genuinely authorized, since a third-party revocation signature
  is not automatically reflected by `revocationInfo`.

## 0.0.1-dev.9

- Upgraded dev-only tooling dependencies: `ffigen` from 14.x to 20.1.1 and
  `lints` from 4.x to 6.1.0. Neither is a runtime dependency: the
  regenerated FFI bindings came out functionally identical (only an added
  `unused_import` lint suppression comment changed) and `dart analyze`
  reports no new issues under the newer lint set.

- Upgraded the internal `sequoia-openpgp` dependency from 1.22.0 to 2.4.0,
  fixing RUSTSEC-2025-0136 (a medium-severity integer underflow in AES key
  unwrapping). Internal dependency bump only: no public Dart API change.

- `Certificate.verifyUserIdCertification` (and the underlying
  `pgp_certificate_verify_userid_certification`) now also matches
  certifications that carry only a legacy bare-key-ID `Issuer` subpacket and
  no modern `IssuerFingerprint` subpacket: previously such a certification
  (never produced by this library's own `certifyUserId`, but possible from
  other, older OpenPGP implementations) would report `NotFound` even if it
  was genuinely issued by the given issuer.

## 0.0.1-dev.8

- Add `PGP.messageRecipientKeyIds(armoredMessage)`, listing the recipient
  key IDs an encrypted message is addressed to (or `"hidden"` for a
  wildcard recipient) without decrypting it or needing any secret key
  material: useful for a multi-key client to pick which of its keys can
  open a message before attempting decryption.
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
