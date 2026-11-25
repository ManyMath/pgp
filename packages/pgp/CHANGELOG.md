## 0.0.2

- Repurposed `pgp` as a pure-Dart package (removing the Flutter SDK requirement) that depends on and re-exports `package:pgp_dart/pgp_dart.dart`.
- Moved `pgp-ffi` into `packages/pgp/native` and added `hook/build.dart` with three-tier asset resolution (`local_lib`, SHA-256-verified prebuilt archives, and `RustBuilder` with `--locked` builds, Windows `crypto-cng`, Android RELR opt-out and 16 KB ELF alignment, and Apple deployment targets).
- Switched bindings to `@Native` (`ffigen` 23) and added idempotent `ensureNativeLibrary()`.
- Added `signDetachedBytes`, `signDetachedFile`, `verifyDetachedBytes`, `verifyDetachedRawBytes`, `verifyDetachedFile`, `verifyDetachedFileRaw`, and `verifyDetachedWithSigner`.
- Added optional `{DateTime? at}` reference timestamps across verification methods, surfaced `PgpException.message` from `pgp_last_error_message`, and exposed `hashAlgorithmCode` / `hashAlgorithm` on verified results.
- Added `SessionKeyInfo.algorithm`, streaming file operations (`encryptFile`, `decryptFile`, `encryptToRecipientsFile`, `encryptAndSignFile`, `decryptAndVerifyFile`), algorithm preference management (`setPreferences`, `preferences`), local certifications (`certifyUserIdExportable`), session key recovery (`sessionKey`, `decryptWithSessionKey`), trust signatures (`certifyUserIdWithTrust`), and designated revokers.

## 0.0.1

- Published Flutter plugin release bundling `pgp_ffi` via Cargokit and re-exporting `pgp_dart` 0.0.1.

## 0.0.1-dev.9

- Upgraded `sequoia-openpgp` to 2.4.0 (addressing RUSTSEC-2025-0136) and updated `verifyUserIdCertification` fallback matching for legacy bare key IDs.

## 0.0.1-dev.8

- Added `PGP.messageRecipientKeyIds`, signature `signedAtEpoch` metadata, symmetric sign+verify, `verifyUserIdCertification`, `CipherSuite` key generation, standalone revocations, `setPrimaryUserId`, `revocationInfo`, `merge`, `userIdCertifications`, `lock`, `revokeUserIdCertification`, `addAuthenticationSubkey`, `userIdsInfo`, `certifyUserId`, `setSubkeyExpiry`, `*WithSigner` variants, `subkeys`, and revocation reasons.

## 0.0.1-dev.7

- Added multi-recipient encryption, certificate inspection, passphrase-protected keys, detached signatures, expiration helpers, signed+encrypted messages, byte APIs, cleartext signatures, and symmetric encryption.

## 0.0.1-dev.6

- Added armored text encrypt/decrypt and sign/verify workflows plus explicit public/secret exports.

## 0.0.1-dev.5

- Removed earlier native assets hook in favor of dynamic loading from prebuilt search paths.

## 0.0.1-dev.4

- Added certificate revocation, subkey, and user ID management APIs.

## 0.0.1-dev.3

- Updated `PGP` to return opaque `Certificate` handles with explicit `dispose()`.

## 0.0.1-dev.1

- Initial release.
