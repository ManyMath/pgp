## 0.0.2

- Extracted `pgp_dart` into a pure-Dart model package with zero `dart:ffi` or Flutter dependencies.
- Added `PgpErrorCode` with `PgpErrorCode.fromCode` and `PgpException.errorCode`.
- Added `PgpException.message` to surface diagnostic strings from `pgp_last_error_message`.
- Added `hashAlgorithmCode` and typed `hashAlgorithm` getters on `SignedPlaintext`, `VerifiedBytes`, and `FileSignatureInfo`.
- Added `fromCode` lookup helpers across enums and `RevocationInfo.reason`.
- Retained `@Deprecated` `nativeLibraryOverridePath` compatibility shim for callers migrating to `package:pgp` build hooks.

## 0.0.1

- Initial pure-Dart release containing Sequoia FFI bindings and OpenPGP types.
