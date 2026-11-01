# `pgp_dart`
OpenPGP for Dart, backed by [Sequoia](https://sequoia-pgp.org) through the
`pgp-ffi` Rust crate.

`pgp_dart` is the Flutter-free, pure-Dart `dart:ffi` binding over the native
`pgp_ffi` library (`libpgp_ffi.{so,dylib}`, `pgp_ffi.dll`). It does not build
the library itself: Flutter apps should depend on
[`pgp_flutter`](../pgp_flutter), which builds and bundles it with cargokit;
CLI tools build the crate once (see
[Building the native library](#building-the-native-library)).

## Status
Development code. The native library links a statically built OpenSSL by
default; Sequoia's pure-Rust backend, which is experimental and variable-time
with open timing advisories, is an opt-in `crypto-rust` feature for
development. See
[`pgp_flutter/rust/README.md`](../pgp_flutter/rust/README.md). Neither package
is published to pub.dev yet.

## Getting started
Add the package:
```sh
dart pub add pgp_dart
```

Generate a certificate, share its public key, encrypt/decrypt, and
sign/verify:
```dart
import 'package:pgp_dart/pgp_dart.dart';

void main() {
  final pgp = PGP();
  final cert = pgp.generateKey('someone@example.org');
  final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

  final encrypted = publicCert.encrypt('hello');
  print(cert.decrypt(encrypted));

  final signed = cert.sign('hello');
  print(publicCert.verify(signed));

  publicCert.dispose();
  cert.dispose();
}
```

The package supports these certificate and message operations. Low-level
packet editing and keyserver operations are outside its scope:

- generate certificates with encryption and signing subkeys, optionally with
  an expiration or a passphrase-locked secret key
- import and export ASCII-armored public and secret certificates
- encrypt/decrypt and sign/verify ASCII-armored text messages, or raw bytes
- multi-recipient and signed+encrypted messages
- detached and cleartext signatures
- symmetric (passphrase-only) encryption and decryption
- add/revoke user IDs, add/revoke subkeys, and revoke certificates
- inspect certificates: fingerprint, user IDs, and expiration

See `example/pgp_dart_example.dart` for the supported operations in one
program. Build the native library first, then run it:
```sh
dart run example/pgp_dart_example.dart
```

## Building the native library
The crate lives in `packages/pgp_flutter/rust/`. From the repository root:
```sh
cargo build --release --manifest-path packages/pgp_flutter/rust/Cargo.toml
```
The artifact lands in `packages/pgp_flutter/rust/target/release/`.

The loader tries, in order: `nativeLibraryOverridePath`, the `PGP_DART_LIB`
environment variable, the plain library name (the OS search path or a Flutter
app bundle), the `pgp_flutter` framework on Apple platforms, the executable's
directory (and its `lib/`), and the crate's `target/{release,debug}` directories
from the current directory upward, so `dart run` and `dart test` anywhere in
the repository work without copying anything. If loading fails it throws an
`ArgumentError` listing every path it tried. Call `ensureNativeLibrary()` to
load it eagerly.

## Development
- To generate the `lib/src/pgp-ffi_bindings_generated.dart` bindings for the
  `pgp-ffi` C header:
  ```
  dart run ffigen --config ffigen.yaml
  ```
- New bindings expose opaque pointers and status codes.  Each native function
  needs a hand-written wrapper in `lib/src/pgp_base.dart` (see `generateKey`).
