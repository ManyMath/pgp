# `pgp`
OpenPGP and Sequoia for Dart, backed by the `pgp-ffi` Rust crate.

`package:pgp` is the Flutter-free, pure-Dart `dart:ffi` binding over a prebuilt
native library (`libpgp_ffi.{so,dylib,dll}`). It does not ship or build the
binary for you; build the crate first (see
[Building the native library](#building-the-native-library)). A separate
`pgp_flutter` package will build and bundle it via cargokit for Flutter apps.

## Getting started
Add the package:
```sh
dart pub add pgp
```

Generate a certificate, share its public key, encrypt/decrypt, sign/verify, and
export the secret key for storage:
```dart
import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();
  final cert = pgp.generateKey('someone@example.org');
  final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

  final encrypted = publicCert.encrypt('hello');
  print(cert.decrypt(encrypted));

  final signed = cert.sign('hello');
  print(publicCert.verify(signed));

  print(cert.exportSecretArmored());
  publicCert.dispose();
  cert.dispose();
}
```

The package intentionally exposes common certificate and message workflows, not
the full OpenPGP packet/keyserver surface:

- generate certificates with encryption and signing subkeys, optionally with
  an expiration or a passphrase-locked secret key
- import and export ASCII-armored public and secret certificates
- encrypt/decrypt and sign/verify ASCII-armored text messages, or raw bytes
- multi-recipient and signed+encrypted messages
- detached and cleartext signatures
- symmetric (passphrase-only) encryption and decryption
- add/revoke user IDs, add/revoke subkeys, and revoke certificates
- inspect certificates: fingerprint, user IDs, and expiration

See `example/pgp_example.dart` for the supported operations in one program.
Build the native library first, then run it from the package root:
```sh
dart run example/pgp_example.dart
```

## Building the native library
The package loads `libpgp_ffi` at runtime via `DynamicLibrary.open`. The crate
lives in the `pgp-ffi` git submodule; build it with `cargo`:
```sh
git submodule update --init   # fetch pgp-ffi if needed
cargo build --release --manifest-path pgp-ffi/Cargo.toml
```
The artifact lands in `pgp-ffi/target/release/`: `libpgp_ffi.so` (Linux),
`libpgp_ffi.dylib` (macOS), or `pgp_ffi.dll` (Windows).

The loader searches that directory relative to the current directory, so
running from the package root works without copying anything. For a compiled
executable, put the library on the dynamic library search path: next to the
executable (or its `lib/`), in the working directory (or its `lib/`), or on
`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / `PATH`. If loading fails, the package
throws an `ArgumentError` listing every path it tried.

## Development
- To generate the `lib/src/pgp-ffi_bindings_generated.dart` bindings for the
  `pgp-ffi` C header:
  ```
  dart run ffigen --config ffigen.yaml
  ```
- New bindings expose opaque pointers and status codes.  Each native function
  needs a hand-written wrapper in `lib/src/pgp_base.dart` (see `generateKey`).
