# pgp

OpenPGP workspace for Dart backed by `sequoia-openpgp` over `dart:ffi`.

## Packages

- [`packages/pgp_dart`](packages/pgp_dart/README.md): Pure-Dart OpenPGP value types, algorithm enums, and `PgpException` with no native or Flutter dependencies.
- [`packages/pgp`](packages/pgp/README.md): Pure-Dart FFI bindings re-exporting `pgp_dart`, plus the native `pgp-ffi` Rust crate under [`packages/pgp/native`](packages/pgp/native/README.md) bundled through `hook/build.dart`.

## Build Hook Resolution

`packages/pgp/hook/build.dart` resolves `libpgp_ffi` in three tiers:

1. `local_lib` user-define override pointing to a local shared library.
2. Prebuilt `.tar.gz` release archive verified by SHA-256 (configured via pinned checksums or `prebuilt_base_url` / `prebuilt_sha256` user defines).
3. Source build via `RustBuilder` (`native_toolchain_rust`), using `crypto-cng` on Windows and `crypto-openssl-vendored` on Unix/Android/iOS/macOS, with `--locked` builds, Android RELR opt-out and 16 KB ELF page alignment, and Apple deployment targets.

## Development

```bash
dart pub get
dart format --output none --set-exit-if-changed packages/pgp_dart packages/pgp
dart analyze packages/pgp_dart packages/pgp
(cd packages/pgp_dart && dart test)
(cd packages/pgp && dart test)
(cd packages/pgp/native && cargo test --locked --lib)
./tool/consumer_build.sh
```
