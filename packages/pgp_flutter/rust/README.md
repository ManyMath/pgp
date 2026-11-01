# `pgp-ffi`
A crate to provide FFI bindings for OpenPGP and Sequoia.

## Dependencies
The crypto backend is chosen with a cargo feature, one at a time:

| Feature | Backend | Notes |
|---|---|---|
| `crypto-openssl-vendored` (default) | OpenSSL, built from source and linked statically | Needs perl, make and a C compiler; no system OpenSSL. |
| `crypto-openssl` | System OpenSSL (3.0.7+) | Needs OpenSSL headers. |
| `crypto-nettle` | Nettle | Needs `nettle-dev`. Not tested here. |
| `crypto-cng` | Windows CNG | Windows only; needs nothing beyond the OS. `pgp_flutter` builds Windows with it. |
| `crypto-rust` | RustCrypto | Sequoia marks it experimental and variable-time, so this crate enables `allow-experimental-crypto` and `allow-variable-time-crypto` for it. Development only. |

For example: `cargo build --release --no-default-features --features crypto-rust`.

The RustCrypto crates are not in the default dependency tree, which keeps
RUSTSEC-2026-0387 (`crypto-bigint`), RUSTSEC-2026-0385 (`ctutils`) and
RUSTSEC-2023-0071 (`rsa`, no fix) out of the shipped library. They remain in
`Cargo.lock` for the `crypto-rust` feature.

## Development
- Install `cbindgen`: `cargo install --force cbindgen`.
- `cargo build --features header` regenerates `pgp-ffi.h` via `build.rs`.
- To run the C smoke test:
  - `cargo build`
  - `gcc test.c -I. -L./target/debug -lpgp_ffi -o test_runner`
  - `LD_LIBRARY_PATH=./target/debug ./test_runner`
