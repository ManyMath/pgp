# `pgp-ffi`
A crate to provide FFI bindings for OpenPGP and Sequoia.

## Dependencies
The crypto backend is chosen with a cargo feature, one at a time:

| Feature | Backend | Notes |
|---|---|---|
| `crypto-rust` (default) | RustCrypto | No system libraries. Sequoia marks it experimental and variable-time, so this crate enables `allow-experimental-crypto` and `allow-variable-time-crypto` for it. Development only. |
| `crypto-openssl` | OpenSSL | Needs OpenSSL headers. |
| `crypto-nettle` | Nettle | Needs `nettle-dev`. |

For example: `cargo build --release --no-default-features --features crypto-openssl`.

`cargo audit` currently reports RUSTSEC-2026-0387 (`crypto-bigint`) and
RUSTSEC-2023-0071 (`rsa`, no fix) against the `crypto-rust` tree.

For the optional in-repo C smoke test (`test.c`), you'll need a C compiler (e.g., `gcc` or `clang`).

## Development
- Install `cbindgen`: `cargo install --force cbindgen`.
- `cargo build` regenerates `pgp-ffi.h` automatically via `build.rs`.
- To run the C smoke test:
  - `cargo build`
  - `gcc test.c -I. -L./target/debug -lpgp_ffi -o test_runner`
  - `LD_LIBRARY_PATH=./target/debug ./test_runner`
