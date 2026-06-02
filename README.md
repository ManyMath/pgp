# `pgp-ffi`
A crate to provide FFI bindings for OpenPGP and Sequoia.

## Dependencies
This crate uses `sequoia-openpgp` with the `crypto-rust` backend, so it does **not** require `nettle` / `nettle-dev` system packages to build.

For the optional in-repo C smoke test (`test.c`), you’ll need a C compiler (e.g., `gcc` or `clang`).

## Development
- Install `cbindgen`: `cargo install --force cbindgen`.
- `cargo build` regenerates `pgp-ffi.h` automatically via `build.rs`.
- To run the C smoke test:
  - `cargo build`
  - `gcc test.c -I. -L./target/debug -lpgp_ffi -o test_runner`
  - `LD_LIBRARY_PATH=./target/debug ./test_runner`
