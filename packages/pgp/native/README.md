# pgp-ffi

C FFI wrapper around `sequoia-openpgp` used by `package:pgp`.

## Crypto Backends

- Default: `crypto-openssl-vendored`
- Windows: `--no-default-features --features crypto-cng`
- Alternative features: `crypto-nettle`, `crypto-rust`

## Build and Test

```bash
cargo fmt --all --check
cargo clippy --locked --lib --tests --examples -- -D warnings
cargo test --locked --lib
cargo test --locked --lib --no-default-features --features crypto-rust
cargo deny --locked check advisories
cargo deny --locked --config deny-windows-cng.toml check advisories
```

Regenerate `pgp-ffi.h` and verify the C harness:

```bash
cargo build --release --locked --features header
gcc -Wall -Werror=implicit-function-declaration test.c -I. -L./target/release -lpgp_ffi -o test_runner
LD_LIBRARY_PATH=./target/release ./test_runner
```
