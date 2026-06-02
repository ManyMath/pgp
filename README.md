# `pgp-ffi`
A crate to provide FFI bindings for OpenPGP and Sequoia.

## Dependencies
The system library `nettle` required by crate `nettle-sys`.  See 
https://gitlab.com/sequoia-pgp/nettle-sys#building for more information.

If you are using Debian (or a derivative), try:
```
$ sudo apt install clang llvm pkg-config nettle-dev
```

If you are using Arch (or a derivative), try:
```
$ sudo pacman -S clang pkg-config nettle --needed
```

If you are using Fedora (or a derivative), try:
```
$ sudo dnf install clang pkg-config nettle-devel
```

## Development
- Install `cbindgen`: `cargo install --force cbindgen`.
- To generate `pgp-ffi.h` C bindings for Rust, use `cbindgen` in the
  `pgp-ffi` directory:
  ```
  cbindgen --config cbindgen.toml --crate pgp-ffi --output pgp-ffi.h
  ```
