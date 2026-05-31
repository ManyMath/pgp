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

