# Private pgp payload verification

Run `python3 -m unittest discover -s tool/tests -v`, then
`python3 tool/native_payload.py --config tool/payload.json --mode candidate --output /tmp/pgp-candidate`.
Use a new output directory for each run. The gate snapshots the checkout,
creates the actual `pgp_dart` and `pgp_flutter` pub archives with the pinned
Dart SDK, checks their sources, Cargo path closure, platform contracts and
cargokit provenance, then builds a fresh Flutter consumer from the extracted
archives. On Linux and Windows a Dart consumer also loads the exact bundled
library through `PGP_DART_LIB`, checks the null-handle ABI and round-trips a
generated key. No registry publication occurs.

`--mode hosted` fails until `pgp_dart` is published, which is expected.

Provision Dart 3.13.2, Flutter, Python 3.12+, and Rust stable plus the required
targets; the gate never installs them. Android, iOS, Linux and macOS builds
compile OpenSSL from source (perl, make, a C compiler, and libclang for
bindgen). Windows builds use
`packages/pgp_flutter/windows/rust`, which wraps the crate with the CNG backend
and needs only the MSVC toolchain. The gate sets RUSTUP_WINDOWS_PATH_ADD_BIN=1
for its children: rustup proxies installed as symlinks cannot be started by
processes that enforce redirection trust (os error 448). The gate copies the
working tree, so run it from a checkout without example build output; Windows
build paths under it exceed MAX_PATH.

Android APK consumers: set ANDROID_SDK_ROOT to an SDK with platform 36,
build-tools 36.0.0 and NDK 28.2.13676358 installed, then run the gate with
`--target apk`. Evidence binds the APK and every expected native ABI to SHA256.
This is build and packaging validation, not device behavior.

Cargokit is pinned by `tool/cargokit/manifest.json`; see
[cargokit/README.md](cargokit/README.md) and `tool/cargokit_sync.py --check`.
