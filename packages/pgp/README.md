# pgp

Flutter integration for [`pgp_dart`](https://pub.dev/packages/pgp_dart):
OpenPGP backed by [Sequoia](https://sequoia-pgp.org).

This package builds the `pgp-ffi` Rust crate it ships in `rust/` automatically
(via [cargokit](https://github.com/ManyMath/cargokit)) and bundles it with your
app, then re-exports the full `pgp_dart` API.

```dart
import 'package:pgp/pgp.dart';

await PgpFlutter.ensureInitialized();
final pgp = PGP();
final cert = pgp.generateKey('someone@example.org');
final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());
print(cert.decrypt(publicCert.encrypt('hello')));
publicCert.dispose();
cert.dispose();
```

`PgpFlutter.certificateFromAsset` parses an armored certificate bundled as a
Flutter asset.

Integration tests live in `example/integration_test`. Run them against a
connected device, emulator or desktop target:

```sh
cd example
flutter test integration_test -d <device-id>
```

## Requirements

- Rust (`rustup`). There are no precompiled binaries yet.
- perl, make, a C compiler and libclang on Android, iOS, Linux and macOS: the
  crate builds OpenSSL from source and links it statically (the
  `crypto-openssl-vendored` feature), so apps need no system OpenSSL, and
  bindgen needs libclang to generate its bindings (Xcode and most Linux
  distributions' clang packages provide it).
- Windows builds use Sequoia's CNG backend through `windows/rust`, which wraps
  the crate with the `crypto-cng` feature, so they need only the Visual Studio
  toolchain Flutter already requires.
- iOS 13 or later; macOS 10.15 or later. On Apple platforms the podspec
  force-loads `libpgp_ffi.a` into the plugin's framework, so the app must
  link pods as frameworks (Flutter's default `use_frameworks!`). With static
  pod linkage the symbols never reach the app and `ensureInitialized` throws;
  the other ManyMath plugins share this limitation.

See [`rust/README.md`](rust/README.md) for the crate's backends.
