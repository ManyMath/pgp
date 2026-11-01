# pgp_flutter

Flutter integration for [`pgp_dart`](../pgp_dart): OpenPGP backed by
[Sequoia](https://sequoia-pgp.org).

This package builds the `pgp-ffi` Rust crate it ships in `rust/` automatically
(via [cargokit](https://github.com/ManyMath/cargokit)) and bundles it with your
app, then re-exports the full `pgp_dart` API.

```dart
import 'package:pgp_flutter/pgp_flutter.dart';

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
- perl, make and a C compiler: the crate builds OpenSSL from source and links
  it statically (the `crypto-openssl-vendored` feature), so apps need no
  system OpenSSL.
- iOS 13 or later; macOS 10.15 or later.

See [`rust/README.md`](rust/README.md) for the crate's backends.
