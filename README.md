# pgp

OpenPGP for Dart and Flutter, backed by [Sequoia](https://sequoia-pgp.org).
Native builds require Rust in addition to Dart or Flutter.

This is a [melos](https://melos.invertase.dev) monorepo:

| Package | What it is |
|---|---|
| [`packages/pgp_dart`](packages/pgp_dart) | Pure Dart (no Flutter); works in CLI tools. Reaches Sequoia over `dart:ffi`. |
| [`packages/pgp_flutter`](packages/pgp_flutter) | Flutter plugin. Builds the native library automatically (via cargokit) and re-exports the `pgp_dart` API. |
| [`packages/pgp_flutter/rust`](packages/pgp_flutter/rust) | The `pgp-ffi` Rust crate (the C ABI behind the bindings), kept inside `pgp_flutter` so it ships with that package. Links a statically built OpenSSL by default. |

## Quick start (Dart CLI)

```dart
import 'package:pgp_dart/pgp_dart.dart';

final pgp = PGP();
final cert = pgp.generateKey('someone@example.org');
```

Build the native library first:
`cargo build --release --manifest-path packages/pgp_flutter/rust/Cargo.toml`.

## Status

Development code; neither package is published to pub.dev yet.

| Host | Status |
|---|---|
| Linux | Working: CLI, tests and the Flutter example's integration test |
| Android | Working: example integration test on an x86_64 emulator (API 36); builds arm64-v8a, armeabi-v7a, x86_64 |
| macOS | Working: CLI, tests and the example integration test (arm64) |
| iOS | Builds (device, no codesign); not yet run |
| Windows | Not yet verified |
| Web | Not supported (no `dart:ffi`) |

## Development

Driven by [melos](https://melos.invertase.dev) (config lives in the root
`pubspec.yaml`). After `flutter pub get`:

```sh
dart run melos run native:build   # build the Rust shared library
dart run melos run analyze        # analyze pgp_dart + pgp_flutter
dart run melos run format         # check Dart formatting (format:fix to apply)
dart run melos run test           # Dart + Flutter tests
dart run melos run native:test    # Rust crate tests
```

`tool/consumer_build.sh linux apk` builds a fresh Flutter app against the two
packages exported from `HEAD`, the way a pub.dev consumer gets them.
`flutter test integration_test -d <device>` (from
`packages/pgp_flutter/example`) runs the on-device round-trip tests.
