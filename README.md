# pgp

OpenPGP for Dart and Flutter, backed by [Sequoia](https://sequoia-pgp.org).
Native builds require Rust in addition to Dart or Flutter.

This is a [melos](https://melos.invertase.dev) monorepo:

| Package | What it is |
|---|---|
| [`packages/pgp_dart`](packages/pgp_dart) | Pure Dart (no Flutter); works in CLI tools. Reaches Sequoia over `dart:ffi`. |
| [`packages/pgp_flutter`](packages/pgp_flutter) | Flutter plugin. Builds the native library automatically (via cargokit) and re-exports the `pgp_dart` API. |
| [`packages/pgp_flutter/rust`](packages/pgp_flutter/rust) | The `pgp-ffi` Rust crate (the C ABI behind the bindings), kept inside `pgp_flutter` so it ships with that package. Links a statically built OpenSSL by default; Windows builds wrap it with Sequoia's CNG backend (`windows/rust`). |

## Quick start (Dart CLI)

```dart
import 'package:pgp_dart/pgp_dart.dart';

final pgp = PGP();
final cert = pgp.generateKey('someone@example.org');
```

Build the native library first:
`cargo build --release --manifest-path packages/pgp_flutter/rust/Cargo.toml`.

## Status

| Host | Status |
|---|---|
| Linux | Working: CLI, tests, the example integration test and the payload gate (Ubuntu 24.04, also WSL2) |
| Linux aarch64 | Crate tests and the pgp_dart suite pass under qemu (cross-built library, arm64 Dart SDK); Flutter not run |
| Android | Working: example integration test on an x86_64 emulator (API 36); the payload gate builds arm64-v8a, armeabi-v7a and x86_64 |
| macOS | Working: CLI, tests, the example integration test and the payload gate (arm64) |
| iOS | Working: example integration test on iPhone 16 Pro and iPhone 18 Pro simulators; device build without codesigning |
| Windows | Working: Dart tests, the example integration test and the payload gate (x64, CNG backend) |
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

`flutter test integration_test -d <device>` (from
`packages/pgp_flutter/example`) runs the on-device round-trip tests.

## Package candidates and verification

The native crate lives in `packages/pgp_flutter/rust` so its complete source
ships in the Flutter publication archive. See [the payload gate](tool/README.md)
for actual pub archive checks, fresh consumer builds and native loading checks:

```sh
python3 tool/native_payload.py --config tool/payload.json --mode candidate --output /tmp/pgp-candidate
```
