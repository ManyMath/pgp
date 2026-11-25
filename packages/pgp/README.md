# pgp

Pure-Dart OpenPGP library backed by `sequoia-openpgp` (`pgp-ffi`) over `@Native` FFI bindings and Dart build hooks, with no Flutter SDK dependency. Re-exports `package:pgp_dart/pgp_dart.dart`.

## Features

- Key generation (`cv25519`, `rsa2k`, `rsa3k`, `rsa4k`, `p256`, `p384`, `p521`), subkey management, expiration, passphrase locking/unlocking, revocation certificates, and designated revokers.
- ASCII-armored, raw-byte, cleartext, and streaming file encryption, decryption, signing, and detached signature verification (`signDetachedBytes`, `verifyDetachedBytes`, `signDetachedFile`, `verifyDetachedFile`).
- Optional reference timestamps (`{DateTime? at}`), RFC 4880 hash algorithm metadata (`hashAlgorithmCode` / `hashAlgorithm`), and Sequoia error messages on `PgpException`.
- Symmetric passphrase-only encryption/signing and recipient key ID inspection.

## Build Options

`hook/build.dart` supports user defines in your app `pubspec.yaml` under `hooks.user_defines.pgp`:

- `local_lib`: Path to a prebuilt `libpgp_ffi` shared library.
- `build_from_source`: Set `true` to skip prebuilt downloads and invoke `RustBuilder`.
- `require_prebuilt`: Set `true` to fail instead of falling back to `RustBuilder` when prebuilt download/verification fails.
- `prebuilt_base_url` / `prebuilt_sha256`: Override prebuilt archive mirror URL and expected SHA-256 digest.

## Usage

```dart
import 'dart:typed_data';

import 'package:pgp/pgp.dart';

void main() {
  ensureNativeLibrary();
  final pgp = PGP();
  final key = pgp.generateKey('alice@example.org');
  final pub = pgp.certificateFromArmored(key.exportPublicArmored());

  final payload = Uint8List.fromList([0x00, 0x01, 0x02, 0xff]);
  final sig = key.signDetachedBytes(payload);
  final info = pub.verifyDetachedBytes(payload, sig);
  print('Verified signer ${info.signerFingerprint} (${info.hashAlgorithm?.standardName})');

  pub.dispose();
  key.dispose();
}
```
