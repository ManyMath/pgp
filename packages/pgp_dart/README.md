# pgp_dart

Pure-Dart OpenPGP models, RFC 4880 algorithm enums, error codes, and `PgpException` with no native `dart:ffi` or Flutter dependencies.

For cryptographic operations backed by `sequoia-openpgp`, depend on [`pgp`](../pgp/README.md), which re-exports `package:pgp_dart/pgp_dart.dart`.

## Usage

```dart
import 'package:pgp_dart/pgp_dart.dart';

void main() {
  const info = CertificateInfo(
    fingerprint: '0123456789ABCDEF0123456789ABCDEF01234567',
    userIds: ['alice@example.org'],
    expiryEpoch: 0,
  );
  print('${info.fingerprint} expires=${info.expiryDate}');
}
```
