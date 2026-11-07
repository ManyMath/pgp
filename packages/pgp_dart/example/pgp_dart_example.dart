import 'package:pgp_dart/pgp_dart.dart';

void main() {
  const info = CertificateInfo(
    fingerprint: '0123456789ABCDEF0123456789ABCDEF01234567',
    userIds: ['alice@example.org'],
    expiryEpoch: 0,
  );
  print('Certificate ${info.fingerprint} expires: ${info.expiryDate}');
}
