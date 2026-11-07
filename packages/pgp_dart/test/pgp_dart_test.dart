import 'dart:typed_data';

import 'package:pgp_dart/pgp_dart.dart';
import 'package:test/test.dart';

void main() {
  test('enum lookup methods handle known and unknown codes', () {
    expect(PgpErrorCode.fromCode(-2), PgpErrorCode.invalid);
    expect(PgpErrorCode.fromCode(-99), isNull);

    expect(RevocationReason.fromCode(2), RevocationReason.keyCompromised);
    expect(RevocationReason.fromCode(99), isNull);

    expect(CipherSuite.fromCode(0), CipherSuite.cv25519);
    expect(CipherSuite.fromCode(99), isNull);

    expect(
      SymmetricAlgorithmPreference.fromCode(9),
      SymmetricAlgorithmPreference.aes256,
    );
    expect(SymmetricAlgorithmPreference.fromCode(1), isNull);

    expect(HashAlgorithmPreference.fromCode(8), HashAlgorithmPreference.sha256);
    expect(HashAlgorithmPreference.sha256.standardName, 'SHA-256');
    expect(HashAlgorithmPreference.fromCode(99), isNull);

    expect(
      CompressionAlgorithmPreference.fromCode(2),
      CompressionAlgorithmPreference.zlib,
    );
    expect(CompressionAlgorithmPreference.fromCode(99), isNull);
  });

  test('model getters expose dates and typed metadata', () {
    const epoch = 1700000000;
    const certInfo = CertificateInfo(
      fingerprint: 'ABCD',
      userIds: ['a@example.org'],
      expiryEpoch: epoch,
    );
    expect(certInfo.hasExpiry, isTrue);
    expect(
      certInfo.expiryDate,
      DateTime.fromMillisecondsSinceEpoch(epoch * 1000, isUtc: true),
    );

    const signed = SignedPlaintext(
      plaintext: 'ok',
      signerFingerprint: 'ABCD',
      signedAtEpoch: epoch,
      hashAlgorithmCode: 8,
    );
    expect(signed.hasSignedAt, isTrue);
    expect(signed.hashAlgorithm, HashAlgorithmPreference.sha256);

    final verifiedBytes = VerifiedBytes(
      plaintext: Uint8List.fromList([1, 2, 3]),
      signerFingerprint: 'ABCD',
      signedAtEpoch: epoch,
      hashAlgorithmCode: 10,
    );
    expect(verifiedBytes.hashAlgorithm, HashAlgorithmPreference.sha512);

    const fileSig = FileSignatureInfo(
      signerFingerprint: 'ABCD',
      signedAtEpoch: epoch,
      hashAlgorithmCode: 8,
    );
    expect(fileSig.hashAlgorithm, HashAlgorithmPreference.sha256);

    const session = SessionKeyInfo(hex: 'AA', algo: 9);
    expect(session.algorithm, SymmetricAlgorithmPreference.aes256);

    const revoked = RevocationInfo(
      isRevoked: true,
      reasonCode: 2,
      message: 'compromised',
    );
    expect(revoked.reason, RevocationReason.keyCompromised);
  });

  test('PgpException formats message when provided', () {
    const plain = PgpException(-3);
    expect(plain.errorCode, PgpErrorCode.failed);
    expect(plain.toString(), 'PgpException: pgp-ffi returned -3');

    const detailed = PgpException(-2, 'invalid armor');
    expect(detailed.errorCode, PgpErrorCode.invalid);
    expect(detailed.toString(), 'PgpException(-2): invalid armor');
  });
}
