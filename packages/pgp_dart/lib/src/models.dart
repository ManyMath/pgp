import 'dart:typed_data';

/// Deprecated compatibility shim retained from `pgp_dart` 0.0.1.
///
/// Native FFI operations now live in `package:pgp`, which bundles `pgp_ffi`
/// through a Dart build hook.
@Deprecated(
  'Native FFI operations live in package:pgp and bundle pgp_ffi via Dart build hooks in 0.0.2+.',
)
String? nativeLibraryOverridePath;

/// FFI status codes returned by `pgp-ffi`.
enum PgpErrorCode {
  ok(0),
  nullPointer(-1),
  invalid(-2),
  failed(-3),
  notFound(-4);

  const PgpErrorCode(this.code);

  final int code;

  /// Resolves [code] to a [PgpErrorCode], or `null` if unknown.
  static PgpErrorCode? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// RFC 4880 reason-for-revocation codes.
enum RevocationReason {
  unspecified(0),
  keySuperseded(1),
  keyCompromised(2),
  keyRetired(3),
  userIdRetired(32);

  const RevocationReason(this.code);

  final int code;

  /// Resolves [code] to a [RevocationReason], or `null` if unknown.
  static RevocationReason? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// Key algorithm and curve preset for key generation.
enum CipherSuite {
  cv25519(0),
  rsa3k(1),
  p256(2),
  p384(3),
  p521(4),
  rsa2k(5),
  rsa4k(6);

  const CipherSuite(this.code);

  final int code;

  /// Resolves [code] to a [CipherSuite], or `null` if unknown.
  static CipherSuite? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// RFC 4880 symmetric-cipher algorithm codes.
enum SymmetricAlgorithmPreference {
  tripleDes(2),
  cast5(3),
  blowfish(4),
  aes128(7),
  aes192(8),
  aes256(9),
  twofish(10),
  camellia128(11),
  camellia192(12),
  camellia256(13);

  const SymmetricAlgorithmPreference(this.code);

  final int code;

  /// Resolves [code] to a [SymmetricAlgorithmPreference], or `null` if unknown.
  static SymmetricAlgorithmPreference? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// RFC 4880 hash algorithm codes.
enum HashAlgorithmPreference {
  sha1(2, 'SHA-1'),
  sha256(8, 'SHA-256'),
  sha384(9, 'SHA-384'),
  sha512(10, 'SHA-512'),
  sha224(11, 'SHA-224');

  const HashAlgorithmPreference(this.code, this.standardName);

  final int code;

  /// Standard digest label (for example `SHA-256`).
  final String standardName;

  /// Resolves [code] to a [HashAlgorithmPreference], or `null` if unknown.
  static HashAlgorithmPreference? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// RFC 4880 compression algorithm codes.
enum CompressionAlgorithmPreference {
  uncompressed(0),
  zip(1),
  zlib(2),
  bzip2(3);

  const CompressionAlgorithmPreference(this.code);

  final int code;

  /// Resolves [code] to a [CompressionAlgorithmPreference], or `null` if unknown.
  static CompressionAlgorithmPreference? fromCode(int code) {
    for (final value in values) {
      if (value.code == code) return value;
    }
    return null;
  }
}

/// Algorithm preferences and features recorded on a certificate direct-key signature.
class CertificatePreferences {
  final List<int> symmetricAlgorithms;
  final List<int> hashAlgorithms;
  final List<int> compressionAlgorithms;
  final int features;

  const CertificatePreferences({
    required this.symmetricAlgorithms,
    required this.hashAlgorithms,
    required this.compressionAlgorithms,
    required this.features,
  });
}

/// Snapshot of primary certificate metadata.
class CertificateInfo {
  final String fingerprint;
  final List<String> userIds;
  final int expiryEpoch;

  const CertificateInfo({
    required this.fingerprint,
    required this.userIds,
    required this.expiryEpoch,
  });

  bool get hasExpiry => expiryEpoch != 0;

  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// Metadata for a certificate subkey.
class SubkeyInfo {
  final int index;
  final String fingerprint;
  final bool canEncrypt;
  final bool canSign;
  final bool canAuthenticate;
  final bool isRevoked;
  final int expiryEpoch;

  const SubkeyInfo({
    required this.index,
    required this.fingerprint,
    required this.canEncrypt,
    required this.canSign,
    required this.canAuthenticate,
    required this.isRevoked,
    required this.expiryEpoch,
  });

  bool get hasExpiry => expiryEpoch != 0;

  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// Metadata for a certificate user ID.
class UserIdInfo {
  final String userId;
  final bool isRevoked;
  final bool isPrimary;
  final int expiryEpoch;

  const UserIdInfo({
    required this.userId,
    required this.isRevoked,
    required this.isPrimary,
    required this.expiryEpoch,
  });

  bool get hasExpiry => expiryEpoch != 0;

  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// Metadata for a third-party certification of a user ID.
class CertifierInfo {
  final String fingerprint;
  final bool isRevoked;
  final int trustDepth;
  final int trustAmount;
  final bool isExportable;

  const CertifierInfo({
    required this.fingerprint,
    required this.isRevoked,
    this.trustDepth = 0,
    this.trustAmount = 0,
    this.isExportable = true,
  });
}

/// Designated revoker entry recorded on a certificate.
class DesignatedRevoker {
  final String fingerprint;
  final bool sensitive;

  const DesignatedRevoker({required this.fingerprint, required this.sensitive});
}

/// Whole-certificate revocation status.
class RevocationInfo {
  final bool isRevoked;
  final int reasonCode;
  final String message;

  const RevocationInfo({
    required this.isRevoked,
    required this.reasonCode,
    required this.message,
  });

  /// Typed [RevocationReason] when [isRevoked] is true and [reasonCode] is known.
  RevocationReason? get reason =>
      isRevoked ? RevocationReason.fromCode(reasonCode) : null;
}

/// Verified (and optionally decrypted) plaintext with signature metadata.
class SignedPlaintext {
  final String plaintext;
  final String signerFingerprint;
  final int signedAtEpoch;

  /// Raw RFC 4880 hash algorithm code used by the verified signature, or 0 if unset.
  final int hashAlgorithmCode;

  const SignedPlaintext({
    required this.plaintext,
    required this.signerFingerprint,
    this.signedAtEpoch = 0,
    this.hashAlgorithmCode = 0,
  });

  bool get hasSignedAt => signedAtEpoch > 0;

  DateTime? get signedAtDate => hasSignedAt
      ? DateTime.fromMillisecondsSinceEpoch(signedAtEpoch * 1000, isUtc: true)
      : null;

  /// Typed [HashAlgorithmPreference] for [hashAlgorithmCode], or `null`.
  HashAlgorithmPreference? get hashAlgorithm => hashAlgorithmCode > 0
      ? HashAlgorithmPreference.fromCode(hashAlgorithmCode)
      : null;
}

/// Signer metadata returned by file and detached verification operations.
class FileSignatureInfo {
  final String signerFingerprint;
  final int signedAtEpoch;

  /// Raw RFC 4880 hash algorithm code used by the verified signature, or 0 if unset.
  final int hashAlgorithmCode;

  const FileSignatureInfo({
    required this.signerFingerprint,
    this.signedAtEpoch = 0,
    this.hashAlgorithmCode = 0,
  });

  bool get hasSignedAt => signedAtEpoch > 0;

  DateTime? get signedAtDate => hasSignedAt
      ? DateTime.fromMillisecondsSinceEpoch(signedAtEpoch * 1000, isUtc: true)
      : null;

  /// Typed [HashAlgorithmPreference] for [hashAlgorithmCode], or `null`.
  HashAlgorithmPreference? get hashAlgorithm => hashAlgorithmCode > 0
      ? HashAlgorithmPreference.fromCode(hashAlgorithmCode)
      : null;
}

/// Recovered symmetric session key and cipher algorithm identifier.
class SessionKeyInfo {
  final String hex;
  final int algo;

  const SessionKeyInfo({required this.hex, required this.algo});

  /// Typed [SymmetricAlgorithmPreference] for [algo], or `null`.
  SymmetricAlgorithmPreference? get algorithm =>
      SymmetricAlgorithmPreference.fromCode(algo);
}

/// Verified raw bytes with signature metadata.
class VerifiedBytes {
  final Uint8List plaintext;
  final String signerFingerprint;
  final int signedAtEpoch;

  /// Raw RFC 4880 hash algorithm code used by the verified signature, or 0 if unset.
  final int hashAlgorithmCode;

  const VerifiedBytes({
    required this.plaintext,
    required this.signerFingerprint,
    this.signedAtEpoch = 0,
    this.hashAlgorithmCode = 0,
  });

  bool get hasSignedAt => signedAtEpoch > 0;

  DateTime? get signedAtDate => hasSignedAt
      ? DateTime.fromMillisecondsSinceEpoch(signedAtEpoch * 1000, isUtc: true)
      : null;

  /// Typed [HashAlgorithmPreference] for [hashAlgorithmCode], or `null`.
  HashAlgorithmPreference? get hashAlgorithm => hashAlgorithmCode > 0
      ? HashAlgorithmPreference.fromCode(hashAlgorithmCode)
      : null;
}

/// Exception thrown when a `pgp-ffi` call returns a non-zero status code.
class PgpException implements Exception {
  final int code;

  /// Diagnostic error detail from `pgp_last_error_message`, when available.
  final String? message;

  const PgpException(this.code, [this.message]);

  /// Typed [PgpErrorCode] for [code], or `null`.
  PgpErrorCode? get errorCode => PgpErrorCode.fromCode(code);

  @override
  String toString() {
    final detail = message;
    if (detail != null && detail.isNotEmpty) {
      return 'PgpException($code): $detail';
    }
    return 'PgpException: pgp-ffi returned $code';
  }
}
