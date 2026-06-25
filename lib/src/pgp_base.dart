import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'native_library.dart';
import 'pgp-ffi_bindings_generated.dart' as ffi;

/// The bindings to the native functions in [nativeLibrary].
final ffi.PgpFfiBindings _bindings = ffi.PgpFfiBindings(nativeLibrary);

/// RFC 4880 reason-for-revocation codes accepted by [Certificate.revoke],
/// [Certificate.revokeSubkey], and [Certificate.revokeUserId].
enum RevocationReason {
  /// No reason given.
  unspecified(0),

  /// The key has been superseded by a new one.
  keySuperseded(1),

  /// The key material has been compromised.
  keyCompromised(2),

  /// The key is retired and no longer used.
  keyRetired(3),

  /// The user ID is no longer valid (user IDs only).
  userIdRetired(32);

  const RevocationReason(this.code);

  /// The wire-format RFC 4880 reason code.
  final int code;
}

/// Key algorithm/curve to use when generating a new certificate, passed to
/// [PGP.generateKeyWithCipherSuite].
enum CipherSuite {
  /// EdDSA and ECDH over Curve25519 with SHA512 and AES256 (the default
  /// used by [PGP.generateKey]).
  cv25519(0),

  /// 3072-bit RSA with SHA512 and AES256.
  rsa3k(1),

  /// EdDSA and ECDH over NIST P-256 with SHA256 and AES256.
  p256(2),

  /// EdDSA and ECDH over NIST P-384 with SHA384 and AES256.
  p384(3),

  /// EdDSA and ECDH over NIST P-521 with SHA512 and AES256.
  p521(4),

  /// 2048-bit RSA with SHA512 and AES256.
  rsa2k(5),

  /// 4096-bit RSA with SHA512 and AES256.
  rsa4k(6);

  const CipherSuite(this.code);

  /// The code `pgp_key_generate_with_cipher_suite` expects.
  final int code;
}

/// A snapshot of certificate metadata returned by [Certificate.info].
class CertificateInfo {
  /// 40-character uppercase hex fingerprint (v4 key).
  final String fingerprint;

  /// All user IDs on the certificate, including revoked ones.
  final List<String> userIds;

  /// Primary key expiration as seconds since the Unix epoch; 0 means no expiry.
  final int expiryEpoch;

  const CertificateInfo({
    required this.fingerprint,
    required this.userIds,
    required this.expiryEpoch,
  });

  /// Whether this certificate has an expiry date set.
  bool get hasExpiry => expiryEpoch != 0;

  /// The expiry as a UTC [DateTime], or null if no expiry is set.
  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// A subkey listed by [Certificate.subkeys].
class SubkeyInfo {
  /// Zero-based index, matching the `subkeyIndex` accepted by
  /// [Certificate.revokeSubkey].
  final int index;

  /// 40-character uppercase hex fingerprint of this subkey.
  final String fingerprint;

  /// Whether this subkey is usable for transport encryption.
  final bool canEncrypt;

  /// Whether this subkey is usable for signing.
  final bool canSign;

  /// Whether this subkey is usable for authentication.
  final bool canAuthenticate;

  /// Whether this subkey has been revoked.
  final bool isRevoked;

  /// This subkey's own expiration as seconds since the Unix epoch; 0 means no
  /// expiry. Independent of the primary key's expiry and of other subkeys'
  /// expiry: see [Certificate.setSubkeyExpiry].
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

  /// Whether this subkey has an expiry date set.
  bool get hasExpiry => expiryEpoch != 0;

  /// This subkey's expiry as a UTC [DateTime], or null if it has no expiry.
  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// A user ID listed by [Certificate.userIdsInfo].
class UserIdInfo {
  /// The user ID's raw text (e.g. `"Alice <alice@example.org>"`).
  final String userId;

  /// Whether this user ID has been revoked.
  final bool isRevoked;

  /// Whether this is the certificate's primary user ID.
  final bool isPrimary;

  /// Expiration of this user ID's binding signature: i.e. how long the
  /// certification itself is valid for: as seconds since the Unix epoch;
  /// 0 means it doesn't expire.
  final int expiryEpoch;

  const UserIdInfo({
    required this.userId,
    required this.isRevoked,
    required this.isPrimary,
    required this.expiryEpoch,
  });

  /// Whether this user ID's binding signature has an expiry set.
  bool get hasExpiry => expiryEpoch != 0;

  /// This user ID's binding-signature expiry as a UTC [DateTime], or null if
  /// it has no expiry.
  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

/// A third-party certifier of a user ID, listed by
/// [Certificate.userIdCertifications].
class CertifierInfo {
  /// 40-character uppercase hex fingerprint of the certifying key (the
  /// certificate that called [Certificate.certifyUserId]).
  final String fingerprint;

  /// Whether this certifier has since revoked their certification via
  /// [Certificate.revokeUserIdCertification].
  final bool isRevoked;

  const CertifierInfo({
    required this.fingerprint,
    required this.isRevoked,
  });
}

/// Whole-certificate revocation status returned by
/// [Certificate.revocationInfo].
class RevocationInfo {
  /// Whether the certificate has been revoked (via [Certificate.revoke]).
  final bool isRevoked;

  /// The RFC 4880 reason-for-revocation code recorded on the revocation
  /// signature, or 0 if not revoked or no reason was given.
  final int reasonCode;

  /// The human-readable revocation message, or an empty string if not
  /// revoked or none was given.
  final String message;

  const RevocationInfo({
    required this.isRevoked,
    required this.reasonCode,
    required this.message,
  });
}

/// Plaintext and signer fingerprint returned by [Certificate.decryptAndVerify],
/// [Certificate.verifyWithSigner], and [Certificate.verifyCleartextWithSigner].
class SignedPlaintext {
  /// The verified (and, for [Certificate.decryptAndVerify], decrypted) plaintext.
  final String plaintext;

  /// 40-character uppercase hex fingerprint of the signing subkey.
  final String signerFingerprint;

  /// The signature's own creation time, as seconds since the Unix epoch, or
  /// 0 if absent.
  final int signedAtEpoch;

  const SignedPlaintext({
    required this.plaintext,
    required this.signerFingerprint,
    this.signedAtEpoch = 0,
  });

  /// Whether [signedAtEpoch] carries a value.
  bool get hasSignedAt => signedAtEpoch > 0;

  /// [signedAtEpoch] as a [DateTime], or null if absent.
  DateTime? get signedAtDate => hasSignedAt
      ? DateTime.fromMillisecondsSinceEpoch(signedAtEpoch * 1000, isUtc: true)
      : null;
}

/// Raw verified bytes and signer fingerprint returned by
/// [Certificate.verifyBytesWithSigner].
class VerifiedBytes {
  /// The verified plaintext bytes.
  final Uint8List plaintext;

  /// 40-character uppercase hex fingerprint of the signing subkey.
  final String signerFingerprint;

  /// The signature's own creation time, as seconds since the Unix epoch, or
  /// 0 if absent.
  final int signedAtEpoch;

  const VerifiedBytes({
    required this.plaintext,
    required this.signerFingerprint,
    this.signedAtEpoch = 0,
  });

  /// Whether [signedAtEpoch] carries a value.
  bool get hasSignedAt => signedAtEpoch > 0;

  /// [signedAtEpoch] as a [DateTime], or null if absent.
  DateTime? get signedAtDate => hasSignedAt
      ? DateTime.fromMillisecondsSinceEpoch(signedAtEpoch * 1000, isUtc: true)
      : null;
}

/// Status code returned by a `pgp-ffi` call.
class PgpException implements Exception {
  /// The non-zero `FFIError` code returned by `pgp-ffi`.
  final int code;

  PgpException(this.code);

  @override
  String toString() => 'PgpException: pgp-ffi returned $code';
}

/// A handle to an OpenPGP certificate owned by `pgp-ffi`.
///
/// The mutating methods return a new [Certificate]; the receiver is left
/// untouched and must be released separately.  Call [dispose] to free a
/// certificate once it is no longer needed.
class Certificate {
  final Pointer<ffi.Certificate> _ptr;

  Certificate._(this._ptr);

  /// The opaque native pointer, for passing to further FFI calls.
  Pointer<ffi.Certificate> get pointer => _ptr;

  /// Exports the certificate as an ASCII-armored public key block.
  String exportPublicArmored() => _exportArmored(
        _bindings.pgp_certificate_export_public_armored,
      );

  /// Exports the certificate as an ASCII-armored secret key block.
  String exportSecretArmored() => _exportArmored(
        _bindings.pgp_certificate_export_secret_armored,
      );

  /// Exports the certificate as an ASCII-armored secret key block.
  ///
  /// Prefer [exportPublicArmored] when sharing a certificate with others.
  String exportArmored() => exportSecretArmored();

  /// Encrypts [plaintext] to this certificate as an ASCII-armored message.
  String encrypt(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_encrypt_string,
      );

  /// Decrypts an ASCII-armored [message] with this secret certificate.
  String decrypt(String message) => _transformString(
        message,
        _bindings.pgp_certificate_decrypt_string,
      );

  /// Signs [plaintext] with this secret certificate as an armored message.
  String sign(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_sign_string,
      );

  /// Verifies an armored signed [message] with this certificate.
  ///
  /// Returns the message plaintext if the signature is valid.
  String verify(String message) => verifyWithSigner(message).plaintext;

  /// Verifies an armored signed [message] with this certificate.
  ///
  /// Returns the plaintext together with the fingerprint of the subkey that
  /// produced the signature. Throws [PgpException] if verification fails.
  SignedPlaintext verifyWithSigner(String message) {
    final msgPtr = message.toNativeUtf8();
    final plaintextOut = calloc<Pointer<Char>>();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = _bindings.pgp_certificate_verify_string(
        _ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      if (code != 0) throw PgpException(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(plaintextOut.value);
      calloc.free(fpOut.value);
      return SignedPlaintext(
        plaintext: pt,
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(msgPtr);
      calloc.free(plaintextOut);
      calloc.free(fpOut);
      calloc.free(epochOut);
    }
  }

  String _exportArmored(
    int Function(Pointer<ffi.Certificate>, Pointer<Pointer<Char>>) call,
  ) {
    final out = calloc<Pointer<Char>>();
    try {
      final code = call(_ptr, out);
      if (code != 0) throw PgpException(code);
      final armored = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value); // Allocated by pgp-ffi with malloc.
      return armored;
    } finally {
      calloc.free(out);
    }
  }

  String _transformString(
    String input,
    int Function(
      Pointer<ffi.Certificate>,
      Pointer<Char>,
      Pointer<Pointer<Char>>,
    ) call,
  ) {
    final inputPointer = input.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = call(_ptr, inputPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value); // Allocated by pgp-ffi with malloc.
      return result;
    } finally {
      calloc.free(inputPointer);
      calloc.free(out);
    }
  }

  /// Revokes the certificate, returning the revoked certificate.
  ///
  /// [reason] and [message] are recorded in the revocation signature so
  /// other implementations can display why the key was revoked.
  Certificate revoke({
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final messagePointer = message?.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_revoke(
          _ptr, reason.code, messagePointer?.cast() ?? nullptr, out));
    } finally {
      if (messagePointer != null) calloc.free(messagePointer);
    }
  }

  /// Reports whether this certificate itself has been revoked (via
  /// [revoke]), and if so, the reason code and message recorded on the
  /// revocation signature. [subkeys] and [userIdsInfo] already report
  /// per-subkey/per-user-ID revocation; this is the whole-certificate
  /// counterpart.
  RevocationInfo revocationInfo() {
    final revokedOut = calloc<Uint8>();
    final reasonOut = calloc<Uint8>();
    final messageOut = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_revocation_info(
        _ptr,
        revokedOut,
        reasonOut,
        messageOut,
      );
      if (code != 0) throw PgpException(code);
      final message = messageOut.value.cast<Utf8>().toDartString();
      calloc.free(messageOut.value);
      return RevocationInfo(
        isRevoked: revokedOut.value == 1,
        reasonCode: reasonOut.value,
        message: message,
      );
    } finally {
      calloc.free(revokedOut);
      calloc.free(reasonOut);
      calloc.free(messageOut);
    }
  }

  /// Generates a standalone, ASCII-armored revocation certificate for this
  /// certificate *without* applying it: the `gpg --gen-revoke` workflow.
  /// Store the result somewhere safe (e.g. offline) right after generating
  /// a key, so it can still be revoked later via [applyRevocationArmored]
  /// even if the secret key or its passphrase is subsequently lost.
  ///
  /// [reason] and [message] use the same conventions as [revoke].
  String generateRevocationArmored({
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final messagePointer = message?.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_generate_revocation_armored(
        _ptr,
        reason.code,
        messagePointer?.cast() ?? nullptr,
        out,
      );
      if (code != 0) throw PgpException(code);
      final armored = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return armored;
    } finally {
      if (messagePointer != null) calloc.free(messagePointer);
      calloc.free(out);
    }
  }

  /// Applies a standalone revocation certificate (produced by
  /// [generateRevocationArmored], or any other RFC 4880
  /// certificate-revocation signature in ASCII armor) to this certificate,
  /// returning the now-revoked certificate. This certificate itself is left
  /// unmodified. Unlike [revoke], this needs no secret key material at all.
  Certificate applyRevocationArmored(String revocationArmored) {
    final armoredPointer = revocationArmored.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_apply_revocation_armored(
          _ptr, armoredPointer.cast(), out));
    } finally {
      calloc.free(armoredPointer);
    }
  }

  /// Adds a transport-encryption subkey, returning the updated certificate.
  Certificate addTransportEncryptionSubkey() => _derive((out) =>
      _bindings.pgp_certificate_add_transport_encryption_subkey(_ptr, out));

  /// Adds a signing subkey, returning the updated certificate.
  Certificate addSigningSubkey() =>
      _derive((out) => _bindings.pgp_certificate_add_signing_subkey(_ptr, out));

  /// Adds an authentication subkey, returning the updated certificate.
  Certificate addAuthenticationSubkey() => _derive(
      (out) => _bindings.pgp_certificate_add_authentication_subkey(_ptr, out));

  /// Revokes the subkey at [index] (counting subkeys only), returning the
  /// updated certificate.
  ///
  /// [reason] and [message] are recorded in the revocation signature so
  /// other implementations can display why the subkey was revoked.
  Certificate revokeSubkey(
    int index, {
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final messagePointer = message?.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_revoke_subkey(
          _ptr, index, reason.code, messagePointer?.cast() ?? nullptr, out));
    } finally {
      if (messagePointer != null) calloc.free(messagePointer);
    }
  }

  /// Adds [userId] to the certificate, returning the updated certificate.
  Certificate addUserId(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_add_userid(
          _ptr, userIdPointer.cast(), out));
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Revokes the exact-match [userId], returning the updated certificate.
  ///
  /// [reason] and [message] are recorded in the revocation signature so
  /// other implementations can display why the user ID was revoked.
  Certificate revokeUserId(
    String userId, {
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final userIdPointer = userId.toNativeUtf8();
    final messagePointer = message?.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_revoke_userid(
          _ptr,
          userIdPointer.cast(),
          reason.code,
          messagePointer?.cast() ?? nullptr,
          out));
    } finally {
      calloc.free(userIdPointer);
      if (messagePointer != null) calloc.free(messagePointer);
    }
  }

  /// Certifies [userId] on [target] using this certificate's key, returning
  /// an updated copy of [target] carrying this certificate's certification
  /// signature on that user ID: the basis of "vouching for" or "signing"
  /// someone else's key. [target] itself is left unmodified.
  ///
  /// Throws [PgpException] if [userId] isn't present on [target] or if this
  /// certificate's certification-capable secret key isn't available.
  Certificate certifyUserId(Certificate target, String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_certify_userid(
          _ptr, target._ptr, userIdPointer.cast(), out));
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Revokes this certificate's own earlier third-party certification of
  /// [userId] on [target]: the counterpart to [certifyUserId]: returning
  /// an updated copy of [target] carrying this certificate's
  /// certification-revocation signature on that user ID. [target] itself is
  /// left unmodified.
  ///
  /// [reason] and [message] are recorded in the revocation signature so
  /// other implementations can display why the certification was revoked.
  ///
  /// Throws [PgpException] if [userId] isn't present on [target] or if this
  /// certificate's certification-capable secret key isn't available.
  Certificate revokeUserIdCertification(
    Certificate target,
    String userId, {
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final userIdPointer = userId.toNativeUtf8();
    final messagePointer = message?.toNativeUtf8();
    try {
      return _derive((out) =>
          _bindings.pgp_certificate_revoke_userid_certification(
              _ptr,
              target._ptr,
              userIdPointer.cast(),
              reason.code,
              messagePointer?.cast() ?? nullptr,
              out));
    } finally {
      calloc.free(userIdPointer);
      if (messagePointer != null) calloc.free(messagePointer);
    }
  }

  /// Marks [userId] as this certificate's primary user ID, returning an
  /// updated copy. The primary user ID is the one implementations should
  /// show by default (e.g. in a key listing) when a certificate has more
  /// than one; [userIdsInfo]'s `isPrimary` flag reflects the result.
  ///
  /// Throws [PgpException] if [userId] isn't present on this certificate or
  /// if this certificate's certification-capable secret key isn't available.
  Certificate setPrimaryUserId(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_set_primary_userid(
          _ptr, userIdPointer.cast(), out));
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Merges updates from [other] into this certificate: new signatures,
  /// certifications, subkeys, and revocations: returning the combined
  /// certificate. This is the counterpart to importing a refreshed copy of a
  /// certificate (e.g. fetched from a keyserver or received from a peer)
  /// without discarding what's already known locally.
  ///
  /// [other] must have the same primary-key fingerprint as this certificate;
  /// secret key material on [other] is always discarded, so only this
  /// certificate's own secret key (if any) survives into the result. Neither
  /// this certificate nor [other] is modified.
  ///
  /// Throws [PgpException] if [other] is not the same certificate as this one.
  Certificate merge(Certificate other) {
    return _derive(
        (out) => _bindings.pgp_certificate_merge(_ptr, other._ptr, out));
  }

  /// Returns the primary key fingerprint as a 40-character uppercase hex string.
  String fingerprint() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_fingerprint(_ptr, out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(out);
    }
  }

  /// Returns all user IDs on this certificate, including revoked ones.
  List<String> userIds() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_userids(_ptr, out);
      if (code != 0) throw PgpException(code);
      final raw = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return raw.isEmpty ? [] : raw.split('\n');
    } finally {
      calloc.free(out);
    }
  }

  /// Returns metadata (revocation status, primary flag, binding-signature
  /// expiry) for every user ID on this certificate, including revoked ones:
  /// same coverage as [userIds], with detail added.
  List<UserIdInfo> userIdsInfo() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_userids_info(_ptr, out);
      if (code != 0) throw PgpException(code);
      final raw = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      if (raw.isEmpty) return [];
      return raw.split('\n').map((line) {
        final fields = line.split('\t');
        return UserIdInfo(
          userId: fields[0],
          isRevoked: fields[1] == '1',
          isPrimary: fields[2] == '1',
          expiryEpoch: int.parse(fields[3]),
        );
      }).toList();
    } finally {
      calloc.free(out);
    }
  }

  /// Returns one [CertifierInfo] per distinct certificate that has called
  /// [certifyUserId] on [userId]: the third-party-certification counterpart
  /// to [userIdsInfo], which only reports self-signature state. Reports what
  /// is attached to the certificate as-is, without re-verifying each
  /// signature against the issuer's own key.
  ///
  /// Throws [PgpException] if [userId] isn't present on this certificate.
  List<CertifierInfo> userIdCertifications(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_userid_certifications(
          _ptr, userIdPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      final raw = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      if (raw.isEmpty) return [];
      return raw.split('\n').map((line) {
        final fields = line.split('\t');
        return CertifierInfo(
          fingerprint: fields[0],
          isRevoked: fields[1] == '1',
        );
      }).toList();
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Cryptographically verifies [issuer]'s third-party certification of
  /// [userId] on this certificate: [userIdCertifications] only reports
  /// issuer fingerprints without checking the signature itself; this
  /// confirms the signature was actually produced by [issuer]'s key.
  ///
  /// Throws [PgpException] if [userId] isn't present on this certificate, or
  /// if no certification issued by [issuer]'s fingerprint is attached.
  bool verifyUserIdCertification(Certificate issuer, String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Uint8>();
    try {
      final code = _bindings.pgp_certificate_verify_userid_certification(
          _ptr, issuer._ptr, userIdPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      return out.value == 1;
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Returns metadata for every subkey on this certificate, in the same
  /// order (and with the same zero-based indexing) expected by
  /// [revokeSubkey].
  List<SubkeyInfo> subkeys() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_subkeys(_ptr, out);
      if (code != 0) throw PgpException(code);
      final raw = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      if (raw.isEmpty) return [];
      return raw.split('\n').map((line) {
        final fields = line.split('\t');
        final flags = fields[2].split(',');
        return SubkeyInfo(
          index: int.parse(fields[0]),
          fingerprint: fields[1],
          canEncrypt: flags.contains('encryption'),
          canSign: flags.contains('signing'),
          canAuthenticate: flags.contains('authentication'),
          isRevoked: fields[3] == '1',
          expiryEpoch: int.parse(fields[4]),
        );
      }).toList();
    } finally {
      calloc.free(out);
    }
  }

  /// Returns the primary key expiration as seconds since the Unix epoch,
  /// or 0 if the certificate has no expiry.
  int expiryEpoch() {
    final out = calloc<Int64>();
    try {
      final code = _bindings.pgp_certificate_expiry_epoch(_ptr, out);
      if (code != 0) throw PgpException(code);
      return out.value;
    } finally {
      calloc.free(out);
    }
  }

  /// Returns a [CertificateInfo] snapshot combining fingerprint, user IDs,
  /// and expiry epoch in a single call.
  CertificateInfo info() => CertificateInfo(
        fingerprint: fingerprint(),
        userIds: userIds(),
        expiryEpoch: expiryEpoch(),
      );

  /// Signs [plaintext] with this secret certificate, returning an ASCII-armored
  /// detached signature (BEGIN PGP SIGNATURE). The plaintext is not modified.
  String signDetached(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_sign_detached,
      );

  /// Verifies [armoredSig] against [plaintext] using this certificate.
  ///
  /// Returns true if the signature is valid. Throws [PgpException] if
  /// verification fails or the signature is malformed.
  bool verifyDetached(String plaintext, String armoredSig) {
    final p1 = plaintext.toNativeUtf8();
    final p2 = armoredSig.toNativeUtf8();
    try {
      final code = _bindings.pgp_certificate_verify_detached(
          _ptr, p1.cast(), p2.cast(), nullptr, nullptr);
      if (code != 0) throw PgpException(code);
      return true;
    } finally {
      calloc.free(p1);
      calloc.free(p2);
    }
  }

  /// Verifies [armoredSig] against [plaintext] using this certificate.
  ///
  /// Returns the fingerprint of the subkey that produced the signature.
  /// Throws [PgpException] if verification fails or the signature is
  /// malformed.
  String verifyDetachedSigner(String plaintext, String armoredSig) {
    final p1 = plaintext.toNativeUtf8();
    final p2 = armoredSig.toNativeUtf8();
    final fpOut = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_verify_detached(
          _ptr, p1.cast(), p2.cast(), fpOut, nullptr);
      if (code != 0) throw PgpException(code);
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(fpOut.value);
      return fp;
    } finally {
      calloc.free(p1);
      calloc.free(p2);
      calloc.free(fpOut);
    }
  }

  /// Unlocks all passphrase-protected secret key material, returning a new
  /// [Certificate] whose secrets are decrypted in memory.
  ///
  /// Throws [PgpException] with code -2 if [passphrase] is wrong, or -4 if
  /// this certificate carries no secret material.
  Certificate unlock(String passphrase) {
    final passphrasePtr = passphrase.toNativeUtf8();
    try {
      return _derive(
        (out) =>
            _bindings.pgp_certificate_unlock(_ptr, passphrasePtr.cast(), out),
      );
    } finally {
      calloc.free(passphrasePtr);
    }
  }

  /// Encrypts all currently-unencrypted secret key material with
  /// [passphrase], returning a new [Certificate] with locked secrets: the
  /// counterpart to [unlock]. Keys that are already passphrase-protected are
  /// left as-is, so calling [lock] again with a different passphrase does
  /// *not* rotate the passphrase on already-locked keys; call [unlock] first
  /// to rotate an existing passphrase.
  ///
  /// Throws [PgpException] with code -4 if this certificate carries no
  /// secret material.
  Certificate lock(String passphrase) {
    final passphrasePtr = passphrase.toNativeUtf8();
    try {
      return _derive(
        (out) =>
            _bindings.pgp_certificate_lock(_ptr, passphrasePtr.cast(), out),
      );
    } finally {
      calloc.free(passphrasePtr);
    }
  }

  /// Updates the expiry on every key in this certificate, returning a new
  /// [Certificate]. Pass null to clear the expiry (keys become permanent).
  /// The receiver is unchanged and must be disposed separately.
  Certificate setExpiry(Duration? validity) {
    final secs = (validity == null || validity == Duration.zero)
        ? 0
        : validity.inSeconds;
    return _derive(
        (out) => _bindings.pgp_certificate_set_expiry(_ptr, secs, out));
  }

  /// Updates the expiry on the subkey at [index] (counting subkeys only,
  /// same indexing as [subkeys] and [revokeSubkey]), returning a new
  /// [Certificate]. The primary key's expiry and every other subkey's expiry
  /// are left untouched. Pass null to clear that subkey's expiry.
  /// The receiver is unchanged and must be disposed separately.
  Certificate setSubkeyExpiry(int index, Duration? validity) {
    final secs = (validity == null || validity == Duration.zero)
        ? 0
        : validity.inSeconds;
    return _derive((out) =>
        _bindings.pgp_certificate_set_subkey_expiry(_ptr, index, secs, out));
  }

  /// Encrypts [data] bytes to this certificate, returning an ASCII-armored
  /// message. Useful for non-UTF-8 payloads such as binary files.
  String encryptBytes(Uint8List data) {
    final dataPtr = calloc<Uint8>(data.length.clamp(1, data.length + 1));
    for (var i = 0; i < data.length; i++) {
      dataPtr[i] = data[i];
    }
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_encrypt_bytes(
          _ptr, dataPtr.cast(), data.length, out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(dataPtr);
      calloc.free(out);
    }
  }

  /// Decrypts an ASCII-armored [message] with this secret certificate,
  /// returning the raw plaintext bytes.
  Uint8List decryptBytes(String message) {
    final msgPtr = message.toNativeUtf8();
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<UintPtr>();
    try {
      final code = _bindings.pgp_certificate_decrypt_bytes(
          _ptr, msgPtr.cast(), outPtr, outLen);
      if (code != 0) throw PgpException(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      calloc.free(outPtr.value);
      return result;
    } finally {
      calloc.free(msgPtr);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Signs [data] bytes with this secret certificate, returning an
  /// ASCII-armored signed message.
  String signBytes(Uint8List data) {
    final dataPtr = calloc<Uint8>(data.length.clamp(1, data.length + 1));
    for (var i = 0; i < data.length; i++) {
      dataPtr[i] = data[i];
    }
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_sign_bytes(
          _ptr, dataPtr.cast(), data.length, out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(dataPtr);
      calloc.free(out);
    }
  }

  /// Verifies an armored signed [message] with this certificate, returning
  /// the raw verified bytes.
  Uint8List verifyBytes(String message) {
    final msgPtr = message.toNativeUtf8();
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<UintPtr>();
    try {
      final code = _bindings.pgp_certificate_verify_bytes(
          _ptr, msgPtr.cast(), outPtr, outLen, nullptr, nullptr);
      if (code != 0) throw PgpException(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      calloc.free(outPtr.value);
      return result;
    } finally {
      calloc.free(msgPtr);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Verifies an armored signed [message] with this certificate, returning
  /// the raw verified bytes together with the signing subkey's fingerprint.
  VerifiedBytes verifyBytesWithSigner(String message) {
    final msgPtr = message.toNativeUtf8();
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<UintPtr>();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = _bindings.pgp_certificate_verify_bytes(
          _ptr, msgPtr.cast(), outPtr, outLen, fpOut, epochOut);
      if (code != 0) throw PgpException(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      calloc.free(outPtr.value);
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(fpOut.value);
      return VerifiedBytes(
        plaintext: result,
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(msgPtr);
      calloc.free(outPtr);
      calloc.free(outLen);
      calloc.free(fpOut);
      calloc.free(epochOut);
    }
  }

  /// Signs [plaintext] using the Cleartext Signature Framework (RFC 4880 section 7),
  /// returning a "-----BEGIN PGP SIGNED MESSAGE-----" block. The plaintext is
  /// human-readable inside the block.
  String signCleartext(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_sign_cleartext,
      );

  /// Verifies a cleartext-signed [message] (BEGIN PGP SIGNED MESSAGE) using
  /// this certificate. Returns the plaintext if the signature is valid.
  String verifyCleartext(String message) =>
      verifyCleartextWithSigner(message).plaintext;

  /// Verifies a cleartext-signed [message] (BEGIN PGP SIGNED MESSAGE) using
  /// this certificate.
  ///
  /// Returns the plaintext together with the fingerprint of the subkey that
  /// produced the signature. Throws [PgpException] if verification fails.
  SignedPlaintext verifyCleartextWithSigner(String message) {
    final msgPtr = message.toNativeUtf8();
    final plaintextOut = calloc<Pointer<Char>>();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = _bindings.pgp_certificate_verify_cleartext(
        _ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      if (code != 0) throw PgpException(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(plaintextOut.value);
      calloc.free(fpOut.value);
      return SignedPlaintext(
        plaintext: pt,
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(msgPtr);
      calloc.free(plaintextOut);
      calloc.free(fpOut);
      calloc.free(epochOut);
    }
  }

  /// Decrypts and verifies a signed+encrypted [message] produced by
  /// [PGP.encryptAndSign]. [verifyCert] is the signer's public certificate.
  ///
  /// Returns [SignedPlaintext] with the plaintext and the signing subkey
  /// fingerprint. Throws [PgpException] if decryption or verification fails.
  SignedPlaintext decryptAndVerify(String message, Certificate verifyCert) {
    final msgPtr = message.toNativeUtf8();
    final plaintextOut = calloc<Pointer<Char>>();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = _bindings.pgp_decrypt_and_verify_string(
        _ptr,
        verifyCert._ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      if (code != 0) throw PgpException(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(plaintextOut.value);
      calloc.free(fpOut.value);
      return SignedPlaintext(
        plaintext: pt,
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(msgPtr);
      calloc.free(plaintextOut);
      calloc.free(fpOut);
      calloc.free(epochOut);
    }
  }

  /// Signs [plaintext] with this secret certificate and encrypts it with
  /// [passphrase] (no recipient public key required): the passphrase-only
  /// counterpart to [PGP.encryptAndSign]. Returns a single ASCII-armored
  /// message; decrypt and verify it with [decryptAndVerifySymmetric].
  String encryptAndSignSymmetric(String plaintext, String passphrase) {
    final ptPtr = plaintext.toNativeUtf8();
    final ppPtr = passphrase.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_and_sign_string_symmetric(
          _ptr, ptPtr.cast(), ppPtr.cast(), out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(ptPtr);
      calloc.free(ppPtr);
      calloc.free(out);
    }
  }

  /// Decrypts a passphrase-encrypted, signed [message] (produced by
  /// [encryptAndSignSymmetric]) using [passphrase], verifying the signature
  /// against this certificate: the passphrase-only counterpart to
  /// [decryptAndVerify].
  ///
  /// Throws [PgpException] if the passphrase is wrong, the message has no
  /// SKESK, or it carries no valid signature from this certificate.
  SignedPlaintext decryptAndVerifySymmetric(String message, String passphrase) {
    final msgPtr = message.toNativeUtf8();
    final ppPtr = passphrase.toNativeUtf8();
    final plaintextOut = calloc<Pointer<Char>>();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = _bindings.pgp_decrypt_and_verify_string_symmetric(
        _ptr,
        msgPtr.cast(),
        ppPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      if (code != 0) throw PgpException(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      calloc.free(plaintextOut.value);
      calloc.free(fpOut.value);
      return SignedPlaintext(
        plaintext: pt,
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(msgPtr);
      calloc.free(ppPtr);
      calloc.free(plaintextOut);
      calloc.free(fpOut);
      calloc.free(epochOut);
    }
  }

  /// Frees the native certificate.  The handle must not be used afterwards.
  void dispose() => _bindings.pgp_certificate_free(_ptr);

  /// Runs a `pgp-ffi` call that writes a new certificate to its out-pointer.
  Certificate _derive(int Function(Pointer<Pointer<ffi.Certificate>>) call) {
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = call(out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(out);
    }
  }
}

class PGP {
  /// Encrypts [plaintext] to every certificate in [recipients], returning a
  /// single ASCII-armored OpenPGP message that any recipient can decrypt.
  ///
  /// Throws [PgpException] if [recipients] is empty or no certificate has a
  /// usable transport-encryption subkey.
  static String encryptToRecipients(
      List<Certificate> recipients, String plaintext) {
    if (recipients.isEmpty) throw PgpException(-4); // FFIError::NotFound

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final plaintextPtr = plaintext.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_string_to_recipients(
        certsArray.cast(),
        recipients.length,
        plaintextPtr.cast(),
        out,
      );
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(plaintextPtr);
      calloc.free(out);
    }
  }

  /// Encrypts raw [data] bytes to all [recipients], returning an
  /// ASCII-armored message any recipient can [Certificate.decryptBytes].
  static String encryptBytesToRecipients(
      List<Certificate> recipients, Uint8List data) {
    if (recipients.isEmpty) throw PgpException(-4);

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final dataPtr = calloc<Uint8>(data.length.clamp(1, data.length + 1));
    for (var i = 0; i < data.length; i++) {
      dataPtr[i] = data[i];
    }
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_bytes_to_recipients(
        certsArray.cast(),
        recipients.length,
        dataPtr.cast(),
        data.length,
        out,
      );
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(dataPtr);
      calloc.free(out);
    }
  }

  /// Encrypts [plaintext] to all [recipients] and signs with [signer].
  ///
  /// Returns a single ASCII-armored message. Any recipient can call
  /// [Certificate.decryptAndVerify] with the signer's public certificate to
  /// recover the plaintext and confirm authenticity.
  static String encryptAndSign(
    Certificate signer,
    List<Certificate> recipients,
    String plaintext,
  ) {
    if (recipients.isEmpty) throw PgpException(-4);

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final plaintextPtr = plaintext.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_and_sign_string(
        signer._ptr,
        certsArray.cast(),
        recipients.length,
        plaintextPtr.cast(),
        out,
      );
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(plaintextPtr);
      calloc.free(out);
    }
  }

  /// Encrypts [plaintext] symmetrically using [passphrase] (no public key
  /// required). Returns an ASCII-armored message.
  static String encryptSymmetric(String plaintext, String passphrase) {
    final ptPtr = plaintext.toNativeUtf8();
    final ppPtr = passphrase.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_string_symmetric(
          ptPtr.cast(), ppPtr.cast(), out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(ptPtr);
      calloc.free(ppPtr);
      calloc.free(out);
    }
  }

  /// Decrypts a passphrase-encrypted [message] using [passphrase].
  ///
  /// Throws [PgpException] if the passphrase is wrong or the message was not
  /// symmetrically encrypted.
  static String decryptSymmetric(String message, String passphrase) {
    final msgPtr = message.toNativeUtf8();
    final ppPtr = passphrase.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_decrypt_string_symmetric(
          msgPtr.cast(), ppPtr.cast(), out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(msgPtr);
      calloc.free(ppPtr);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId].
  Certificate generateKey(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = _bindings.pgp_key_generate(userIdPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId] using [cipherSuite]
  /// instead of the default [CipherSuite.cv25519]: e.g. to produce an RSA
  /// key for interoperating with a target that requires one.
  Certificate generateKeyWithCipherSuite(String userId, CipherSuite cipherSuite) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = _bindings.pgp_key_generate_with_cipher_suite(
          userIdPointer.cast(), cipherSuite.code, out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId] with an optional validity
  /// period. Pass null or [Duration.zero] for no expiry.
  Certificate generateKeyWithExpiry(String userId, Duration? validity) {
    final userIdPtr = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final secs = (validity == null || validity == Duration.zero)
          ? 0
          : validity.inSeconds;
      final code =
          _bindings.pgp_key_generate_with_expiry(userIdPtr.cast(), secs, out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPtr);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId] with all secret key
  /// material encrypted with [passphrase].
  Certificate generateLockedKey(String userId, String passphrase) {
    final userIdPtr = userId.toNativeUtf8();
    final passphrasePtr = passphrase.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = _bindings.pgp_key_generate_with_passphrase(
          userIdPtr.cast(), passphrasePtr.cast(), out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPtr);
      calloc.free(passphrasePtr);
      calloc.free(out);
    }
  }

  /// Parses an ASCII-armored certificate.
  Certificate certificateFromArmored(String armored) {
    final armoredPointer = armored.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code =
          _bindings.pgp_certificate_from_armored(armoredPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(armoredPointer);
      calloc.free(out);
    }
  }
}
