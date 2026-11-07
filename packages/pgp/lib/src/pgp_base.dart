import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pgp_dart/pgp_dart.dart';

import 'pgp-ffi_bindings_generated.dart' as ffi;

/// Verifies that the bundled `pgp_ffi` native library is loaded and
/// resolvable. Safe to call repeatedly.
void ensureNativeLibrary() {
  final out = calloc<Pointer<Char>>();
  try {
    final code = ffi.pgp_last_error_message(out);
    if (code == 0 && out.value != nullptr) {
      ffi.pgp_free(out.value.cast());
    }
  } finally {
    calloc.free(out);
  }
}

void _check(int code) {
  if (code != 0) throw _pgpError(code);
}

PgpException _pgpError(int code) => PgpException(code);

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
  String exportPublicArmored() =>
      _exportArmored(ffi.pgp_certificate_export_public_armored);

  /// Exports the certificate as an ASCII-armored secret key block.
  String exportSecretArmored() =>
      _exportArmored(ffi.pgp_certificate_export_secret_armored);

  /// Exports the certificate as an ASCII-armored secret key block.
  ///
  /// Prefer [exportPublicArmored] when sharing a certificate with others.
  String exportArmored() => exportSecretArmored();

  /// Encrypts [plaintext] to this certificate as an ASCII-armored message.
  String encrypt(String plaintext) =>
      _transformString(plaintext, ffi.pgp_certificate_encrypt_string);

  /// Decrypts an ASCII-armored [message] with this secret certificate.
  String decrypt(String message) =>
      _transformString(message, ffi.pgp_certificate_decrypt_string);

  /// Encrypts the file at [inputPath] to this certificate, streaming the
  /// ASCII-armored result to [outputPath].
  ///
  /// Unlike [encrypt], which requires the whole plaintext to already be a
  /// Dart [String] in memory, this streams the data straight from/to disk on
  /// the native side, so encrypting a file far larger than would comfortably
  /// fit in memory (e.g. a multi-gigabyte backup) doesn't require ever
  /// holding it all at once. Throws [PgpException] on failure; any output
  /// file already created is removed first.
  void encryptFile(String inputPath, String outputPath) {
    final inPtr = inputPath.toNativeUtf8();
    final outPtr = outputPath.toNativeUtf8();
    try {
      final code = ffi.pgp_certificate_encrypt_file(
        _ptr,
        inPtr.cast(),
        outPtr.cast(),
      );
      _check(code);
    } finally {
      calloc.free(inPtr);
      calloc.free(outPtr);
    }
  }

  /// Decrypts the ASCII-armored message at [inputPath] with this secret
  /// certificate, streaming the plaintext to [outputPath]. The file-based
  /// counterpart of [decrypt]; see [encryptFile] for why this exists.
  ///
  /// Throws [PgpException] on failure; any output file already created is
  /// removed first.
  void decryptFile(String inputPath, String outputPath) {
    final inPtr = inputPath.toNativeUtf8();
    final outPtr = outputPath.toNativeUtf8();
    try {
      final code = ffi.pgp_certificate_decrypt_file(
        _ptr,
        inPtr.cast(),
        outPtr.cast(),
      );
      _check(code);
    } finally {
      calloc.free(inPtr);
      calloc.free(outPtr);
    }
  }

  /// Recovers the symmetric session key that encrypts [message]'s body,
  /// using this certificate's transport-encryption subkey(s), *without*
  /// decrypting the message body itself. Useful for archival/escrow
  /// workflows: the recovered [SessionKeyInfo] can be stored or handed to a
  /// third party to later decrypt the message via
  /// [PGP.decryptWithSessionKey], without ever exposing this certificate's
  /// long-term secret key material to that party.
  ///
  /// Throws [PgpException] if no PKESK packet in [message] can be decrypted
  /// with any of this certificate's transport-encryption subkeys.
  SessionKeyInfo sessionKey(String message) {
    final msgPtr = message.toNativeUtf8();
    final hexOut = calloc<Pointer<Char>>();
    final algoOut = calloc<Uint8>();
    try {
      final code = ffi.pgp_message_session_key(
        _ptr,
        msgPtr.cast(),
        hexOut,
        algoOut,
      );
      _check(code);
      final hex = hexOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(hexOut.value.cast());
      return SessionKeyInfo(hex: hex, algo: algoOut.value);
    } finally {
      calloc.free(msgPtr);
      calloc.free(hexOut);
      calloc.free(algoOut);
    }
  }

  /// Signs [plaintext] with this secret certificate as an armored message.
  String sign(String plaintext) =>
      _transformString(plaintext, ffi.pgp_certificate_sign_string);

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
      final code = ffi.pgp_certificate_verify_string(
        _ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      _check(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(plaintextOut.value.cast());
      ffi.pgp_free(fpOut.value.cast());
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
      _check(code);
      final armored = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
    )
    call,
  ) {
    final inputPointer = input.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = call(_ptr, inputPointer.cast(), out);
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      return _derive(
        (out) => ffi.pgp_certificate_revoke(
          _ptr,
          reason.code,
          messagePointer?.cast() ?? nullptr,
          out,
        ),
      );
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
      final code = ffi.pgp_certificate_revocation_info(
        _ptr,
        revokedOut,
        reasonOut,
        messageOut,
      );
      _check(code);
      final message = messageOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(messageOut.value.cast());
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
      final code = ffi.pgp_certificate_generate_revocation_armored(
        _ptr,
        reason.code,
        messagePointer?.cast() ?? nullptr,
        out,
      );
      _check(code);
      final armored = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      return _derive(
        (out) => ffi.pgp_certificate_apply_revocation_armored(
          _ptr,
          armoredPointer.cast(),
          out,
        ),
      );
    } finally {
      calloc.free(armoredPointer);
    }
  }

  /// Designates [revoker] as authorized to revoke this certificate on its
  /// behalf: RFC 4880's designated-revoker mechanism (the
  /// `gpg --edit-key addrevoker` workflow), a recovery path for when this
  /// certificate's own secret key or passphrase is later lost or
  /// compromised. Returns an updated copy of this certificate; the receiver
  /// is left unmodified. Once published, [revoker]'s own secret key can
  /// later revoke this certificate via [generateRevocationArmoredFor], even
  /// without access to this certificate's secret key at all.
  ///
  /// Throws [PgpException] if this certificate's certification-capable
  /// secret key isn't available.
  Certificate addDesignatedRevoker(Certificate revoker) {
    return _derive(
      (out) =>
          ffi.pgp_certificate_add_designated_revoker(_ptr, revoker._ptr, out),
    );
  }

  /// Returns the designated revokers configured on this certificate (via
  /// [addDesignatedRevoker]), deduplicated.
  List<DesignatedRevoker> revocationKeys() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_certificate_revocation_keys(_ptr, out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      if (raw.isEmpty) return [];
      return raw.split('\n').map((line) {
        final fields = line.split('\t');
        return DesignatedRevoker(
          fingerprint: fields[0],
          sensitive: fields[1] == '1',
        );
      }).toList();
    } finally {
      calloc.free(out);
    }
  }

  /// Generates a standalone, ASCII-armored revocation certificate for
  /// [target], signed by this certificate rather than by [target] itself:
  /// the counterpart to [generateRevocationArmored] for a designated
  /// revoker ([addDesignatedRevoker]) to use when [target]'s own secret key
  /// or passphrase has been lost or compromised. This certificate's
  /// certification-capable secret key must be available; [target] need not
  /// have any secret key material at all. Apply the result with
  /// [applyRevocationArmored] on [target], exactly as with a self-generated
  /// revocation certificate, then confirm it with
  /// [target].[verifyDesignatedRevocation].
  ///
  /// [reason] and [message] use the same conventions as [revoke].
  String generateRevocationArmoredFor(
    Certificate target, {
    RevocationReason reason = RevocationReason.unspecified,
    String? message,
  }) {
    final messagePointer = message?.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_certificate_generate_revocation_armored_by(
        _ptr,
        target._ptr,
        reason.code,
        messagePointer?.cast() ?? nullptr,
        out,
      );
      _check(code);
      final armored = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return armored;
    } finally {
      if (messagePointer != null) calloc.free(messagePointer);
      calloc.free(out);
    }
  }

  /// Cryptographically verifies that this certificate's revocation was
  /// genuinely authorized by [revoker] as a designated revoker.
  ///
  /// A revocation signed by a key other than this certificate's own primary
  /// key (e.g. one applied via [applyRevocationArmored] using a signature
  /// from [generateRevocationArmoredFor]) is *not* reflected by
  /// [revocationInfo]: trusting it requires confirming both that [revoker]
  /// is genuinely listed among this certificate's own designated revokers
  /// and that the signature verifies against [revoker]'s key, which is what
  /// this method does. Returns false (not an exception) if no such
  /// revocation signature from [revoker] is present at all.
  bool verifyDesignatedRevocation(Certificate revoker) {
    final out = calloc<Uint8>();
    try {
      final code = ffi.pgp_certificate_verify_designated_revocation(
        _ptr,
        revoker._ptr,
        out,
      );
      if (code == -4) return false; // NotFound
      _check(code);
      return out.value == 1;
    } finally {
      calloc.free(out);
    }
  }

  /// Sets this certificate's algorithm-preference and features
  /// self-signature subpackets (RFC 4880), returning the updated certificate;
  /// the receiver is unchanged. These tell other implementations which
  /// symmetric/hash/compression algorithms this certificate supports when
  /// they encrypt or sign for it, and which optional OpenPGP features (e.g.
  /// SEIPDv2/AEAD) it understands. Each algorithm list may be empty (which
  /// records an empty preference list, distinct from the subpacket being
  /// absent entirely). `features` is the raw first octet of the RFC 4880
  /// Features subpacket (bit 0 = SEIPDv1, bit 1 = AEAD, bit 2 = SEIPDv2);
  /// defaults to 0.
  ///
  /// Throws [PgpException] if this certificate's certification-capable
  /// secret key isn't available.
  Certificate setPreferences({
    List<int> symmetricAlgorithms = const [],
    List<int> hashAlgorithms = const [],
    List<int> compressionAlgorithms = const [],
    int features = 0,
  }) {
    final symPtr = calloc<Uint8>(
      symmetricAlgorithms.length.clamp(1, symmetricAlgorithms.length + 1),
    );
    final hashPtr = calloc<Uint8>(
      hashAlgorithms.length.clamp(1, hashAlgorithms.length + 1),
    );
    final compPtr = calloc<Uint8>(
      compressionAlgorithms.length.clamp(1, compressionAlgorithms.length + 1),
    );
    try {
      for (var i = 0; i < symmetricAlgorithms.length; i++) {
        symPtr[i] = symmetricAlgorithms[i];
      }
      for (var i = 0; i < hashAlgorithms.length; i++) {
        hashPtr[i] = hashAlgorithms[i];
      }
      for (var i = 0; i < compressionAlgorithms.length; i++) {
        compPtr[i] = compressionAlgorithms[i];
      }
      return _derive(
        (out) => ffi.pgp_certificate_set_preferences(
          _ptr,
          symPtr,
          symmetricAlgorithms.length,
          hashPtr,
          hashAlgorithms.length,
          compPtr,
          compressionAlgorithms.length,
          features,
          out,
        ),
      );
    } finally {
      calloc.free(symPtr);
      calloc.free(hashPtr);
      calloc.free(compPtr);
    }
  }

  /// Reads back this certificate's algorithm-preference and features
  /// subpackets (as set by [setPreferences], or Sequoia's own defaults if
  /// that has never been called).
  CertificatePreferences preferences() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_certificate_preferences(_ptr, out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      final fields = raw.split('\t');
      List<int> parseCsv(String s) =>
          s.isEmpty ? [] : s.split(',').map(int.parse).toList();
      return CertificatePreferences(
        symmetricAlgorithms: parseCsv(fields[0]),
        hashAlgorithms: parseCsv(fields[1]),
        compressionAlgorithms: parseCsv(fields[2]),
        features: int.parse(fields[3]),
      );
    } finally {
      calloc.free(out);
    }
  }

  /// Adds a transport-encryption subkey, returning the updated certificate.
  Certificate addTransportEncryptionSubkey() => _derive(
    (out) => ffi.pgp_certificate_add_transport_encryption_subkey(_ptr, out),
  );

  /// Adds a signing subkey, returning the updated certificate.
  Certificate addSigningSubkey() =>
      _derive((out) => ffi.pgp_certificate_add_signing_subkey(_ptr, out));

  /// Adds an authentication subkey, returning the updated certificate.
  Certificate addAuthenticationSubkey() => _derive(
    (out) => ffi.pgp_certificate_add_authentication_subkey(_ptr, out),
  );

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
      return _derive(
        (out) => ffi.pgp_certificate_revoke_subkey(
          _ptr,
          index,
          reason.code,
          messagePointer?.cast() ?? nullptr,
          out,
        ),
      );
    } finally {
      if (messagePointer != null) calloc.free(messagePointer);
    }
  }

  /// Adds [userId] to the certificate, returning the updated certificate.
  Certificate addUserId(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive(
        (out) =>
            ffi.pgp_certificate_add_userid(_ptr, userIdPointer.cast(), out),
      );
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
      return _derive(
        (out) => ffi.pgp_certificate_revoke_userid(
          _ptr,
          userIdPointer.cast(),
          reason.code,
          messagePointer?.cast() ?? nullptr,
          out,
        ),
      );
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
      return _derive(
        (out) => ffi.pgp_certificate_certify_userid(
          _ptr,
          target._ptr,
          userIdPointer.cast(),
          out,
        ),
      );
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Like [certifyUserId], but records an RFC 4880 Trust Signature:
  /// delegated trust rather than plain direct certification, letting the
  /// certifier be trusted not just to vouch for a user ID, but to introduce
  /// *other* trusted certifiers (a certificate-authority hierarchy).
  ///
  /// [trustDepth] is the RFC 4880 trust level (0 = not trusted to certify
  /// further; 1 = a trusted introducer; 2+ = can designate further trusted
  /// introducers). [trustAmount] is the degree of confidence out of 255 (120
  /// conventionally means "fully trusted", 60 "marginally trusted"). This
  /// library records and reports both values via [userIdCertifications] but
  /// does not itself interpret them.
  ///
  /// Throws [PgpException] if [userId] isn't present on [target] or if this
  /// certificate's certification-capable secret key isn't available.
  Certificate certifyUserIdWithTrust(
    Certificate target,
    String userId, {
    required int trustDepth,
    required int trustAmount,
  }) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive(
        (out) => ffi.pgp_certificate_certify_userid_with_trust(
          _ptr,
          target._ptr,
          userIdPointer.cast(),
          trustDepth,
          trustAmount,
          out,
        ),
      );
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
      return _derive(
        (out) => ffi.pgp_certificate_revoke_userid_certification(
          _ptr,
          target._ptr,
          userIdPointer.cast(),
          reason.code,
          messagePointer?.cast() ?? nullptr,
          out,
        ),
      );
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
      return _derive(
        (out) => ffi.pgp_certificate_set_primary_userid(
          _ptr,
          userIdPointer.cast(),
          out,
        ),
      );
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Like [certifyUserId], but records an RFC 4880 Exportable Certification
  /// subpacket: GnuPG's `--lsign-key` "local certification" concept. When
  /// [exportable] is `false`, [exportPublicArmored] (the method meant for
  /// sharing a certificate with others) silently omits this certification
  /// from its output, while it remains fully present and inspectable (via
  /// [userIdCertifications]) on the in-memory certificate returned here or
  /// on one reloaded from [exportSecretArmored]. Useful for vouching for a
  /// key only within a private, local trust database without that
  /// endorsement leaking onto a keyserver.
  ///
  /// Throws [PgpException] if [userId] isn't present on [target] or if this
  /// certificate's certification-capable secret key isn't available.
  Certificate certifyUserIdExportable(
    Certificate target,
    String userId, {
    required bool exportable,
  }) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive(
        (out) => ffi.pgp_certificate_certify_userid_exportable(
          _ptr,
          target._ptr,
          userIdPointer.cast(),
          exportable ? 1 : 0,
          out,
        ),
      );
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
    return _derive((out) => ffi.pgp_certificate_merge(_ptr, other._ptr, out));
  }

  /// Returns the primary key fingerprint as a 40-character uppercase hex string.
  String fingerprint() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_certificate_fingerprint(_ptr, out);
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return result;
    } finally {
      calloc.free(out);
    }
  }

  /// Returns all user IDs on this certificate, including revoked ones.
  List<String> userIds() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_certificate_userids(_ptr, out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_certificate_userids_info(_ptr, out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_certificate_userid_certifications(
        _ptr,
        userIdPointer.cast(),
        out,
      );
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      if (raw.isEmpty) return [];
      return raw.split('\n').map((line) {
        final fields = line.split('\t');
        return CertifierInfo(
          fingerprint: fields[0],
          isRevoked: fields[1] == '1',
          trustDepth: int.parse(fields[2]),
          trustAmount: int.parse(fields[3]),
          isExportable: fields[4] == '1',
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
  /// if no certification issued by [issuer] is attached (matching prefers
  /// [issuer]'s fingerprint but falls back to a legacy bare key ID for
  /// certifications from other implementations that only carry that).
  bool verifyUserIdCertification(Certificate issuer, String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Uint8>();
    try {
      final code = ffi.pgp_certificate_verify_userid_certification(
        _ptr,
        issuer._ptr,
        userIdPointer.cast(),
        out,
      );
      _check(code);
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
      final code = ffi.pgp_certificate_subkeys(_ptr, out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_certificate_expiry_epoch(_ptr, out);
      _check(code);
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
  String signDetached(String plaintext) =>
      _transformString(plaintext, ffi.pgp_certificate_sign_detached);

  /// Verifies [armoredSig] against [plaintext] using this certificate.
  ///
  /// Returns true if the signature is valid. Throws [PgpException] if
  /// verification fails or the signature is malformed.
  bool verifyDetached(String plaintext, String armoredSig) {
    final p1 = plaintext.toNativeUtf8();
    final p2 = armoredSig.toNativeUtf8();
    try {
      final code = ffi.pgp_certificate_verify_detached(
        _ptr,
        p1.cast(),
        p2.cast(),
        nullptr,
        nullptr,
      );
      _check(code);
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
      final code = ffi.pgp_certificate_verify_detached(
        _ptr,
        p1.cast(),
        p2.cast(),
        fpOut,
        nullptr,
      );
      _check(code);
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(fpOut.value.cast());
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
        (out) => ffi.pgp_certificate_unlock(_ptr, passphrasePtr.cast(), out),
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
        (out) => ffi.pgp_certificate_lock(_ptr, passphrasePtr.cast(), out),
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
    return _derive((out) => ffi.pgp_certificate_set_expiry(_ptr, secs, out));
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
    return _derive(
      (out) => ffi.pgp_certificate_set_subkey_expiry(_ptr, index, secs, out),
    );
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
      final code = ffi.pgp_certificate_encrypt_bytes(
        _ptr,
        dataPtr.cast(),
        data.length,
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_certificate_decrypt_bytes(
        _ptr,
        msgPtr.cast(),
        outPtr,
        outLen,
      );
      _check(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      ffi.pgp_free(outPtr.value.cast());
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
      final code = ffi.pgp_certificate_sign_bytes(
        _ptr,
        dataPtr.cast(),
        data.length,
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_certificate_verify_bytes(
        _ptr,
        msgPtr.cast(),
        outPtr,
        outLen,
        nullptr,
        nullptr,
      );
      _check(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      ffi.pgp_free(outPtr.value.cast());
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
      final code = ffi.pgp_certificate_verify_bytes(
        _ptr,
        msgPtr.cast(),
        outPtr,
        outLen,
        fpOut,
        epochOut,
      );
      _check(code);
      final len = outLen.value;
      final result = Uint8List.fromList(outPtr.value.asTypedList(len));
      ffi.pgp_free(outPtr.value.cast());
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(fpOut.value.cast());
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
  String signCleartext(String plaintext) =>
      _transformString(plaintext, ffi.pgp_certificate_sign_cleartext);

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
      final code = ffi.pgp_certificate_verify_cleartext(
        _ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      _check(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(plaintextOut.value.cast());
      ffi.pgp_free(fpOut.value.cast());
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
      final code = ffi.pgp_decrypt_and_verify_string(
        _ptr,
        verifyCert._ptr,
        msgPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      _check(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(plaintextOut.value.cast());
      ffi.pgp_free(fpOut.value.cast());
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

  /// Decrypts and verifies a signed+encrypted message at [inputPath]
  /// (produced by [PGP.encryptAndSignFile]), streaming the plaintext to
  /// [outputPath]. [verifyCert] is the signer's public certificate. The
  /// file-based counterpart of [decryptAndVerify]; see [encryptFile] for why
  /// this exists.
  ///
  /// Returns the signer's fingerprint and the signature's creation time.
  /// Throws [PgpException] if decryption or verification fails; any output
  /// file already created is removed first.
  FileSignatureInfo decryptAndVerifyFile(
    String inputPath,
    String outputPath,
    Certificate verifyCert,
  ) {
    final inPtr = inputPath.toNativeUtf8();
    final outPtr = outputPath.toNativeUtf8();
    final fpOut = calloc<Pointer<Char>>();
    final epochOut = calloc<Int64>();
    try {
      final code = ffi.pgp_decrypt_and_verify_file(
        _ptr,
        verifyCert._ptr,
        inPtr.cast(),
        outPtr.cast(),
        fpOut,
        epochOut,
      );
      _check(code);
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(fpOut.value.cast());
      return FileSignatureInfo(
        signerFingerprint: fp,
        signedAtEpoch: epochOut.value,
      );
    } finally {
      calloc.free(inPtr);
      calloc.free(outPtr);
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
      final code = ffi.pgp_encrypt_and_sign_string_symmetric(
        _ptr,
        ptPtr.cast(),
        ppPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_decrypt_and_verify_string_symmetric(
        _ptr,
        msgPtr.cast(),
        ppPtr.cast(),
        plaintextOut,
        fpOut,
        epochOut,
      );
      _check(code);
      final pt = plaintextOut.value.cast<Utf8>().toDartString();
      final fp = fpOut.value.cast<Utf8>().toDartString();
      ffi.pgp_free(plaintextOut.value.cast());
      ffi.pgp_free(fpOut.value.cast());
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
  void dispose() => ffi.pgp_certificate_free(_ptr);

  /// Runs a `pgp-ffi` call that writes a new certificate to its out-pointer.
  Certificate _derive(int Function(Pointer<Pointer<ffi.Certificate>>) call) {
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = call(out);
      _check(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(out);
    }
  }
}

class PGP {
  /// Lists the recipient key IDs [armoredMessage] is addressed to, without
  /// decrypting it and without needing any secret key material: reads each
  /// top-level PKESK packet's recipient key ID off the message. Each entry
  /// is a 16-character uppercase hex key ID (the low 64 bits of a
  /// fingerprint, not a full fingerprint), or the literal string `"hidden"`
  /// for a hidden/wildcard recipient. Useful for a multi-key client to
  /// determine which of its keys, if any, could plausibly decrypt a message
  /// before attempting to do so.
  ///
  /// Throws [PgpException] if [armoredMessage] isn't a valid OpenPGP message.
  static List<String> messageRecipientKeyIds(String armoredMessage) {
    final msgPtr = armoredMessage.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_message_recipient_key_ids(msgPtr.cast(), out);
      _check(code);
      final raw = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return raw.isEmpty ? [] : raw.split('\n');
    } finally {
      calloc.free(msgPtr);
      calloc.free(out);
    }
  }

  /// Decrypts an ASCII-armored [armoredMessage] using [sessionKeyInfo] (e.g.
  /// recovered via [Certificate.sessionKey]) instead of a certificate's
  /// secret key material: no [Certificate] is needed at all.
  ///
  /// Throws [PgpException] if the session key doesn't decrypt the message.
  static String decryptWithSessionKey(
    SessionKeyInfo sessionKeyInfo,
    String armoredMessage,
  ) {
    final hexPtr = sessionKeyInfo.hex.toNativeUtf8();
    final msgPtr = armoredMessage.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_decrypt_with_session_key(
        hexPtr.cast(),
        sessionKeyInfo.algo,
        msgPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return result;
    } finally {
      calloc.free(hexPtr);
      calloc.free(msgPtr);
      calloc.free(out);
    }
  }

  /// Encrypts [plaintext] to every certificate in [recipients], returning a
  /// single ASCII-armored OpenPGP message that any recipient can decrypt.
  ///
  /// Throws [PgpException] if [recipients] is empty or no certificate has a
  /// usable transport-encryption subkey.
  static String encryptToRecipients(
    List<Certificate> recipients,
    String plaintext,
  ) {
    if (recipients.isEmpty) throw PgpException(-4); // FFIError::NotFound

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final plaintextPtr = plaintext.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_encrypt_string_to_recipients(
        certsArray.cast(),
        recipients.length,
        plaintextPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(plaintextPtr);
      calloc.free(out);
    }
  }

  /// Encrypts the file at [inputPath] to all [recipients], streaming the
  /// ASCII-armored result to [outputPath]. The file-based counterpart of
  /// [encryptToRecipients]; see [Certificate.encryptFile] for why this exists
  /// alongside it (which only supports a single recipient).
  static void encryptToRecipientsFile(
    List<Certificate> recipients,
    String inputPath,
    String outputPath,
  ) {
    if (recipients.isEmpty) throw PgpException(-4); // FFIError::NotFound

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final inPtr = inputPath.toNativeUtf8();
    final outPtr = outputPath.toNativeUtf8();
    try {
      final code = ffi.pgp_encrypt_to_recipients_file(
        certsArray.cast(),
        recipients.length,
        inPtr.cast(),
        outPtr.cast(),
      );
      _check(code);
    } finally {
      calloc.free(certsArray);
      calloc.free(inPtr);
      calloc.free(outPtr);
    }
  }

  /// Encrypts raw [data] bytes to all [recipients], returning an
  /// ASCII-armored message any recipient can [Certificate.decryptBytes].
  static String encryptBytesToRecipients(
    List<Certificate> recipients,
    Uint8List data,
  ) {
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
      final code = ffi.pgp_encrypt_bytes_to_recipients(
        certsArray.cast(),
        recipients.length,
        dataPtr.cast(),
        data.length,
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_encrypt_and_sign_string(
        signer._ptr,
        certsArray.cast(),
        recipients.length,
        plaintextPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(plaintextPtr);
      calloc.free(out);
    }
  }

  /// Encrypts the file at [inputPath] to all [recipients] and signs it with
  /// [signer], streaming the ASCII-armored result to [outputPath]. The
  /// file-based counterpart of [encryptAndSign]; see
  /// [Certificate.encryptFile] for why this exists. Any recipient can call
  /// [Certificate.decryptAndVerifyFile] with the signer's public certificate
  /// to recover the plaintext and confirm authenticity.
  static void encryptAndSignFile(
    Certificate signer,
    List<Certificate> recipients,
    String inputPath,
    String outputPath,
  ) {
    if (recipients.isEmpty) throw PgpException(-4);

    final certsArray = calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final inPtr = inputPath.toNativeUtf8();
    final outPtr = outputPath.toNativeUtf8();
    try {
      final code = ffi.pgp_encrypt_and_sign_file(
        signer._ptr,
        certsArray.cast(),
        recipients.length,
        inPtr.cast(),
        outPtr.cast(),
      );
      _check(code);
    } finally {
      calloc.free(certsArray);
      calloc.free(inPtr);
      calloc.free(outPtr);
    }
  }

  /// Encrypts [plaintext] symmetrically using [passphrase] (no public key
  /// required). Returns an ASCII-armored message.
  static String encryptSymmetric(String plaintext, String passphrase) {
    final ptPtr = plaintext.toNativeUtf8();
    final ppPtr = passphrase.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = ffi.pgp_encrypt_string_symmetric(
        ptPtr.cast(),
        ppPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_decrypt_string_symmetric(
        msgPtr.cast(),
        ppPtr.cast(),
        out,
      );
      _check(code);
      final result = out.value.cast<Utf8>().toDartString();
      ffi.pgp_free(out.value.cast());
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
      final code = ffi.pgp_key_generate(userIdPointer.cast(), out);
      _check(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId] using [cipherSuite]
  /// instead of the default [CipherSuite.cv25519]: e.g. to produce an RSA
  /// key for interoperating with a target that requires one.
  Certificate generateKeyWithCipherSuite(
    String userId,
    CipherSuite cipherSuite,
  ) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = ffi.pgp_key_generate_with_cipher_suite(
        userIdPointer.cast(),
        cipherSuite.code,
        out,
      );
      _check(code);
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
      final code = ffi.pgp_key_generate_with_expiry(
        userIdPtr.cast(),
        secs,
        out,
      );
      _check(code);
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
      final code = ffi.pgp_key_generate_with_passphrase(
        userIdPtr.cast(),
        passphrasePtr.cast(),
        out,
      );
      _check(code);
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
      final code = ffi.pgp_certificate_from_armored(armoredPointer.cast(), out);
      _check(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(armoredPointer);
      calloc.free(out);
    }
  }
}
