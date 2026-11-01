import 'dart:convert';

import 'package:pgp_dart/pgp_dart.dart';

void main() {
  final pgp = PGP();

  // Generate a certificate with encryption and signing subkeys.
  var cert = pgp.generateKey('someone@example.org');
  final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

  final encrypted = publicCert.encrypt('hello OpenPGP');
  print(cert.decrypt(encrypted));

  final signed = cert.sign('hello signed OpenPGP');
  print(publicCert.verify(signed));

  // Inspect a certificate.
  final info = cert.info();
  print('fingerprint: ${info.fingerprint}');
  print('user IDs: ${info.userIds}');

  // Detached and cleartext signatures.
  final detached = cert.signDetached('hello detached OpenPGP');
  print(publicCert.verifyDetached('hello detached OpenPGP', detached));
  print(cert.signCleartext('hello cleartext OpenPGP'));

  // Raw bytes.
  final encryptedBytes = publicCert.encryptBytes(utf8.encode('hello bytes'));
  print(utf8.decode(cert.decryptBytes(encryptedBytes)));

  // Multi-recipient and signed+encrypted messages.
  final other = pgp.generateKey('other-recipient@example.org');
  final otherPublic = pgp.certificateFromArmored(other.exportPublicArmored());
  final toBoth = PGP.encryptToRecipients(
      [publicCert, otherPublic], 'hello multiple recipients');
  print(cert.decrypt(toBoth));

  final signedAndEncrypted =
      PGP.encryptAndSign(cert, [otherPublic], 'hello signed and encrypted');
  final verified = other.decryptAndVerify(signedAndEncrypted, publicCert);
  print('${verified.plaintext} (signed by ${verified.signerFingerprint})');
  otherPublic.dispose();
  other.dispose();

  // Symmetric (passphrase-only) encryption, with no certificate involved.
  final symmetric = PGP.encryptSymmetric('hello symmetric', 'a passphrase');
  print(PGP.decryptSymmetric(symmetric, 'a passphrase'));

  // A passphrase-locked secret key must be unlocked before it can decrypt or
  // sign.
  var lockedCert = pgp.generateLockedKey('locked@example.org', 'a passphrase');
  lockedCert = lockedCert.unlock('a passphrase');

  // A key that expires in 30 days; expiry can also be cleared or changed
  // later with setExpiry.
  var expiringCert = pgp.generateKeyWithExpiry(
      'expiring@example.org', const Duration(days: 30));
  print('expires: ${expiringCert.expiryEpoch()}');

  publicCert.dispose();
  lockedCert.dispose();
  expiringCert.dispose();

  // Generating a key with a specific algorithm (default is Curve25519).
  final rsaCert =
      pgp.generateKeyWithCipherSuite('rsa@example.org', CipherSuite.rsa2k);
  rsaCert.dispose();

  // Inspecting subkeys and user IDs in detail.
  var alice = pgp.generateKey('alice@example.org');
  for (final subkey in alice.subkeys()) {
    print('subkey ${subkey.fingerprint}: encrypt=${subkey.canEncrypt} '
        'sign=${subkey.canSign}');
  }
  alice = _replace(alice, alice.addUserId('alice-work@example.org'));
  for (final userId in alice.userIdsInfo()) {
    print('${userId.userId}: primary=${userId.isPrimary}');
  }
  alice = _replace(alice, alice.setPrimaryUserId('alice-work@example.org'));

  // Third-party certification: Bob vouches for one of Alice's user IDs (the
  // basic web-of-trust building block).
  var bob = pgp.generateKey('bob@example.org');
  alice = _replace(alice, bob.certifyUserId(alice, 'alice@example.org'));
  final certifiers = alice.userIdCertifications('alice@example.org');
  print('certified by: ${certifiers.map((c) => c.fingerprint)}');
  print(
      'genuine: ${alice.verifyUserIdCertification(bob, 'alice@example.org')}');
  alice = _replace(
      alice, bob.revokeUserIdCertification(alice, 'alice@example.org'));
  bob.dispose();

  // Merging in updates from another copy of the same certificate (e.g. a
  // keyserver refresh) without discarding local state.
  var refreshed = pgp.certificateFromArmored(alice.exportSecretArmored());
  refreshed =
      _replace(refreshed, refreshed.addUserId('alice-refreshed@example.org'));
  alice = _replace(alice, alice.merge(refreshed));
  refreshed.dispose();

  // Locking (and unlocking) secret key material with a passphrase.
  final locked = alice.lock('a passphrase');
  final unlocked = locked.unlock('a passphrase');
  locked.dispose();
  unlocked.dispose();

  // Generating a standalone revocation certificate ahead of time (the
  // `gpg --gen-revoke` workflow) so the key can still be revoked later even
  // if its secret material is lost.
  final standaloneRevocation = alice.generateRevocationArmored(
      reason: RevocationReason.keyCompromised, message: 'lost the key');
  final revokedViaStandalone =
      alice.applyRevocationArmored(standaloneRevocation);
  print('revoked: ${revokedViaStandalone.revocationInfo().isRevoked}');
  revokedViaStandalone.dispose();

  // Signing and encrypting with a passphrase instead of a recipient key.
  final signedSymmetric =
      alice.encryptAndSignSymmetric('hello signed symmetric', 'a passphrase');
  final verifiedSymmetric =
      alice.decryptAndVerifySymmetric(signedSymmetric, 'a passphrase');
  print('${verifiedSymmetric.plaintext} '
      '(signed at ${verifiedSymmetric.signedAtDate})');

  // Listing who a message is addressed to, without decrypting it.
  final addressed = alice.encrypt('hello addressed');
  print('addressed to: ${PGP.messageRecipientKeyIds(addressed)}');

  alice.dispose();

  // Key-management methods return a new certificate; dispose the old one.
  cert = _replace(cert, cert.addUserId('other@example.org'));
  cert = _replace(cert, cert.addTransportEncryptionSubkey());
  cert = _replace(cert, cert.revokeUserId('other@example.org'));
  cert = _replace(cert, cert.revokeSubkey(0));
  cert = _replace(cert, cert.revoke());

  cert.dispose();
}

/// Disposes [old] and returns [updated] in its place.
Certificate _replace(Certificate old, Certificate updated) {
  old.dispose();
  return updated;
}
