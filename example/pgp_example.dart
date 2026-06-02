import 'dart:convert';

import 'package:pgp/pgp.dart';

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

  // Key-management methods return a new certificate; dispose the old one.
  cert = _replace(cert, cert.addUserId('other@example.org'));
  cert = _replace(cert, cert.addTransportEncryptionSubkey());
  cert = _replace(cert, cert.revokeUserId('other@example.org'));
  cert = _replace(cert, cert.revokeSubkey(0));
  cert = _replace(cert, cert.revoke());

  print(cert.exportSecretArmored());
  cert.dispose();
}

/// Disposes [old] and returns [updated] in its place.
Certificate _replace(Certificate old, Certificate updated) {
  old.dispose();
  return updated;
}
