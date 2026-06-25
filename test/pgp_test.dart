import 'dart:io';
import 'dart:typed_data';

import 'package:pgp/pgp.dart';
import 'package:test/test.dart';

void main() {
  final pgp = PGP();

  test('generateKey returns a certificate handle', () {
    final cert = pgp.generateKey('someone@example.org');
    expect(cert.pointer.address, isNonZero);
    cert.dispose();
  });

  test('generateKeyWithCipherSuite defaults match generateKey', () {
    final cvCert = pgp.generateKeyWithCipherSuite(
        'cv25519@example.org', CipherSuite.cv25519);
    expect(cvCert.pointer.address, isNonZero);
    cvCert.dispose();
  });

  test('generateKeyWithCipherSuite can produce an RSA key', () {
    final rsaCert =
        pgp.generateKeyWithCipherSuite('rsa@example.org', CipherSuite.rsa2k);
    expect(rsaCert.pointer.address, isNonZero);

    final encrypted = rsaCert.encrypt('hello RSA');
    final decrypted = rsaCert.decrypt(encrypted);
    expect(decrypted, 'hello RSA');

    rsaCert.dispose();
  });

  test('certificateFromArmored rejects invalid input', () {
    expect(() => pgp.certificateFromArmored('not a certificate'),
        throwsA(isA<PgpException>()));
  });

  test('exportArmored round-trips through certificateFromArmored', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportArmored();
    expect(armored, contains('-----BEGIN PGP PRIVATE KEY BLOCK-----'));

    final parsed = pgp.certificateFromArmored(armored);
    expect(parsed.pointer.address, isNonZero);

    parsed.dispose();
    cert.dispose();
  });

  test('exportPublicArmored emits a public key block', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportPublicArmored();
    expect(armored, contains('-----BEGIN PGP PUBLIC KEY BLOCK-----'));
    expect(armored, isNot(contains('PRIVATE KEY BLOCK')));
    cert.dispose();
  });

  test('exportSecretArmored emits a private key block', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportSecretArmored();
    expect(armored, contains('-----BEGIN PGP PRIVATE KEY BLOCK-----'));
    cert.dispose();
  });

  test('encrypt and decrypt round-trip through a public certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

    final encrypted = publicCert.encrypt('hello OpenPGP');
    expect(encrypted, contains('-----BEGIN PGP MESSAGE-----'));
    expect(cert.decrypt(encrypted), 'hello OpenPGP');

    publicCert.dispose();
    cert.dispose();
  });

  test('decrypt rejects a public-only certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());
    final encrypted = publicCert.encrypt('hello OpenPGP');

    expect(() => publicCert.decrypt(encrypted), throwsA(isA<PgpException>()));

    publicCert.dispose();
    cert.dispose();
  });

  test('sign and verify round-trip through a public certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

    final signed = cert.sign('hello signed OpenPGP');
    expect(signed, contains('-----BEGIN PGP MESSAGE-----'));
    expect(publicCert.verify(signed), 'hello signed OpenPGP');

    publicCert.dispose();
    cert.dispose();
  });

  test('verify rejects a different certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final other = pgp.generateKey('other@example.org');
    final signed = cert.sign('hello signed OpenPGP');

    expect(() => other.verify(signed), throwsA(isA<PgpException>()));

    other.dispose();
    cert.dispose();
  });

  test('verifyWithSigner reports the signing subkey fingerprint', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());
    final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);

    final signed = cert.sign('hello signed OpenPGP');
    final result = publicCert.verifyWithSigner(signed);

    expect(result.plaintext, 'hello signed OpenPGP');
    expect(result.signerFingerprint, signingSubkey.fingerprint);

    publicCert.dispose();
    cert.dispose();
  });

  test('verifyWithSigner reports the signature creation time', () {
    final cert = pgp.generateKey('someone@example.org');
    final signed = cert.sign('hello signed OpenPGP');
    final result = cert.verifyWithSigner(signed);

    expect(result.hasSignedAt, isTrue);
    expect(result.signedAtEpoch, greaterThan(0));
    expect(result.signedAtDate, isNotNull);

    cert.dispose();
  });

  test('revoke returns a revoked certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final revoked = cert.revoke();
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    cert.dispose();
  });

  test('revoke accepts a reason and message', () {
    final cert = pgp.generateKey('someone@example.org');
    final revoked = cert.revoke(
      reason: RevocationReason.keyCompromised,
      message: 'key compromised',
    );
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    cert.dispose();
  });

  test('revocationInfo reports not revoked for a fresh certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final info = cert.revocationInfo();
    expect(info.isRevoked, isFalse);
    expect(info.reasonCode, 0);
    expect(info.message, '');
    cert.dispose();
  });

  test('revocationInfo reports the reason and message after revoke', () {
    final cert = pgp.generateKey('someone@example.org');
    final revoked = cert.revoke(
      reason: RevocationReason.keyCompromised,
      message: 'key compromised',
    );
    final info = revoked.revocationInfo();
    expect(info.isRevoked, isTrue);
    expect(info.reasonCode, RevocationReason.keyCompromised.code);
    expect(info.message, 'key compromised');
    revoked.dispose();
    cert.dispose();
  });

  test(
      'generateRevocationArmored produces a certificate applicable via '
      'applyRevocationArmored', () {
    final cert = pgp.generateKey('someone@example.org');
    final armoredRevocation = cert.generateRevocationArmored(
      reason: RevocationReason.keyCompromised,
      message: 'lost the secret key',
    );
    expect(armoredRevocation, contains('BEGIN PGP SIGNATURE'));

    // Generating the certificate must not revoke the source certificate.
    expect(cert.revocationInfo().isRevoked, isFalse);

    final revoked = cert.applyRevocationArmored(armoredRevocation);
    final info = revoked.revocationInfo();
    expect(info.isRevoked, isTrue);
    expect(info.reasonCode, RevocationReason.keyCompromised.code);
    expect(info.message, 'lost the secret key');

    revoked.dispose();
    cert.dispose();
  });

  test('applyRevocationArmored throws for garbage input', () {
    final cert = pgp.generateKey('someone@example.org');
    expect(
      () => cert.applyRevocationArmored('not a signature'),
      throwsA(isA<PgpException>()),
    );
    cert.dispose();
  });

  group('designated revoker', () {
    test('revocationKeys is empty for a fresh certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      expect(cert.revocationKeys(), isEmpty);
      cert.dispose();
    });

    test('addDesignatedRevoker lists the revoker', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');

      final updated = alice.addDesignatedRevoker(bob);
      final keys = updated.revocationKeys();
      expect(keys, hasLength(1));
      expect(keys.first.fingerprint, bob.fingerprint());
      expect(keys.first.sensitive, isFalse);

      // The source certificate must be untouched.
      expect(alice.revocationKeys(), isEmpty);

      updated.dispose();
      bob.dispose();
      alice.dispose();
    });

    test(
        'generateRevocationArmoredFor + applyRevocationArmored + '
        'verifyDesignatedRevocation round trip', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final aliceWithRevoker = alice.addDesignatedRevoker(bob);

      final armored = bob.generateRevocationArmoredFor(
        aliceWithRevoker,
        reason: RevocationReason.keyCompromised,
        message: 'alice lost her key',
      );
      expect(armored, contains('BEGIN PGP SIGNATURE'));

      final revoked = aliceWithRevoker.applyRevocationArmored(armored);

      // A third-party revocation isn't reflected by revocationInfo until
      // it's cryptographically confirmed via verifyDesignatedRevocation.
      expect(revoked.revocationInfo().isRevoked, isFalse);
      expect(revoked.verifyDesignatedRevocation(bob), isTrue);

      revoked.dispose();
      aliceWithRevoker.dispose();
      bob.dispose();
      alice.dispose();
    });

    test('verifyDesignatedRevocation returns false for an undeclared revoker',
        () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');

      // Bob was never designated as a revoker for Alice.
      final armored = bob.generateRevocationArmoredFor(alice);
      final revoked = alice.applyRevocationArmored(armored);

      expect(revoked.verifyDesignatedRevocation(bob), isFalse);

      revoked.dispose();
      bob.dispose();
      alice.dispose();
    });
  });

  test('addSigningSubkey returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addSigningSubkey();
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('addTransportEncryptionSubkey returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addTransportEncryptionSubkey();
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('addAuthenticationSubkey returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addAuthenticationSubkey();
    expect(updated.pointer.address, isNonZero);
    expect(updated.subkeys().where((s) => s.canAuthenticate), hasLength(1));
    updated.dispose();
    cert.dispose();
  });

  test('revokeSubkey revokes the generated subkey', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.revokeSubkey(0);
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('revokeSubkey accepts a reason and message', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.revokeSubkey(
      0,
      reason: RevocationReason.keySuperseded,
      message: 'superseded by new subkey',
    );
    expect(updated.pointer.address, isNonZero);
    expect(updated.subkeys().first.isRevoked, isTrue);
    updated.dispose();
    cert.dispose();
  });

  group('subkey inspection', () {
    test('subkeys lists the encryption and signing subkeys', () {
      final cert = pgp.generateKey('someone@example.org');
      final subkeys = cert.subkeys();

      expect(subkeys, hasLength(2));
      expect(subkeys.map((s) => s.index), [0, 1]);
      expect(subkeys.every((s) => s.fingerprint.length == 40), isTrue);
      expect(subkeys.every((s) => !s.isRevoked), isTrue);
      expect(subkeys.where((s) => s.canEncrypt), hasLength(1));
      expect(subkeys.where((s) => s.canSign), hasLength(1));
      expect(subkeys.where((s) => s.canAuthenticate), isEmpty);

      cert.dispose();
    });

    test('subkeys agrees with revokeSubkey indexing', () {
      final cert = pgp.generateKey('someone@example.org');
      final encryptionSubkey = cert.subkeys().firstWhere((s) => s.canEncrypt);

      final revoked = cert.revokeSubkey(encryptionSubkey.index);
      final revokedInfo = revoked
          .subkeys()
          .firstWhere((s) => s.index == encryptionSubkey.index);
      expect(revokedInfo.isRevoked, isTrue);

      revoked.dispose();
      cert.dispose();
    });

    test('subkeys reflects a newly added signing subkey', () {
      final cert = pgp.generateKey('someone@example.org');
      final updated = cert.addSigningSubkey();

      final subkeys = updated.subkeys();
      expect(subkeys, hasLength(3));
      expect(subkeys.where((s) => s.canSign), hasLength(2));

      updated.dispose();
      cert.dispose();
    });
  });

  test('addUserId returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addUserId('other@example.org');
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('revokeUserId revokes an added user ID', () {
    final cert = pgp.generateKey('someone@example.org');
    final withUser = cert.addUserId('other@example.org');
    final revoked = withUser.revokeUserId('other@example.org');
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    withUser.dispose();
    cert.dispose();
  });

  test('revokeUserId accepts a reason and message', () {
    final cert = pgp.generateKey('someone@example.org');
    final withUser = cert.addUserId('other@example.org');
    final revoked = withUser.revokeUserId(
      'other@example.org',
      reason: RevocationReason.userIdRetired,
      message: 'address decommissioned',
    );
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    withUser.dispose();
    cert.dispose();
  });

  group('third-party certification', () {
    test('certifyUserId attaches a signature from another certificate', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      expect(certified.pointer.address, isNonZero);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('certifyUserId leaves the target certificate unmodified', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      alice.certifyUserId(bob, 'bob@example.org').dispose();
      expect(bob.pointer.address, isNonZero);
      alice.dispose();
      bob.dispose();
    });

    test('certifyUserId throws for a user ID not on the target', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      expect(
        () => alice.certifyUserId(bob, 'nobody@example.org'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      alice.dispose();
      bob.dispose();
    });

    test(
        'revokeUserIdCertification returns an updated certificate after '
        'certifyUserId', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      final revoked = alice.revokeUserIdCertification(
        certified,
        'bob@example.org',
        reason: RevocationReason.keyCompromised,
        message: 'signing key compromised',
      );
      expect(revoked.pointer.address, isNonZero);
      revoked.dispose();
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('revokeUserIdCertification leaves the target certificate unmodified',
        () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      alice.revokeUserIdCertification(certified, 'bob@example.org').dispose();
      expect(certified.pointer.address, isNonZero);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('revokeUserIdCertification throws for a user ID not on the target',
        () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      expect(
        () => alice.revokeUserIdCertification(bob, 'nobody@example.org'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      alice.dispose();
      bob.dispose();
    });

    test(
        'userIdCertifications reports the certifier as unrevoked after '
        'certifyUserId', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      final certifications = certified.userIdCertifications('bob@example.org');
      expect(certifications, hasLength(1));
      expect(certifications.first.fingerprint, alice.fingerprint());
      expect(certifications.first.isRevoked, isFalse);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test(
        'userIdCertifications reports the certifier as revoked after '
        'revokeUserIdCertification', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      final revoked =
          alice.revokeUserIdCertification(certified, 'bob@example.org');
      final certifications = revoked.userIdCertifications('bob@example.org');
      expect(certifications, hasLength(1));
      expect(certifications.first.fingerprint, alice.fingerprint());
      expect(certifications.first.isRevoked, isTrue);
      revoked.dispose();
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test(
        'certifyUserIdWithTrust records trust depth and amount in '
        'userIdCertifications', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserIdWithTrust(
        bob,
        'bob@example.org',
        trustDepth: 1,
        trustAmount: 120,
      );
      final certifications = certified.userIdCertifications('bob@example.org');
      expect(certifications, hasLength(1));
      expect(certifications.first.fingerprint, alice.fingerprint());
      expect(certifications.first.trustDepth, 1);
      expect(certifications.first.trustAmount, 120);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('certifyUserId (plain) records zero trust depth and amount', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      final certifications = certified.userIdCertifications('bob@example.org');
      expect(certifications.first.trustDepth, 0);
      expect(certifications.first.trustAmount, 0);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test(
        'certifyUserIdExportable(false) survives in memory but is dropped by '
        'exportPublicArmored', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserIdExportable(
        bob,
        'bob@example.org',
        exportable: false,
      );

      final certifications = certified.userIdCertifications('bob@example.org');
      expect(certifications, hasLength(1));
      expect(certifications.first.isExportable, isFalse);

      final reimported =
          pgp.certificateFromArmored(certified.exportPublicArmored());
      expect(reimported.userIdCertifications('bob@example.org'), isEmpty);

      reimported.dispose();
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('certifyUserIdExportable(true) survives exportPublicArmored', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserIdExportable(
        bob,
        'bob@example.org',
        exportable: true,
      );

      final reimported =
          pgp.certificateFromArmored(certified.exportPublicArmored());
      final certifications =
          reimported.userIdCertifications('bob@example.org');
      expect(certifications, hasLength(1));
      expect(certifications.first.isExportable, isTrue);

      reimported.dispose();
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('certifyUserId (plain) records exportable as true', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      final certifications = certified.userIdCertifications('bob@example.org');
      expect(certifications.first.isExportable, isTrue);
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('userIdCertifications is empty for an uncertified user ID', () {
      final cert = pgp.generateKey('someone@example.org');
      expect(cert.userIdCertifications('someone@example.org'), isEmpty);
      cert.dispose();
    });

    test('userIdCertifications throws for a user ID not on the certificate',
        () {
      final cert = pgp.generateKey('someone@example.org');
      expect(
        () => cert.userIdCertifications('nobody@example.org'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      cert.dispose();
    });

    test('verifyUserIdCertification confirms a genuine certification', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      expect(
        certified.verifyUserIdCertification(alice, 'bob@example.org'),
        isTrue,
      );
      certified.dispose();
      alice.dispose();
      bob.dispose();
    });

    test(
        'verifyUserIdCertification throws for an issuer that never '
        'certified', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final mallory = pgp.generateKey('mallory@example.org');
      final certified = alice.certifyUserId(bob, 'bob@example.org');
      expect(
        () => certified.verifyUserIdCertification(mallory, 'bob@example.org'),
        throwsA(isA<PgpException>()),
      );
      certified.dispose();
      alice.dispose();
      bob.dispose();
      mallory.dispose();
    });
  });

  group('merge', () {
    test('merge pulls in a new user ID added to a copy of the same cert', () {
      final cert = pgp.generateKey('merge-base@example.org');
      final withExtra = cert.addUserId('merge-extra@example.org');
      final merged = cert.merge(withExtra);
      expect(merged.userIds(), contains('merge-extra@example.org'));
      merged.dispose();
      withExtra.dispose();
      cert.dispose();
    });

    test('merge leaves both input certificates unmodified', () {
      final cert = pgp.generateKey('merge-unmodified@example.org');
      final withExtra = cert.addUserId('merge-unmodified-extra@example.org');
      cert.merge(withExtra).dispose();
      expect(cert.userIds(),
          isNot(contains('merge-unmodified-extra@example.org')));
      withExtra.dispose();
      cert.dispose();
    });

    test('merge throws for two unrelated certificates', () {
      final alice = pgp.generateKey('merge-alice@example.org');
      final bob = pgp.generateKey('merge-bob@example.org');
      expect(
        () => alice.merge(bob),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -3)),
      );
      alice.dispose();
      bob.dispose();
    });
  });

  group('user ID inspection', () {
    test('userIdsInfo reports the generated user ID as primary and unrevoked',
        () {
      final cert = pgp.generateKey('someone@example.org');
      final infos = cert.userIdsInfo();

      expect(infos, hasLength(1));
      expect(infos.single.userId, 'someone@example.org');
      expect(infos.single.isPrimary, isTrue);
      expect(infos.single.isRevoked, isFalse);
      expect(infos.single.hasExpiry, isFalse);

      cert.dispose();
    });

    test('userIdsInfo reports an added user ID as non-primary', () {
      final cert = pgp.generateKey('someone@example.org');
      final updated = cert.addUserId('other@example.org');
      final infos = updated.userIdsInfo();

      expect(infos, hasLength(2));
      final primary =
          infos.firstWhere((i) => i.userId == 'someone@example.org');
      final secondary =
          infos.firstWhere((i) => i.userId == 'other@example.org');
      expect(primary.isPrimary, isTrue);
      expect(secondary.isPrimary, isFalse);

      updated.dispose();
      cert.dispose();
    });

    test('userIdsInfo agrees with revokeUserId', () {
      final cert = pgp.generateKey('someone@example.org');
      final withUser = cert.addUserId('other@example.org');
      final revoked = withUser.revokeUserId('other@example.org');

      final infos = revoked.userIdsInfo();
      final revokedInfo =
          infos.firstWhere((i) => i.userId == 'other@example.org');
      expect(revokedInfo.isRevoked, isTrue);
      final primaryInfo =
          infos.firstWhere((i) => i.userId == 'someone@example.org');
      expect(primaryInfo.isRevoked, isFalse);

      revoked.dispose();
      withUser.dispose();
      cert.dispose();
    });

    test('setPrimaryUserId switches which user ID is primary', () {
      final cert = pgp.generateKey('someone@example.org');
      final withSecond = cert.addUserId('second@example.org');
      final updated = withSecond.setPrimaryUserId('second@example.org');

      final infos = updated.userIdsInfo();
      final primary =
          infos.firstWhere((i) => i.userId == 'someone@example.org');
      final secondary =
          infos.firstWhere((i) => i.userId == 'second@example.org');
      expect(primary.isPrimary, isFalse);
      expect(secondary.isPrimary, isTrue);

      // withSecond itself must be unaffected.
      final originalInfos = withSecond.userIdsInfo();
      expect(
          originalInfos
              .firstWhere((i) => i.userId == 'someone@example.org')
              .isPrimary,
          isTrue);

      updated.dispose();
      withSecond.dispose();
      cert.dispose();
    });

    test('setPrimaryUserId throws for a user ID not on the certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      expect(
        () => cert.setPrimaryUserId('nobody@example.org'),
        throwsA(isA<PgpException>()),
      );
      cert.dispose();
    });
  });

  group('key expiration', () {
    test('generateKeyWithExpiry returns a valid certificate handle', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(hours: 1));
      expect(cert.pointer.address, isNonZero);
      cert.dispose();
    });

    test('generateKeyWithExpiry with Duration.zero behaves like generateKey',
        () {
      final cert =
          pgp.generateKeyWithExpiry('alice@example.org', Duration.zero);
      final encrypted = cert.encrypt('hello');
      expect(encrypted, contains('-----BEGIN PGP MESSAGE-----'));
      cert.dispose();
    });

    test('generateKeyWithExpiry with null validity behaves like generateKey',
        () {
      final cert = pgp.generateKeyWithExpiry('alice@example.org', null);
      expect(cert.pointer.address, isNonZero);
      cert.dispose();
    });

    test('generateKeyWithExpiry expiry is readable via expiryEpoch', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(hours: 1));
      expect(cert.expiryEpoch(), greaterThan(0));
      cert.dispose();
    });

    test('setExpiry returns an updated certificate handle', () {
      final cert = pgp.generateKey('alice@example.org');
      final updated = cert.setExpiry(const Duration(hours: 2));
      expect(updated.pointer.address, isNonZero);
      updated.dispose();
      cert.dispose();
    });

    test('setExpiry with null clears the expiry', () {
      final cert = pgp.generateKey('alice@example.org');
      final withExpiry = cert.setExpiry(const Duration(hours: 2));
      final cleared = withExpiry.setExpiry(null);
      expect(cleared.expiryEpoch(), 0);
      cleared.dispose();
      withExpiry.dispose();
      cert.dispose();
    });

    test('key with far-future expiry can encrypt and decrypt', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(days: 365));
      final encrypted = cert.encrypt('expiring key test');
      expect(cert.decrypt(encrypted), 'expiring key test');
      cert.dispose();
    });

    test('subkeys report no expiry by default', () {
      final cert = pgp.generateKey('subkey-expiry@example.org');
      for (final subkey in cert.subkeys()) {
        expect(subkey.hasExpiry, isFalse);
        expect(subkey.expiryDate, isNull);
      }
      cert.dispose();
    });

    test('setSubkeyExpiry updates only the target subkey', () {
      final cert = pgp.generateKey('subkey-expiry@example.org');
      final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);
      final encryptionSubkey = cert.subkeys().firstWhere((s) => s.canEncrypt);

      final updated =
          cert.setSubkeyExpiry(signingSubkey.index, const Duration(hours: 2));

      final updatedSigning =
          updated.subkeys().firstWhere((s) => s.index == signingSubkey.index);
      final updatedEncryption = updated
          .subkeys()
          .firstWhere((s) => s.index == encryptionSubkey.index);

      expect(updatedSigning.hasExpiry, isTrue);
      expect(updatedEncryption.hasExpiry, isFalse);
      expect(updated.expiryEpoch(), 0); // primary key untouched

      updated.dispose();
      cert.dispose();
    });

    test('setSubkeyExpiry with null clears that subkey\'s expiry', () {
      final cert = pgp.generateKey('subkey-expiry@example.org');
      final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);

      final withExpiry =
          cert.setSubkeyExpiry(signingSubkey.index, const Duration(hours: 2));
      final cleared = withExpiry.setSubkeyExpiry(signingSubkey.index, null);

      final clearedSigning =
          cleared.subkeys().firstWhere((s) => s.index == signingSubkey.index);
      expect(clearedSigning.hasExpiry, isFalse);

      cleared.dispose();
      withExpiry.dispose();
      cert.dispose();
    });

    test('setSubkeyExpiry throws for an out-of-range index', () {
      final cert = pgp.generateKey('subkey-expiry@example.org');
      expect(
        () => cert.setSubkeyExpiry(99, const Duration(hours: 2)),
        throwsA(isA<PgpException>()),
      );
      cert.dispose();
    });
  });

  group('detached signatures', () {
    test('signDetached returns an armored signature block', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(sig, contains('-----BEGIN PGP SIGNATURE-----'));
      cert.dispose();
    });

    test('signDetached does not wrap content in a PGP Message', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(sig, isNot(contains('-----BEGIN PGP MESSAGE-----')));
      cert.dispose();
    });

    test('verifyDetached round-trips through a public certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      const plain = 'hello detached OpenPGP';
      final sig = cert.signDetached(plain);
      expect(pub.verifyDetached(plain, sig), isTrue);
      pub.dispose();
      cert.dispose();
    });

    test('verifyDetached rejects a different certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      final other = pgp.generateKey('other@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(
        () => other.verifyDetached('hello detached OpenPGP', sig),
        throwsA(isA<PgpException>()),
      );
      other.dispose();
      cert.dispose();
    });

    test('verifyDetached rejects tampered content', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(
        () => cert.verifyDetached('tampered content', sig),
        throwsA(isA<PgpException>()),
      );
      cert.dispose();
    });

    test('verifyDetachedSigner reports the signing subkey fingerprint', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);
      const plain = 'hello detached OpenPGP';
      final sig = cert.signDetached(plain);

      expect(pub.verifyDetachedSigner(plain, sig), signingSubkey.fingerprint);

      pub.dispose();
      cert.dispose();
    });
  });

  group('passphrase-protected keys', () {
    test('unlock with correct passphrase enables decrypt', () {
      final locked = pgp.generateLockedKey('locked@example.org', 'hunter2');
      final unlocked = locked.unlock('hunter2');
      final pub = pgp.certificateFromArmored(locked.exportPublicArmored());
      final cipher = pub.encrypt('secret message');
      expect(unlocked.decrypt(cipher), 'secret message');
      pub.dispose();
      unlocked.dispose();
      locked.dispose();
    });

    test('unlock with wrong passphrase throws PgpException(-2)', () {
      final locked =
          pgp.generateLockedKey('locked@example.org', 'correcthorse');
      expect(
        () => locked.unlock('wrongpassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -2)),
      );
      locked.dispose();
    });

    test('unlock on public-only cert throws PgpException(-4)', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      expect(
        () => pub.unlock('anypassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      pub.dispose();
      cert.dispose();
    });

    test('unlock then sign produces a verifiable message', () {
      final locked = pgp.generateLockedKey('signer@example.org', 's3cr3t');
      final unlocked = locked.unlock('s3cr3t');
      final pub = pgp.certificateFromArmored(locked.exportPublicArmored());
      final signed = unlocked.sign('authenticated text');
      expect(pub.verify(signed), 'authenticated text');
      pub.dispose();
      unlocked.dispose();
      locked.dispose();
    });

    test('unlock on already-unlocked cert is a no-op', () {
      final cert = pgp.generateKey('someone@example.org');
      final same = cert.unlock('');
      expect(same.pointer.address, isNonZero);
      same.dispose();
      cert.dispose();
    });

    test('lock then unlock round-trips with the same passphrase', () {
      final cert = pgp.generateKey('lockable@example.org');
      final locked = cert.lock('hunter2');
      final unlocked = locked.unlock('hunter2');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      final cipher = pub.encrypt('secret message');
      expect(unlocked.decrypt(cipher), 'secret message');
      pub.dispose();
      unlocked.dispose();
      locked.dispose();
      cert.dispose();
    });

    test('unlock after lock with wrong passphrase throws PgpException(-2)', () {
      final cert = pgp.generateKey('lockable@example.org');
      final locked = cert.lock('correcthorse');
      expect(
        () => locked.unlock('wrongpassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -2)),
      );
      locked.dispose();
      cert.dispose();
    });

    test('lock on public-only cert throws PgpException(-4)', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      expect(
        () => pub.lock('anypassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      pub.dispose();
      cert.dispose();
    });
  });

  group('certificate inspection', () {
    test('fingerprint is 40-character uppercase hex', () {
      final cert = pgp.generateKey('alice@example.org');
      final fp = cert.fingerprint();
      expect(fp.length, 40);
      expect(fp, matches(RegExp(r'^[0-9A-F]{40}$')));
      cert.dispose();
    });

    test('fingerprint is stable across export/import round-trip', () {
      final cert = pgp.generateKey('alice@example.org');
      final fp1 = cert.fingerprint();
      final parsed = pgp.certificateFromArmored(cert.exportPublicArmored());
      final fp2 = parsed.fingerprint();
      expect(fp1, fp2);
      parsed.dispose();
      cert.dispose();
    });

    test('userIds contains the user ID supplied at generation', () {
      final cert = pgp.generateKey('alice@example.org');
      expect(cert.userIds(), contains('alice@example.org'));
      cert.dispose();
    });

    test('userIds lists multiple user IDs after addUserId', () {
      final cert = pgp.generateKey('alice@example.org');
      final updated = cert.addUserId('alias@example.org');
      final ids = updated.userIds();
      expect(ids, contains('alice@example.org'));
      expect(ids, contains('alias@example.org'));
      updated.dispose();
      cert.dispose();
    });

    test('userIds still lists a revoked user ID', () {
      final cert = pgp.generateKey('alice@example.org');
      final withExtra = cert.addUserId('alias@example.org');
      final revoked = withExtra.revokeUserId('alias@example.org');
      expect(revoked.userIds(), contains('alias@example.org'));
      revoked.dispose();
      withExtra.dispose();
      cert.dispose();
    });

    test('expiryEpoch returns 0 for a certificate with no expiry', () {
      final cert = pgp.generateKey('alice@example.org');
      expect(cert.expiryEpoch(), 0);
      cert.dispose();
    });

    test('info() returns consistent CertificateInfo', () {
      final cert = pgp.generateKey('alice@example.org');
      final info = cert.info();
      expect(info.fingerprint, cert.fingerprint());
      expect(info.userIds, containsAll(cert.userIds()));
      expect(info.expiryEpoch, cert.expiryEpoch());
      expect(info.hasExpiry, isFalse);
      expect(info.expiryDate, isNull);
      cert.dispose();
    });
  });

  group('signed+encrypted messages', () {
    test('encryptAndSign round-trips through decryptAndVerify', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher = PGP.encryptAndSign(alice, [bobPub], 'hello signed+enc');
      expect(cipher, contains('-----BEGIN PGP MESSAGE-----'));

      final result = bob.decryptAndVerify(cipher, alicePub);
      expect(result.plaintext, 'hello signed+enc');
      expect(result.signerFingerprint.length, 40);
      expect(result.signerFingerprint, matches(RegExp(r'^[0-9A-F]{40}$')));
      expect(result.hasSignedAt, isTrue);

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('encryptAndSign to multiple recipients', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final carol = pgp.generateKey('carol@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());
      final carolPub = pgp.certificateFromArmored(carol.exportPublicArmored());

      final cipher =
          PGP.encryptAndSign(alice, [bobPub, carolPub], 'group message');
      final r1 = bob.decryptAndVerify(cipher, alicePub);
      final r2 = carol.decryptAndVerify(cipher, alicePub);
      expect(r1.plaintext, 'group message');
      expect(r2.plaintext, 'group message');
      expect(r1.signerFingerprint, r2.signerFingerprint);

      alicePub.dispose();
      bobPub.dispose();
      carolPub.dispose();
      alice.dispose();
      bob.dispose();
      carol.dispose();
    });

    test('decryptAndVerify throws when wrong verify cert is supplied', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final eve = pgp.generateKey('eve@example.org');
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());
      final evePub = pgp.certificateFromArmored(eve.exportPublicArmored());

      final cipher = PGP.encryptAndSign(alice, [bobPub], 'secret');
      expect(
        () => bob.decryptAndVerify(cipher, evePub),
        throwsA(isA<PgpException>()),
      );

      bobPub.dispose();
      evePub.dispose();
      alice.dispose();
      bob.dispose();
      eve.dispose();
    });

    test('encryptAndSign throws for empty recipient list', () {
      final alice = pgp.generateKey('alice@example.org');
      expect(
        () => PGP.encryptAndSign(alice, [], 'hello'),
        throwsA(isA<PgpException>()),
      );
      alice.dispose();
    });
  });

  group('file-based streaming operations', () {
    late Directory tmp;

    setUp(() {
      tmp = Directory.systemTemp.createTempSync('pgp_dart_test_');
    });

    tearDown(() {
      tmp.deleteSync(recursive: true);
    });

    test('encryptFile/decryptFile round-trip', () {
      final cert = pgp.generateKey('file-alice@example.org');
      final inputFile = File('${tmp.path}/plain.txt')
        ..writeAsStringSync('streamed straight from disk');
      final encryptedFile = File('${tmp.path}/cipher.asc');
      final decryptedFile = File('${tmp.path}/plain.out');

      cert.encryptFile(inputFile.path, encryptedFile.path);
      expect(encryptedFile.existsSync(), isTrue);
      expect(
        encryptedFile.readAsStringSync(),
        contains('-----BEGIN PGP MESSAGE-----'),
      );

      cert.decryptFile(encryptedFile.path, decryptedFile.path);
      expect(decryptedFile.readAsStringSync(), 'streamed straight from disk');

      cert.dispose();
    });

    test('decryptFile throws for a nonexistent input file', () {
      final cert = pgp.generateKey('file-missing@example.org');
      expect(
        () => cert.decryptFile(
          '${tmp.path}/does-not-exist.asc',
          '${tmp.path}/out.txt',
        ),
        throwsA(isA<PgpException>()),
      );
      cert.dispose();
    });

    test('encryptAndSignFile round-trips through decryptAndVerifyFile', () {
      final alice = pgp.generateKey('file-signer@example.org');
      final bob = pgp.generateKey('file-recipient@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final inputFile = File('${tmp.path}/sign-plain.txt')
        ..writeAsStringSync('large signed payload streamed');
      final encryptedFile = File('${tmp.path}/sign-cipher.asc');
      final decryptedFile = File('${tmp.path}/sign-plain.out');

      PGP.encryptAndSignFile(
        alice,
        [bobPub],
        inputFile.path,
        encryptedFile.path,
      );

      final result = bob.decryptAndVerifyFile(
        encryptedFile.path,
        decryptedFile.path,
        alicePub,
      );
      expect(decryptedFile.readAsStringSync(), 'large signed payload streamed');
      expect(result.signerFingerprint.length, 40);
      expect(result.hasSignedAt, isTrue);

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('encryptAndSignFile throws for empty recipient list', () {
      final alice = pgp.generateKey('file-empty@example.org');
      expect(
        () => PGP.encryptAndSignFile(
          alice,
          [],
          '${tmp.path}/in.txt',
          '${tmp.path}/out.asc',
        ),
        throwsA(isA<PgpException>()),
      );
      alice.dispose();
    });
  });

  group('binary data (bytes API)', () {
    test('encryptBytes and decryptBytes round-trip arbitrary bytes', () {
      final cert = pgp.generateKey('bytes@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());

      final original = Uint8List.fromList([0, 1, 2, 255, 254, 128, 0, 42]);
      final cipher = pub.encryptBytes(original);
      expect(cipher, contains('-----BEGIN PGP MESSAGE-----'));

      final recovered = cert.decryptBytes(cipher);
      expect(recovered, original);

      pub.dispose();
      cert.dispose();
    });

    test('encryptBytes handles zero-length data', () {
      final cert = pgp.generateKey('empty@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());

      final cipher = pub.encryptBytes(Uint8List(0));
      final recovered = cert.decryptBytes(cipher);
      expect(recovered, isEmpty);

      pub.dispose();
      cert.dispose();
    });

    test('signBytes and verifyBytes round-trip binary content', () {
      final cert = pgp.generateKey('bsign@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());

      final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      final signed = cert.signBytes(data);
      final verified = pub.verifyBytes(signed);
      expect(verified, data);

      pub.dispose();
      cert.dispose();
    });

    test('verifyBytesWithSigner reports the signing subkey fingerprint', () {
      final cert = pgp.generateKey('bsign-signer@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);

      final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      final signed = cert.signBytes(data);
      final result = pub.verifyBytesWithSigner(signed);

      expect(result.plaintext, data);
      expect(result.signerFingerprint, signingSubkey.fingerprint);

      pub.dispose();
      cert.dispose();
    });

    test('verifyBytes rejects a wrong certificate', () {
      final cert = pgp.generateKey('btamper@example.org');
      final other = pgp.generateKey('btamper2@example.org');
      final otherPub = pgp.certificateFromArmored(other.exportPublicArmored());

      final signed = cert.signBytes(Uint8List.fromList([1, 2, 3]));
      expect(
        () => otherPub.verifyBytes(signed),
        throwsA(isA<PgpException>()),
      );

      otherPub.dispose();
      other.dispose();
      cert.dispose();
    });

    test('encryptBytesToRecipients multi-recipient round-trips', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final data = Uint8List.fromList([10, 20, 30, 40, 50]);
      final cipher = PGP.encryptBytesToRecipients([alicePub, bobPub], data);
      expect(alice.decryptBytes(cipher), data);
      expect(bob.decryptBytes(cipher), data);

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });
  });

  group('cleartext signatures', () {
    test('signCleartext produces a SIGNED MESSAGE block', () {
      final cert = pgp.generateKey('cleartext@example.org');
      const plain = 'hello cleartext world';
      final signed = cert.signCleartext(plain);
      expect(signed, contains('-----BEGIN PGP SIGNED MESSAGE-----'));
      expect(signed, contains('-----BEGIN PGP SIGNATURE-----'));
      cert.dispose();
    });

    test('signCleartext embeds the plaintext visibly', () {
      final cert = pgp.generateKey('cleartext@example.org');
      const plain = 'readable content for humans';
      final signed = cert.signCleartext(plain);
      expect(signed, contains(plain));
      cert.dispose();
    });

    test('verifyCleartext round-trips through a public certificate', () {
      final cert = pgp.generateKey('cleartext@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      const plain = 'hello cleartext round-trip';
      final signed = cert.signCleartext(plain);
      expect(pub.verifyCleartext(signed), plain);
      pub.dispose();
      cert.dispose();
    });

    test('verifyCleartextWithSigner reports the signing subkey fingerprint',
        () {
      final cert = pgp.generateKey('cleartext-signer@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());
      final signingSubkey = cert.subkeys().firstWhere((s) => s.canSign);
      const plain = 'hello cleartext round-trip';
      final signed = cert.signCleartext(plain);

      final result = pub.verifyCleartextWithSigner(signed);

      expect(result.plaintext, plain);
      expect(result.signerFingerprint, signingSubkey.fingerprint);

      pub.dispose();
      cert.dispose();
    });

    test('verifyCleartext rejects a different certificate', () {
      final cert = pgp.generateKey('cleartext@example.org');
      final other = pgp.generateKey('other@example.org');
      final signed = cert.signCleartext('hello');
      expect(
        () => other.verifyCleartext(signed),
        throwsA(isA<PgpException>()),
      );
      other.dispose();
      cert.dispose();
    });

    test('cleartext message is not a PGP MESSAGE block', () {
      final cert = pgp.generateKey('cleartext@example.org');
      final signed = cert.signCleartext('test');
      expect(signed, isNot(contains('-----BEGIN PGP MESSAGE-----')));
      cert.dispose();
    });
  });

  group('symmetric encryption', () {
    test('encryptSymmetric produces an armored message', () {
      final cipher = PGP.encryptSymmetric('hello symmetric', 'passphrase1');
      expect(cipher, contains('-----BEGIN PGP MESSAGE-----'));
    });

    test('encryptSymmetric and decryptSymmetric round-trip', () {
      const plain = 'secret backup data';
      const pass = 'correct horse battery staple';
      final cipher = PGP.encryptSymmetric(plain, pass);
      expect(PGP.decryptSymmetric(cipher, pass), plain);
    });

    test('decryptSymmetric rejects wrong passphrase', () {
      final cipher = PGP.encryptSymmetric('sensitive', 'rightpass');
      expect(
        () => PGP.decryptSymmetric(cipher, 'wrongpass'),
        throwsA(isA<PgpException>()),
      );
    });

    test('encryptSymmetric output is different each time (random session key)',
        () {
      const plain = 'same message';
      const pass = 'same pass';
      final c1 = PGP.encryptSymmetric(plain, pass);
      final c2 = PGP.encryptSymmetric(plain, pass);
      expect(c1, isNot(equals(c2)));
    });

    test('symmetric ciphertext cannot be decrypted without passphrase', () {
      final cert = pgp.generateKey('somebody@example.org');
      final cipher = PGP.encryptSymmetric('top secret', 'mypassword');
      expect(() => cert.decrypt(cipher), throwsA(isA<PgpException>()));
      cert.dispose();
    });

    test(
        'encryptAndSignSymmetric and decryptAndVerifySymmetric round-trip',
        () {
      final signer = pgp.generateKey('symmetric-signer@example.org');
      const plain = 'sign+symmetric secret';
      const pass = 'correct horse battery staple';

      final signingSubkey = signer.subkeys().firstWhere((s) => s.canSign);

      final cipher = signer.encryptAndSignSymmetric(plain, pass);
      final result = signer.decryptAndVerifySymmetric(cipher, pass);
      expect(result.plaintext, plain);
      expect(result.signerFingerprint, signingSubkey.fingerprint);

      signer.dispose();
    });

    test('decryptAndVerifySymmetric rejects wrong passphrase', () {
      final signer = pgp.generateKey('symmetric-signer-wrong@example.org');
      final cipher =
          signer.encryptAndSignSymmetric('payload', 'rightpass');
      expect(
        () => signer.decryptAndVerifySymmetric(cipher, 'wrongpass'),
        throwsA(isA<PgpException>()),
      );
      signer.dispose();
    });
  });

  group('messageRecipientKeyIds', () {
    test('reports the transport-encryption subkey key ID', () {
      final cert = pgp.generateKey('recipient-key-ids@example.org');
      final cipher = cert.encrypt('hello');
      final encryptionSubkey =
          cert.subkeys().firstWhere((s) => s.canEncrypt);
      final expectedKeyId =
          encryptionSubkey.fingerprint.substring(24); // last 16 hex chars

      final keyIds = PGP.messageRecipientKeyIds(cipher);
      expect(keyIds, [expectedKeyId]);

      cert.dispose();
    });

    test('reports one key ID per recipient', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher = PGP.encryptToRecipients([alicePub, bobPub], 'hello both');
      final keyIds = PGP.messageRecipientKeyIds(cipher);
      expect(keyIds, hasLength(2));

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('throws for invalid input', () {
      expect(
        () => PGP.messageRecipientKeyIds('not a message'),
        throwsA(isA<PgpException>()),
      );
    });
  });

  group('sessionKey / decryptWithSessionKey', () {
    test('recovers a session key and decrypts with it', () {
      final cert = pgp.generateKey('session-key@example.org');
      final cipher = cert.encrypt('session key test payload');

      final sessionKey = cert.sessionKey(cipher);
      expect(sessionKey.hex, isNotEmpty);
      expect(sessionKey.algo, isNonZero);

      final plaintext = PGP.decryptWithSessionKey(sessionKey, cipher);
      expect(plaintext, 'session key test payload');

      cert.dispose();
    });

    test('sessionKey throws when using the wrong certificate', () {
      final cert = pgp.generateKey('session-key-wrong@example.org');
      final other = pgp.generateKey('session-key-other@example.org');
      final cipher = cert.encrypt('payload');

      expect(
        () => other.sessionKey(cipher),
        throwsA(isA<PgpException>()),
      );

      cert.dispose();
      other.dispose();
    });

    test('decryptWithSessionKey throws for a bogus session key', () {
      final cert = pgp.generateKey('session-key-bogus@example.org');
      final cipher = cert.encrypt('payload');
      final sessionKey = cert.sessionKey(cipher);
      final bogus = SessionKeyInfo(
        hex: List.filled(sessionKey.hex.length ~/ 2, '00').join(),
        algo: sessionKey.algo,
      );

      expect(
        () => PGP.decryptWithSessionKey(bogus, cipher),
        throwsA(isA<PgpException>()),
      );

      cert.dispose();
    });
  });

  group('encryptToRecipients', () {
    test('encrypts to two recipients, each can decrypt', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher = PGP.encryptToRecipients([alicePub, bobPub], 'hello both');
      expect(cipher, contains('-----BEGIN PGP MESSAGE-----'));
      expect(alice.decrypt(cipher), 'hello both');
      expect(bob.decrypt(cipher), 'hello both');

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('sender-can-read pattern', () {
      final sender = pgp.generateKey('sender@example.org');
      final receiver = pgp.generateKey('receiver@example.org');
      final senderPub =
          pgp.certificateFromArmored(sender.exportPublicArmored());
      final receiverPub =
          pgp.certificateFromArmored(receiver.exportPublicArmored());

      final cipher =
          PGP.encryptToRecipients([senderPub, receiverPub], 'sent mail');
      expect(sender.decrypt(cipher), 'sent mail');
      expect(receiver.decrypt(cipher), 'sent mail');

      senderPub.dispose();
      receiverPub.dispose();
      sender.dispose();
      receiver.dispose();
    });

    test('single recipient matches encrypt()', () {
      final cert = pgp.generateKey('solo@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());

      final viaMulti = PGP.encryptToRecipients([pub], 'solo message');
      expect(cert.decrypt(viaMulti), 'solo message');

      pub.dispose();
      cert.dispose();
    });

    test('throws PgpException for empty recipient list', () {
      expect(
        () => PGP.encryptToRecipients([], 'hello'),
        throwsA(isA<PgpException>()),
      );
    });

    test('non-recipient cannot decrypt', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final eve = pgp.generateKey('eve@example.org');
      final alicePub = pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher = PGP.encryptToRecipients([alicePub, bobPub], 'secret');
      expect(() => eve.decrypt(cipher), throwsA(isA<PgpException>()));

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
      eve.dispose();
    });
  });

  group('algorithm preferences', () {
    test('setPreferences round-trips through preferences()', () {
      final cert = pgp.generateKey('preferences@example.org');

      final updated = cert.setPreferences(
        symmetricAlgorithms: [
          SymmetricAlgorithmPreference.aes256.code,
          SymmetricAlgorithmPreference.aes128.code,
        ],
        hashAlgorithms: [
          HashAlgorithmPreference.sha256.code,
          HashAlgorithmPreference.sha1.code,
        ],
        compressionAlgorithms: [CompressionAlgorithmPreference.zlib.code],
        features: 1,
      );

      final prefs = updated.preferences();
      expect(prefs.symmetricAlgorithms, [9, 7]);
      expect(prefs.hashAlgorithms, [8, 2]);
      expect(prefs.compressionAlgorithms, [2]);
      expect(prefs.features, 1);

      cert.dispose();
      updated.dispose();
    });

    test('setPreferences leaves the receiver unchanged', () {
      final cert = pgp.generateKey('preferences-unchanged@example.org');
      final before = cert.preferences();

      final updated = cert.setPreferences(
        symmetricAlgorithms: [SymmetricAlgorithmPreference.aes256.code],
      );

      final after = cert.preferences();
      expect(after.symmetricAlgorithms, before.symmetricAlgorithms);
      expect(after.hashAlgorithms, before.hashAlgorithms);
      expect(after.compressionAlgorithms, before.compressionAlgorithms);
      expect(after.features, before.features);

      cert.dispose();
      updated.dispose();
    });

    test('setPreferences allows clearing to empty lists', () {
      final cert = pgp.generateKey('preferences-empty@example.org');

      final updated = cert.setPreferences();
      final prefs = updated.preferences();
      expect(prefs.symmetricAlgorithms, isEmpty);
      expect(prefs.hashAlgorithms, isEmpty);
      expect(prefs.compressionAlgorithms, isEmpty);
      expect(prefs.features, 0);

      cert.dispose();
      updated.dispose();
    });
  });
}
