#include "pgp-ffi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  struct Certificate *cert = NULL;
  int32_t rc = pgp_key_generate("someone@example.org", &cert);
  if (rc != 0 || cert == NULL) {
    fprintf(stderr, "pgp_key_generate failed: rc=%" PRId32 "\n", rc);
    return 1;
  }

  struct Certificate *updated = NULL;
  rc = pgp_certificate_add_userid(cert, "other@example.org", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_add_userid failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  struct Certificate *alice = NULL;
  rc = pgp_key_generate("alice@example.org", &alice);
  if (rc != 0 || alice == NULL) {
    fprintf(stderr, "pgp_key_generate (alice) failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    return 1;
  }

  updated = NULL;
  rc = pgp_certificate_certify_userid(alice, cert, "other@example.org",
                                       &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_certify_userid failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  char *alice_fp = NULL;
  rc = pgp_certificate_fingerprint(alice, &alice_fp);
  if (rc != 0 || alice_fp == NULL) {
    fprintf(stderr, "pgp_certificate_fingerprint (alice) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }

  char *certifications = NULL;
  rc = pgp_certificate_userid_certifications(cert, "other@example.org",
                                              &certifications);
  if (rc != 0 || certifications == NULL) {
    fprintf(stderr,
            "pgp_certificate_userid_certifications failed: rc=%" PRId32 "\n",
            rc);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  if (strstr(certifications, alice_fp) == NULL ||
      strstr(certifications, "\t0") == NULL) {
    fprintf(stderr,
            "pgp_certificate_userid_certifications did not report alice as "
            "an unrevoked certifier: %s\n",
            certifications);
    free(certifications);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  free(certifications);

  uint8_t certification_verified = 0;
  rc = pgp_certificate_verify_userid_certification(
      cert, alice, "other@example.org", &certification_verified);
  if (rc != 0 || certification_verified != 1) {
    fprintf(stderr,
            "pgp_certificate_verify_userid_certification failed: rc=%" PRId32
            " verified=%u\n",
            rc, certification_verified);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }

  updated = NULL;
  rc = pgp_certificate_revoke_userid_certification(
      alice, cert, "other@example.org", 2, "signing key compromised",
      &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr,
            "pgp_certificate_revoke_userid_certification failed: rc=%" PRId32
            "\n",
            rc);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  certifications = NULL;
  rc = pgp_certificate_userid_certifications(cert, "other@example.org",
                                              &certifications);
  if (rc != 0 || certifications == NULL) {
    fprintf(stderr,
            "pgp_certificate_userid_certifications (post-revoke) failed: "
            "rc=%" PRId32 "\n",
            rc);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  if (strstr(certifications, alice_fp) == NULL ||
      strstr(certifications, "\t1") == NULL) {
    fprintf(stderr,
            "pgp_certificate_userid_certifications did not report alice's "
            "certification as revoked: %s\n",
            certifications);
    free(certifications);
    free(alice_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(alice);
    return 1;
  }
  free(certifications);
  free(alice_fp);
  pgp_certificate_free(alice);

  struct Certificate *introducer = NULL;
  rc = pgp_key_generate("introducer@example.org", &introducer);
  if (rc != 0 || introducer == NULL) {
    fprintf(stderr, "pgp_key_generate (introducer) failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  struct Certificate *trust_certified = NULL;
  rc = pgp_certificate_certify_userid_with_trust(
      introducer, cert, "other@example.org", 1, 120, &trust_certified);
  if (rc != 0 || trust_certified == NULL) {
    fprintf(stderr,
            "pgp_certificate_certify_userid_with_trust failed: rc=%" PRId32
            "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(introducer);
    return 1;
  }

  char *trust_certifications = NULL;
  rc = pgp_certificate_userid_certifications(trust_certified, "other@example.org",
                                              &trust_certifications);
  if (rc != 0 || trust_certifications == NULL ||
      strstr(trust_certifications, "\t1\t120") == NULL) {
    fprintf(stderr,
            "pgp_certificate_certify_userid_with_trust did not record the "
            "trust signature: rc=%" PRId32 " listing=%s\n",
            rc, trust_certifications ? trust_certifications : "(null)");
    free(trust_certifications);
    pgp_certificate_free(cert);
    pgp_certificate_free(introducer);
    pgp_certificate_free(trust_certified);
    return 1;
  }
  free(trust_certifications);
  pgp_certificate_free(introducer);
  pgp_certificate_free(trust_certified);

  struct Certificate *local_certifier = NULL;
  rc = pgp_key_generate("local-certifier@example.org", &local_certifier);
  if (rc != 0 || local_certifier == NULL) {
    fprintf(stderr, "pgp_key_generate (local_certifier) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  char *local_certifier_fp = NULL;
  rc = pgp_certificate_fingerprint(local_certifier, &local_certifier_fp);
  if (rc != 0 || local_certifier_fp == NULL) {
    fprintf(stderr, "pgp_certificate_fingerprint (local_certifier) failed: "
                     "rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    return 1;
  }

  struct Certificate *locally_certified = NULL;
  rc = pgp_certificate_certify_userid_exportable(
      local_certifier, cert, "other@example.org", 0, &locally_certified);
  if (rc != 0 || locally_certified == NULL) {
    fprintf(stderr,
            "pgp_certificate_certify_userid_exportable failed: rc=%" PRId32
            "\n",
            rc);
    free(local_certifier_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    return 1;
  }

  char *local_certifications = NULL;
  rc = pgp_certificate_userid_certifications(
      locally_certified, "other@example.org", &local_certifications);
  char *local_certifier_line =
      local_certifications != NULL
          ? strstr(local_certifications, local_certifier_fp)
          : NULL;
  if (rc != 0 || local_certifications == NULL || local_certifier_line == NULL ||
      strncmp(local_certifier_line + strlen(local_certifier_fp), "\t0\t0\t0\t0",
               8) != 0) {
    fprintf(stderr,
            "pgp_certificate_certify_userid_exportable did not record a "
            "non-exportable certification: rc=%" PRId32 " listing=%s\n",
            rc, local_certifications ? local_certifications : "(null)");
    free(local_certifications);
    free(local_certifier_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    pgp_certificate_free(locally_certified);
    return 1;
  }
  free(local_certifications);
  free(local_certifier_fp);

  char *local_export = NULL;
  rc = pgp_certificate_export_public_armored(locally_certified, &local_export);
  if (rc != 0 || local_export == NULL) {
    fprintf(stderr,
            "pgp_certificate_export_public_armored (local cert) failed: "
            "rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    pgp_certificate_free(locally_certified);
    return 1;
  }

  struct Certificate *reimported_local = NULL;
  rc = pgp_certificate_from_armored(local_export, &reimported_local);
  free(local_export);
  if (rc != 0 || reimported_local == NULL) {
    fprintf(stderr,
            "pgp_certificate_from_armored (local cert re-export) failed: "
            "rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    pgp_certificate_free(locally_certified);
    return 1;
  }

  char *local_certifier_fp_again = NULL;
  rc = pgp_certificate_fingerprint(local_certifier, &local_certifier_fp_again);
  if (rc != 0 || local_certifier_fp_again == NULL) {
    fprintf(stderr, "pgp_certificate_fingerprint (local_certifier, 2nd) "
                     "failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    pgp_certificate_free(locally_certified);
    pgp_certificate_free(reimported_local);
    return 1;
  }

  char *reimported_certifications = NULL;
  rc = pgp_certificate_userid_certifications(
      reimported_local, "other@example.org", &reimported_certifications);
  if (rc != 0 || reimported_certifications == NULL ||
      strstr(reimported_certifications, local_certifier_fp_again) != NULL) {
    fprintf(stderr,
            "pgp_certificate_export_public_armored did not drop the "
            "non-exportable certification: rc=%" PRId32 " listing=%s\n",
            rc, reimported_certifications ? reimported_certifications : "(null)");
    free(reimported_certifications);
    free(local_certifier_fp_again);
    pgp_certificate_free(cert);
    pgp_certificate_free(local_certifier);
    pgp_certificate_free(locally_certified);
    pgp_certificate_free(reimported_local);
    return 1;
  }
  free(reimported_certifications);
  free(local_certifier_fp_again);
  pgp_certificate_free(local_certifier);
  pgp_certificate_free(locally_certified);
  pgp_certificate_free(reimported_local);

  struct Certificate *with_new_uid = NULL;
  rc = pgp_certificate_add_userid(cert, "merged@example.org", &with_new_uid);
  if (rc != 0 || with_new_uid == NULL) {
    fprintf(stderr, "pgp_certificate_add_userid (merge prep) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  struct Certificate *merged = NULL;
  rc = pgp_certificate_merge(cert, with_new_uid, &merged);
  if (rc != 0 || merged == NULL) {
    fprintf(stderr, "pgp_certificate_merge failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(with_new_uid);
    return 1;
  }
  pgp_certificate_free(with_new_uid);

  char *merged_userids = NULL;
  rc = pgp_certificate_userids(merged, &merged_userids);
  if (rc != 0 || merged_userids == NULL ||
      strstr(merged_userids, "merged@example.org") == NULL) {
    fprintf(stderr,
            "pgp_certificate_merge did not pull in the new user ID: %s\n",
            merged_userids ? merged_userids : "(null)");
    if (merged_userids != NULL) free(merged_userids);
    pgp_certificate_free(cert);
    pgp_certificate_free(merged);
    return 1;
  }
  free(merged_userids);
  pgp_certificate_free(merged);

  updated = NULL;
  rc = pgp_certificate_set_primary_userid(cert, "other@example.org", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_set_primary_userid failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  char *primary_info = NULL;
  rc = pgp_certificate_userids_info(updated, &primary_info);
  if (rc != 0 || primary_info == NULL ||
      strstr(primary_info, "someone@example.org\t0\t0\t") == NULL ||
      strstr(primary_info, "other@example.org\t0\t1\t") == NULL) {
    fprintf(stderr,
            "pgp_certificate_set_primary_userid did not switch the primary "
            "user ID: %s\n",
            primary_info ? primary_info : "(null)");
    if (primary_info != NULL) free(primary_info);
    pgp_certificate_free(cert);
    pgp_certificate_free(updated);
    return 1;
  }
  free(primary_info);
  pgp_certificate_free(updated);

  updated = NULL;
  rc = pgp_certificate_add_transport_encryption_subkey(cert, &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr,
            "pgp_certificate_add_transport_encryption_subkey failed: rc=%" PRId32
            "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  updated = NULL;
  rc = pgp_certificate_add_authentication_subkey(cert, &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr,
            "pgp_certificate_add_authentication_subkey failed: rc=%" PRId32
            "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  char *subkeys = NULL;
  rc = pgp_certificate_subkeys(cert, &subkeys);
  if (rc != 0 || subkeys == NULL) {
    fprintf(stderr, "pgp_certificate_subkeys failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    return 1;
  }
  if (strstr(subkeys, "authentication") == NULL) {
    fprintf(stderr,
            "pgp_certificate_subkeys did not report an authentication "
            "subkey: %s\n",
            subkeys);
    free(subkeys);
    pgp_certificate_free(cert);
    return 1;
  }
  free(subkeys);

  updated = NULL;
  rc = pgp_certificate_revoke_userid(cert, "other@example.org", 32,
                                      "address decommissioned", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_revoke_userid failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  char *userids_info = NULL;
  rc = pgp_certificate_userids_info(cert, &userids_info);
  if (rc != 0 || userids_info == NULL) {
    fprintf(stderr, "pgp_certificate_userids_info failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  if (strstr(userids_info, "other@example.org\t1\t") == NULL) {
    fprintf(stderr,
            "pgp_certificate_userids_info did not report other@example.org "
            "as revoked: %s\n",
            userids_info);
    free(userids_info);
    pgp_certificate_free(cert);
    return 1;
  }
  free(userids_info);

  updated = NULL;
  rc = pgp_certificate_revoke_subkey(cert, 1, 3, "no longer used", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_revoke_subkey failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  updated = NULL;
  rc = pgp_certificate_revoke(cert, 2, "key compromised", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_revoke failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  uint8_t revoked_flag = 0;
  uint8_t revoked_reason = 0;
  char *revoked_message = NULL;
  rc = pgp_certificate_revocation_info(cert, &revoked_flag, &revoked_reason,
                                        &revoked_message);
  if (rc != 0 || revoked_flag != 1 || revoked_reason != 2 ||
      revoked_message == NULL || strcmp(revoked_message, "key compromised") != 0) {
    fprintf(stderr,
            "pgp_certificate_revocation_info failed: rc=%" PRId32
            " revoked=%u reason=%u message=%s\n",
            rc, revoked_flag, revoked_reason,
            revoked_message ? revoked_message : "(null)");
    free(revoked_message);
    pgp_certificate_free(cert);
    return 1;
  }
  free(revoked_message);

  struct Certificate *locked = NULL;
  rc = pgp_certificate_lock(cert, "correct horse battery staple", &locked);
  if (rc != 0 || locked == NULL) {
    fprintf(stderr, "pgp_certificate_lock failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    return 1;
  }

  struct Certificate *unlocked = NULL;
  rc = pgp_certificate_unlock(locked, "correct horse battery staple",
                               &unlocked);
  if (rc != 0 || unlocked == NULL) {
    fprintf(stderr, "pgp_certificate_unlock failed: rc=%" PRId32 "\n", rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(locked);
    return 1;
  }
  pgp_certificate_free(locked);
  pgp_certificate_free(unlocked);

  struct Certificate *revocable = NULL;
  rc = pgp_key_generate("revocable@example.org", &revocable);
  if (rc != 0 || revocable == NULL) {
    fprintf(stderr, "pgp_key_generate (revocable) failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  char *standalone_revocation = NULL;
  rc = pgp_certificate_generate_revocation_armored(
      revocable, 2, "key compromised", &standalone_revocation);
  if (rc != 0 || standalone_revocation == NULL) {
    fprintf(stderr,
            "pgp_certificate_generate_revocation_armored failed: rc=%" PRId32
            "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(revocable);
    return 1;
  }

  struct Certificate *revoked_via_standalone = NULL;
  rc = pgp_certificate_apply_revocation_armored(
      revocable, standalone_revocation, &revoked_via_standalone);
  if (rc != 0 || revoked_via_standalone == NULL) {
    fprintf(stderr,
            "pgp_certificate_apply_revocation_armored failed: rc=%" PRId32
            "\n",
            rc);
    free(standalone_revocation);
    pgp_certificate_free(cert);
    pgp_certificate_free(revocable);
    return 1;
  }
  free(standalone_revocation);

  uint8_t standalone_revoked_flag = 0;
  uint8_t standalone_reason = 0;
  char *standalone_message = NULL;
  rc = pgp_certificate_revocation_info(revoked_via_standalone,
                                        &standalone_revoked_flag,
                                        &standalone_reason,
                                        &standalone_message);
  if (rc != 0 || standalone_revoked_flag != 1 || standalone_reason != 2) {
    fprintf(stderr,
            "pgp_certificate_apply_revocation_armored did not apply the "
            "standalone revocation: rc=%" PRId32 " revoked=%u reason=%u\n",
            rc, standalone_revoked_flag, standalone_reason);
    free(standalone_message);
    pgp_certificate_free(cert);
    pgp_certificate_free(revocable);
    pgp_certificate_free(revoked_via_standalone);
    return 1;
  }
  free(standalone_message);
  pgp_certificate_free(revocable);
  pgp_certificate_free(revoked_via_standalone);

  struct Certificate *revoker_alice = NULL;
  rc = pgp_key_generate("revoker-alice@example.org", &revoker_alice);
  if (rc != 0 || revoker_alice == NULL) {
    fprintf(stderr, "pgp_key_generate (revoker_alice) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  struct Certificate *revoker_bob = NULL;
  rc = pgp_key_generate("revoker-bob@example.org", &revoker_bob);
  if (rc != 0 || revoker_bob == NULL) {
    fprintf(stderr, "pgp_key_generate (revoker_bob) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    return 1;
  }

  struct Certificate *alice_with_revoker = NULL;
  rc = pgp_certificate_add_designated_revoker(revoker_alice, revoker_bob,
                                               &alice_with_revoker);
  if (rc != 0 || alice_with_revoker == NULL) {
    fprintf(stderr,
            "pgp_certificate_add_designated_revoker failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    pgp_certificate_free(revoker_bob);
    return 1;
  }

  char *revocation_keys = NULL;
  rc = pgp_certificate_revocation_keys(alice_with_revoker, &revocation_keys);
  if (rc != 0 || revocation_keys == NULL || strstr(revocation_keys, "\t0") == NULL) {
    fprintf(stderr,
            "pgp_certificate_revocation_keys failed: rc=%" PRId32
            " keys=%s\n",
            rc, revocation_keys ? revocation_keys : "(null)");
    free(revocation_keys);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    pgp_certificate_free(revoker_bob);
    pgp_certificate_free(alice_with_revoker);
    return 1;
  }
  free(revocation_keys);

  char *revoker_armored = NULL;
  rc = pgp_certificate_generate_revocation_armored_by(
      revoker_bob, alice_with_revoker, 2, "alice lost her key",
      &revoker_armored);
  if (rc != 0 || revoker_armored == NULL) {
    fprintf(stderr,
            "pgp_certificate_generate_revocation_armored_by failed: rc=%"
            PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    pgp_certificate_free(revoker_bob);
    pgp_certificate_free(alice_with_revoker);
    return 1;
  }

  struct Certificate *alice_revoked_by_bob = NULL;
  rc = pgp_certificate_apply_revocation_armored(
      alice_with_revoker, revoker_armored, &alice_revoked_by_bob);
  free(revoker_armored);
  if (rc != 0 || alice_revoked_by_bob == NULL) {
    fprintf(stderr,
            "pgp_certificate_apply_revocation_armored (designated) failed: "
            "rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    pgp_certificate_free(revoker_bob);
    pgp_certificate_free(alice_with_revoker);
    return 1;
  }

  uint8_t designated_verified = 0;
  rc = pgp_certificate_verify_designated_revocation(
      alice_revoked_by_bob, revoker_bob, &designated_verified);
  if (rc != 0 || designated_verified != 1) {
    fprintf(stderr,
            "pgp_certificate_verify_designated_revocation failed: rc=%"
            PRId32 " verified=%u\n",
            rc, designated_verified);
    pgp_certificate_free(cert);
    pgp_certificate_free(revoker_alice);
    pgp_certificate_free(revoker_bob);
    pgp_certificate_free(alice_with_revoker);
    pgp_certificate_free(alice_revoked_by_bob);
    return 1;
  }

  pgp_certificate_free(revoker_alice);
  pgp_certificate_free(revoker_bob);
  pgp_certificate_free(alice_with_revoker);
  pgp_certificate_free(alice_revoked_by_bob);

  struct Certificate *rsa_cert = NULL;
  rc = pgp_key_generate_with_cipher_suite(
      "rsa-key@example.org", /* RSA2k */ 5, &rsa_cert);
  if (rc != 0 || rsa_cert == NULL) {
    fprintf(stderr,
            "pgp_key_generate_with_cipher_suite failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(rsa_cert);

  struct Certificate *symmetric_signer = NULL;
  rc = pgp_key_generate("symmetric-signer@example.org", &symmetric_signer);
  if (rc != 0 || symmetric_signer == NULL) {
    fprintf(stderr, "pgp_key_generate (symmetric_signer) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  char *symmetric_signed = NULL;
  rc = pgp_encrypt_and_sign_string_symmetric(
      symmetric_signer, "sign+symmetric test payload",
      "correct horse battery staple", &symmetric_signed);
  if (rc != 0 || symmetric_signed == NULL) {
    fprintf(stderr,
            "pgp_encrypt_and_sign_string_symmetric failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(symmetric_signer);
    return 1;
  }

  char *symmetric_plaintext = NULL;
  char *symmetric_signer_fp = NULL;
  int64_t symmetric_signed_at = 0;
  rc = pgp_decrypt_and_verify_string_symmetric(
      symmetric_signer, symmetric_signed, "correct horse battery staple",
      &symmetric_plaintext, &symmetric_signer_fp, &symmetric_signed_at);
  if (rc != 0 || symmetric_plaintext == NULL || symmetric_signer_fp == NULL ||
      symmetric_signed_at <= 0 ||
      strcmp(symmetric_plaintext, "sign+symmetric test payload") != 0) {
    fprintf(stderr,
            "pgp_decrypt_and_verify_string_symmetric failed: rc=%" PRId32
            " plaintext=%s\n",
            rc, symmetric_plaintext ? symmetric_plaintext : "(null)");
    free(symmetric_signed);
    if (symmetric_plaintext != NULL) free(symmetric_plaintext);
    if (symmetric_signer_fp != NULL) free(symmetric_signer_fp);
    pgp_certificate_free(cert);
    pgp_certificate_free(symmetric_signer);
    return 1;
  }
  free(symmetric_signed);
  free(symmetric_plaintext);
  free(symmetric_signer_fp);

  char *recipient_message = NULL;
  rc = pgp_certificate_encrypt_string(symmetric_signer, "hello recipient",
                                       &recipient_message);
  if (rc != 0 || recipient_message == NULL) {
    fprintf(stderr, "pgp_certificate_encrypt_string failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(symmetric_signer);
    return 1;
  }

  char *recipient_key_ids = NULL;
  rc = pgp_message_recipient_key_ids(recipient_message, &recipient_key_ids);
  if (rc != 0 || recipient_key_ids == NULL ||
      strlen(recipient_key_ids) != 16) {
    fprintf(stderr,
            "pgp_message_recipient_key_ids failed: rc=%" PRId32
            " key_ids=%s\n",
            rc, recipient_key_ids ? recipient_key_ids : "(null)");
    free(recipient_message);
    if (recipient_key_ids != NULL) free(recipient_key_ids);
    pgp_certificate_free(cert);
    pgp_certificate_free(symmetric_signer);
    return 1;
  }
  free(recipient_message);
  free(recipient_key_ids);
  pgp_certificate_free(symmetric_signer);

  struct Certificate *session_key_cert = NULL;
  rc = pgp_key_generate("session-key@example.org", &session_key_cert);
  if (rc != 0 || session_key_cert == NULL) {
    fprintf(stderr, "pgp_key_generate (session_key_cert) failed: rc=%" PRId32
                     "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  char *session_key_cipher = NULL;
  rc = pgp_certificate_encrypt_string(session_key_cert, "session key payload",
                                       &session_key_cipher);
  if (rc != 0 || session_key_cipher == NULL) {
    fprintf(stderr, "pgp_certificate_encrypt_string (session key) failed: "
                     "rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    pgp_certificate_free(session_key_cert);
    return 1;
  }

  char *session_key_hex = NULL;
  uint8_t session_key_algo = 0;
  rc = pgp_message_session_key(session_key_cert, session_key_cipher,
                                &session_key_hex, &session_key_algo);
  if (rc != 0 || session_key_hex == NULL || session_key_algo == 0) {
    fprintf(stderr,
            "pgp_message_session_key failed: rc=%" PRId32 " algo=%u\n",
            rc, session_key_algo);
    free(session_key_cipher);
    pgp_certificate_free(cert);
    pgp_certificate_free(session_key_cert);
    return 1;
  }

  char *session_key_plaintext = NULL;
  rc = pgp_decrypt_with_session_key(session_key_hex, session_key_algo,
                                     session_key_cipher,
                                     &session_key_plaintext);
  if (rc != 0 || session_key_plaintext == NULL ||
      strcmp(session_key_plaintext, "session key payload") != 0) {
    fprintf(stderr,
            "pgp_decrypt_with_session_key failed: rc=%" PRId32
            " plaintext=%s\n",
            rc, session_key_plaintext ? session_key_plaintext : "(null)");
    free(session_key_hex);
    free(session_key_cipher);
    free(session_key_plaintext);
    pgp_certificate_free(cert);
    pgp_certificate_free(session_key_cert);
    return 1;
  }
  free(session_key_hex);
  free(session_key_cipher);
  free(session_key_plaintext);
  pgp_certificate_free(session_key_cert);

  char *armored = NULL;
  rc = pgp_certificate_export_armored(cert, &armored);
  if (rc != 0 || armored == NULL) {
    fprintf(stderr, "pgp_certificate_export_armored failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }

  printf("%s\n", armored);

  free(armored);
  pgp_certificate_free(cert);

  return 0;
}
