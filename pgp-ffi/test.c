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
