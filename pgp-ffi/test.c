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
  pgp_certificate_free(alice);
  cert = updated;

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
