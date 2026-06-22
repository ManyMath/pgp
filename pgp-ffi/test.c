#include "pgp-ffi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

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
  rc = pgp_certificate_revoke_userid(cert, "other@example.org", &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_revoke_userid failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  updated = NULL;
  rc = pgp_certificate_revoke_subkey(cert, 1, &updated);
  if (rc != 0 || updated == NULL) {
    fprintf(stderr, "pgp_certificate_revoke_subkey failed: rc=%" PRId32 "\n",
            rc);
    pgp_certificate_free(cert);
    return 1;
  }
  pgp_certificate_free(cert);
  cert = updated;

  updated = NULL;
  rc = pgp_certificate_revoke(cert, &updated);
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
