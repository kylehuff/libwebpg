#include "gpgme.h"

int main(int argc, char* argv[]) {
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_check_version(NULL);
  gpgme_error_t err = gpgme_new (&ctx);
     
  if (!err) {
    return 0;
  } else if (gpg_err_code (err) != GPG_ERR_EOF) {
    fprintf (stderr, "can not list keys: %s\n", gpgme_strerror (err));
    return 1;
  }
}
