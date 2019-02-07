#include "../Hacl/hacl_test_utils.h"
void
ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {

  read_random_bytes((uint64_t) len,  p);

}





