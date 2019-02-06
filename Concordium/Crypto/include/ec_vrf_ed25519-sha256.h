#include "../Ed25519/ed25519-donna.h"
#include "ed25519.h"
#include "string.h"
#include <inttypes.h>
#include "Hacl_SHA2_512.h"


//void print_bytes(unsigned char *b, size_t len);
void print_bignum25519(const bignum25519 y);
void ecvrf_prove(unsigned char pi[80], const ed25519_public_key pk, const ed25519_secret_key sk, uint8_t *alpha, size_t len);

int ecvrf_verify_key(const ed25519_public_key pk);
    
int ecvrf_proof_to_hash(unsigned char out[32], const unsigned char pi[80]);

int ecvrf_verify(const ed25519_public_key pk, const unsigned char pi[80], uint8_t *alpha, size_t len);

int priv_key(ed25519_secret_key sk);

int public_key(ed25519_secret_key pk, ed25519_public_key sk);

int keyPair(ed25519_secret_key sk, ed25519_public_key pk);

static void ecvrf_extsk(hash_512bits extsk, const ed25519_secret_key sk) {
    Hacl_SHA2_512_hash(extsk, sk, 32);
    extsk[0] &= 248;
    extsk[31] &= 127;
    extsk[31] |= 64;
}
