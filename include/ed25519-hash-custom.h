#include "Hacl_SHA2_512.h"
/*
	a custom hash must have a 512bit digest and implement:

	struct ed25519_hash_context;

	void ed25519_hash_init(ed25519_hash_context *ctx);
	void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
	void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
	void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/

#define  STATE_SIZE   169
#define  BLCK_SIZE    128

typedef struct ed25519_hash_context_t  
 { uint64_t state[STATE_SIZE];
   uint8_t  buffer[BLCK_SIZE];
   size_t   leftover;
 } ed25519_hash_context;
        

void ed25519_hash_init(ed25519_hash_context *ctx){
    for(int i=0; i< STATE_SIZE; i++) 
        (ctx->state)[i] = 0;
    Hacl_SHA2_512_init(ctx -> state);
    ctx->leftover = 0;
}
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen){
    
   size_t data_size = inlen + ctx->leftover;
   if (data_size < BLCK_SIZE){
       memcpy(&(ctx->buffer[ctx->leftover]), in, inlen);
       ctx->leftover = data_size;
   }
   else{
       size_t m = BLCK_SIZE-(ctx->leftover);
       memcpy(&(ctx->buffer[ctx->leftover]), in, m);
       Hacl_SHA2_512_update(ctx->state, ctx->buffer);
       size_t data_len = (inlen - m) / BLCK_SIZE;
       ctx->leftover = (inlen-m) % BLCK_SIZE;
       uint8_t *data = &in[m];
       memcpy(ctx->buffer, &data[data_len * BLCK_SIZE] , ctx->leftover); 
       Hacl_SHA2_512_update_multi(ctx->state, data, data_len); 
   }

}
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash){
     Hacl_SHA2_512_update_last(ctx->state, ctx->buffer, ctx->leftover);
     ctx->leftover = 0;
     Hacl_SHA2_512_finish(ctx->state, hash);
}
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen){
    Hacl_SHA2_512_hash(hash, in, inlen);
}

