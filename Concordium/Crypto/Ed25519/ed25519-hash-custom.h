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
    //print_bytes(ctx->state,169*8);
    //printf("zerod context\n");
    Hacl_SHA2_512_init(ctx -> state);
    //print_bytes(ctx->state,169*8);
    ctx->leftover = 0;
    //printf("init done\n");
}
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen){
   size_t num_of_blocks = (inlen + (ctx->leftover))/BLCK_SIZE;
   size_t update_multi_size = num_of_blocks * BLCK_SIZE;
   if (update_multi_size == 0){
       memcpy(&(ctx->buffer[ctx->leftover]),in, inlen);
       ctx->leftover = ctx->leftover + inlen;
   }
   else
   {
       uint8_t to_multi[update_multi_size];
       memcpy(to_multi, ctx->buffer, ctx->leftover); 
       memcpy(&to_multi[ctx->leftover], in, (update_multi_size - ctx->leftover));
       Hacl_SHA2_512_update_multi(ctx->state, to_multi, num_of_blocks); 
       ctx->leftover = ctx->leftover + inlen - update_multi_size;
       memcpy(ctx->buffer, &in[inlen-(ctx->leftover)], ctx->leftover);
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

