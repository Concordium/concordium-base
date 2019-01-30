#include "ec_vrf_ed25519-sha256.h"
//#include "ed25519-donna.h" 
//#include "../Ed25519/ed25519.h" 
#include "../Ed25519/ed25519-hash.h" 
#include "string.h"
#include <inttypes.h>
#include "openssl/sha.h" 
#include "openssl/rand.h" 
#include "stdio.h"
#include "../Ed25519/ed25519_cryptonite_exts.h"


void ed25519_extsk(hash_512bits extsk, const ed25519_secret_key sk) {
    ed25519_hash(extsk, sk, 32);
    extsk[0] &= 248;
    extsk[31] &= 127;
    extsk[31] |= 64;
}

static const bignum256modm zero = {
    0x00000000000000,
    0x00000000000000,
    0x00000000000000,
    0x00000000000000,
    0x00000000000000
};
const ge25519 INF={{0x00000000000000,0x00000000000000,0x00000000000000,0x00000000000000},
                   {0x00000000000000,0x00000000000000,0x00000000000000,0x00000000000000},
                   {0x00000000000000,0x00000000000000,0x00000000000000,0x00000000000000},
                   {0x00000000000000,0x00000000000000,0x00000000000000,0x00000000000000}};

void inv256_modm(bignum256modm out, bignum256modm in){
    reduce256_modm(in);
    bignum256modm t;
    bignum256modm_element_t b = 0, pb, mask;

    pb = 0;
    pb += in[0]; b = lt_modm(modm_m[0], pb); out[0] = (modm_m[0] - pb + (b << 56)); pb = b;
    pb += in[1]; b = lt_modm(modm_m[1], pb); out[1] = (modm_m[1] - pb + (b << 56)); pb = b;
    pb += in[2]; b = lt_modm(modm_m[2], pb); out[2] = (modm_m[2] - pb + (b << 56)); pb = b;
    pb += in[3]; b = lt_modm(modm_m[3], pb); out[3] = (modm_m[3] - pb + (b << 56)); pb = b;
    pb += in[4]; b = lt_modm(modm_m[4], pb); out[4] = (modm_m[4] - pb + (b << 32));
    bignum256modm sum;
    add256_modm(sum,in,out);
    /*if(!iszero256_modm_batch(sum))
       printf("\n NOT ZERO \n ");*/
    
}
void additive_inverse(bignum256modm out, bignum256modm in){
   out[0]=(uint64_t) -in[0]; 
   out[1]=(uint64_t) -in[1]; 
   out[2]=(uint64_t) -in[2]; 
   out[3]=(uint64_t) -in[3]; 
   out[4]=(uint64_t) -in[4]; 
   reduce256_modm(out);
   bignum256modm sum;
   add256_modm(sum,in,out);
   /*if(!iszero256_modm_batch(sum))
       printf("\n NOT ZERO \n ");*/
}

void subtract256_modm(bignum256modm out, bignum256modm a, bignum256modm  b){
    bignum256modm minus_b;
    inv256_modm(minus_b, b);
    add256_modm(out, a, minus_b);
} 

void mulByCofactor(ge25519 *r, const ge25519 *p){
    ge25519_double_partial(r, p);
    ge25519_double_partial(r, r);
    ge25519_double(r, r);
}

#define FE_LENGTH 16
#define EC_LENGTH 32

static void ge25519_scalarmult_vartime(ge25519 *out, const ge25519 *p, const bignum256modm s){
    ed25519_point_scalarmul (out, p, s);
}

static int os2ecp(ge25519 *r, const unsigned char p[32]) {
   unsigned char pcopy[32];
   memcpy(pcopy, p, 32);
   pcopy[31] ^= (1<<7); /* negating */
   int success = ge25519_unpack_negative_vartime (r, pcopy);
   return success;
}

void print_bytes(unsigned char *b, size_t len){
   for(size_t i = 0; i < len; i++)
        printf("%.2x",b[i]); 
}
void print_bignum25519(const bignum25519 y){
    for(int i =0; i< 5; i++)
       printf("%" PRIu64, y[i]);
}
void print_ge25519(const ge25519 *a){
    printf("x=");print_bignum25519(a->x);printf(", ");
    printf("y=");print_bignum25519(a->y);printf(", ");
    printf("z=");print_bignum25519(a->z);printf(", ");
    printf("t=");print_bignum25519(a->t);printf("\n");

}


static void ec2osp(unsigned char r[32], const ge25519 *p) {
    ge25519_pack (r, p); //p into byte string r
}
static int rs2ecp(ge25519 *r, const unsigned char p[32]) {
   return os2ecp(r, p);
}

int testEc2OS(){
    unsigned char testbytes[32];
    int i = 0;
    ge25519 points[10];
    while(i < 10){
        RAND_bytes(testbytes,32);
        ge25519 ALIGN(16) point;
        int x = os2ecp(&point, testbytes);
        if(x){
            ge25519 ALIGN(16) anotherPoint;
            mulByCofactor(&anotherPoint, &point);
            unsigned char tmpbytes[32];
            ec2osp(tmpbytes, &anotherPoint);
            int y = os2ecp(&point, tmpbytes);
            if(y){
              if(ed25519_point_eq(&point,&anotherPoint)!=1){
                  printf("points don't match");
              }
              i++;
            }
        }
    }
    return 1;
}

static void hash(unsigned char *digest, const unsigned char *m, size_t n){
    SHA256(m, n, digest);
}

static void os2bignum256modmp(bignum256modm out, const unsigned char  *in, size_t inLen){
    expand256_modm(out, in, inLen);
}

static int bignum256modm2osp(unsigned char *out, const bignum256modm in, size_t outLen){
    static const unsigned char zeros[32] = {0};
    unsigned char tmp[32];
    contract256_modm(tmp, in);
    if (memcmp(&tmp[outLen], zeros, 32-outLen) != 0){
       return -1;
    }
    else{
       memcpy(out, tmp, outLen);
       return 1;
    }
}


static void uint322osp(unsigned char out[4], uint32_t in){
    out[0] = (in >> 24);
    out[1] = (in >> 16) & 0xFF;
    out[2] = (in >> 8) & 0xFF;
    out[3] = in & 0xFF;
}

static uint32_t os2uint32p(unsigned char in[4], size_t inLen){
    return ((((in[0] << 8 | in[1]) << 8) | in[2]) << 8 | in[3]);
}

int testuint322osp(){
   unsigned char testBytes[4]; 
   unsigned char compare[4];
   for(int i = 0; i< 100; i++){
      RAND_bytes(testBytes,4);
      int res = os2uint32p(testBytes, 4);
      uint322osp(compare, res);
      if(memcmp(compare, testBytes, 4)!=0)
          return 0;
   }
   return 1;
}


static void ecvrf_hash_to_curve(ge25519 *out, const ed25519_public_key pk, unsigned char *alpha, size_t alphaLen){
    uint32_t ctr = 0;
    int valid = 0;
    unsigned char octr[4];
    uint8_t cpy[32+alphaLen+4];
    memcpy(cpy, pk, 32); memcpy(&cpy[32], alpha, alphaLen);
    unsigned char digest[32]={ 0 };
    ge25519 ALIGN(16) p;
    while (!valid){
       uint322osp(octr, ctr);
       ctr += 1;
       memcpy(&cpy[32+alphaLen], octr, 4);
       hash (digest, cpy, 36+alphaLen);
       valid = os2ecp(&p, digest);
    }
    mulByCofactor(out, &p);
}

static void ecvrf_hash_points(bignum256modm out, ge25519 *in, size_t len){
    unsigned char P[32 * len];
    unsigned char tmp[32];
    for (int i=0; i< len; i++){
        ec2osp(tmp, in);
        memcpy(&P[i*32], tmp, 32);
        in++;
    }
    unsigned char digest[32]={ 0 };
    hash(digest, P, 32 * len);
    os2bignum256modmp(out, digest, FE_LENGTH);
    /*for(int i=0; i<5;i++)
        printf("%" PRIu64, out[i]);*/
}

void printPoints(ge25519 points[6]){
    unsigned char tmp[32]={0};
    ec2osp(tmp, &points[0]);
    printf("[\n");
    for(int i=0; i<32;i++)
        printf("%c", tmp[i]);
    for(int j=1;j<6;j++){
        ec2osp(tmp, &points[j]);
        printf(",\n");
        for(int i=0; i<32;i++)
          printf("%c", tmp[i]);
    }
    printf("\n ]");
}

void
ed25519_point_copy (ge25519 *r, const ge25519 *p) {
    curve25519_copy(r->x, p->x);
    curve25519_copy(r->y, p->y);
    curve25519_copy(r->z, p->z);
    curve25519_copy(r->t, p->t);
}
ge25519 co;

void expand_sk(bignum256modm out, const ed25519_secret_key sk){
    ge25519 ALIGN(16) A;
    hash_512bits extsk;

    /* A = aB */
    ed25519_extsk(extsk, sk);
    expand256_modm(out, extsk, 32);
}

void ecvrf_prove(unsigned char pi[80], const ed25519_public_key pk, const ed25519_secret_key sk, uint8_t *alpha, size_t len){
    ge25519 ALIGN(16) h; 
    ge25519 ALIGN(16) gamma; 
    bignum256modm x;
    ecvrf_hash_to_curve (&h, pk, alpha, len);
    //expand256_modm(x, sk, 32);
    expand_sk(x,sk);
    ge25519_scalarmult_vartime(&gamma, &h, x);   
    unsigned char kk[32];
    int rc=RAND_bytes(kk, 32); 
    if(rc !=1)
        printf("RAND BYTES FAILED");
    bignum256modm k;
    expand256_modm(k, kk, 32);
    ge25519 points[6];
    ge25519 ALIGN(16) hk;
    ge25519 ALIGN(16) gk;
    ge25519 ALIGN(16) y;
    ge25519_scalarmult_vartime(&hk, &h, k);
    ge25519_scalarmult_base_niels(&gk, ge25519_niels_base_multiples, k);
    os2ecp(&y,pk);
    points[0] = ge25519_basepoint;
    points[1] = h;
    points[2] = y;
    points[3] = gamma;
    points[4] = gk;
    points[5] = hk;
    bignum256modm c;
    ecvrf_hash_points(c, points, 6);
    bignum256modm cx;
    bignum256modm kcx;
    mul256_modm(cx, c, x);
    subtract256_modm(kcx,k,cx);
    //curve25519_sub_reduce(kcx, k,cx);
    //reduce256_modm(kcx);
    //sub256_modm_batch (kcx,k,cx,bignum256modm_limb_size);
    unsigned char tmp[32];
    /* pi = ec2osp(gamma) || i2osp(c,16) || i2osp(s,32) */
    ec2osp(tmp, &gamma); 
    memcpy(pi, tmp, 32);

    bignum256modm2osp(tmp, c, 16);
    memcpy(&pi[32], tmp, 16);

    bignum256modm2osp(tmp, kcx, 32);  
    memcpy(&pi[3 * FE_LENGTH], tmp, 32); 
}


int ecvrf_decode_proof(const unsigned char pi[80], ge25519 *gamma, bignum256modm c, bignum256modm s){
    unsigned char gamma2[32]; memcpy(gamma2, pi, 32);
    unsigned char c2[16]; memcpy(c2, &pi[32], 16);
    unsigned char s2[32]; memcpy(s2, &pi[48], 32);
    if (os2ecp(gamma,gamma2) < 1) 
        return -1;
    os2bignum256modmp(c,c2,16);
    os2bignum256modmp(s,s2,32);
    return 1;
}

int ed25519_is_inf(ge25519* p){
    bignum256modm tmp;
    curve25519_copy(tmp,p->z);
    reduce256_modm(tmp); 
    return (iszero256_modm_batch(tmp)? 1 : 0);
}

int ecvrf_verify_key(const ed25519_public_key pk){
    ge25519 ALIGN(16) y;
    if(!os2ecp(&y,pk))
        return 0;
    ge25519 ALIGN(16) yByCof;
    mulByCofactor(&yByCof, &y);
    return (ed25519_is_inf(&yByCof)? 0 : 1);
}
int ecvrf_proof_to_hash(unsigned char out[32], const unsigned char pi[80]){
    ge25519 ALIGN(16) gamma;
    bignum256modm c;
    bignum256modm s;
    if (ecvrf_decode_proof(pi, &gamma, c, s) < 1)
        return -1;
    
    ge25519 ALIGN(16) gammaByCofactor;
    mulByCofactor(&gammaByCofactor,&gamma);
    unsigned char message[32];
    ec2osp(message, &gammaByCofactor);
    hash(out, message, 32);
    return 1;
}

int ecvrf_verify(const ed25519_public_key pk, const unsigned char pi[80], uint8_t *alpha, size_t len){
    ge25519 ALIGN(16) gamma;
    bignum256modm c;
    bignum256modm s;
    if (ecvrf_decode_proof(pi, &gamma, c, s) < 1)
        return -1;
    ge25519 ALIGN(16) y; 
    os2ecp(&y,pk);
    ge25519 ALIGN(16) u;
    ge25519_double_scalarmult_vartime(&u, &y, c, s);
    ge25519 ALIGN(16) h;
    ecvrf_hash_to_curve(&h, pk, alpha, len); 
    ge25519 ALIGN(16) gammac;
    ge25519 ALIGN(16) hs;
    ge25519 ALIGN(16) v;
    ge25519_scalarmult_vartime(&gammac, &gamma, c);
    ge25519_scalarmult_vartime(&hs, &h, s);
    ge25519_add(&v, &gammac, &hs); /*should be equal to h^k*/
    /* 
    for(int i = 0; i < 32; i++)
        printf("%.2x",toPrint[i]);
    */ 
    ge25519 points[6];
    points[0] = ge25519_basepoint;
    points[1] = h;
    points[2] = y;
    points[3] = gamma;
    points[4] = u;
    points[5] = v;
    bignum256modm c2;
    ecvrf_hash_points(c2, points, 6);
    reduce256_modm(c);reduce256_modm(c2);
    return ed25519_scalar_eq(c,c2);
    
}

int priv_key(ed25519_secret_key sk){
    int rc = RAND_bytes(sk,sizeof(ed25519_secret_key));
    //print_bytes(sk,32);
    return rc;
}

int public_key(ed25519_secret_key pk, ed25519_public_key sk){
    //print_bytes(sk,32);printf("\n");
    bignum256modm x;
    //os2bignum256modmp(x,sk,sizeof(ed25519_secret_key));
    expand_sk(x,sk);
    ge25519 ALIGN(16) pk_point;
    ge25519_scalarmult_base_niels(&pk_point, ge25519_niels_base_multiples, x);
    ec2osp(pk,&pk_point);
    //print_bytes(pk,32);printf("\n");
    return 1;
}

int keyPair(ed25519_secret_key sk, ed25519_public_key pk){
    //int rc = RAND_bytes(sk,sizeof(ed25519_secret_key));
    //print_bytes(sk,32);printf("\n");
    int rc = priv_key(sk);
    if(rc != 1)
        return 0;
    //bignum256modm x;
    //os2bignum256modmp(x,sk,sizeof(ed25519_secret_key));
    //ge25519 ALIGN(16) pk_point;
    //ge25519_scalarmult_base_niels(&pk_point, ge25519_niels_base_multiples, x);
    //ec2osp(pk,&pk_point);
    //print_bytes(pk,32);printf("\n");
    return public_key(pk, sk);
}

int main(){
    //int x = testEc2OS();
    //printf("result %d\n", x);
    //return x;
 printf( "length?");
 int length;
 int result = scanf("%d", &length);
 if (result == EOF)
 { 
     printf("ERROR");
     return -1;
 }
 else
 {
     ed25519_secret_key sk;
     ed25519_public_key pk;
     int success = keyPair(sk,pk);
     if (success !=1)
         printf("ERROR GENERATING KEY PAIR");
     if(ecvrf_verify_key(pk)==0)
         printf("KEY NOT VALID");
     while(1)
     {
         uint8_t alpha[length];
         printf("message?");
         scanf("%s", alpha);
         unsigned char pi[80];
         ecvrf_prove(pi,pk ,sk , alpha, length);
         unsigned char proofHash[32];
         int pth = ecvrf_proof_to_hash(proofHash,pi);
         if (pth){
             for(int i =0;i<32;i++)
               printf("%.2x",proofHash[i]);
         }

         int val= ecvrf_verify(pk, pi, alpha, length); 
         printf("\n **** %d ****\n", val);
             
     }
     return 1;
 }
}
