#include "ec_vrf_ed25519-sha256.h"




int main(){
     ed25519_secret_key sk;
     ed25519_public_key pk;
     int success = keyPair(sk,pk);
     if (success !=1)
         printf("ERROR GENERATING KEY PAIR");
     if(ecvrf_verify_key(pk)==0)
         printf("KEY NOT VALID");
     printf("SK: "); print_bytes(sk, 32); printf("\n");
     printf("PK: "); print_bytes(pk, 32); printf("\n");
     
     int succ = 0;

     for(int j=2; j<1000; j++){
       uint8_t m[1000]; 
       randombytes(m, j);
       printf("MESSAGE: "); print_bytes(m, j); printf("\n");
       unsigned char pi[80];
       ecvrf_prove(pi,pk,sk,m,j);
       unsigned char proofHash[32];
       int pth = ecvrf_proof_to_hash(proofHash,pi);
       if (pth ==0)
           break;
       printf("PROOF: "); print_bytes(pi, 80); printf("\n");
       printf("PROOF Hash: "); print_bytes(proofHash, 32); printf("\n");
       int val = ecvrf_verify(pk,pi, m, j);
       printf(val==1? "SUCCESS":"FAILURE"); 
       succ = succ + val;
     }

     printf("total succ number: %d", succ);
}

