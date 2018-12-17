
/* 
 *  uint32_t is the length of the input byte array
 *  the has is stored at *hash
 */
void hash(uint8_t *hash, uint8_t *input, uint32_t len)
{

}

/* Following certicom corp
 * Standards for Efficient Cryptography
 * SEC 1: Elliptic Curve Cryptography
 * http://www.secg.org/sec1-v2.pdf
 */

typedef struct {
	mpz_t x_coordinate;
	mpz_t y_coordinate;
} ecPoint;

typedef struct {
	mpz_t f_ord; /* prime order of field */
	mpz_t coeff_1; mpz_t coeff_0; /* coefficients y^2 = x^3 + a x + b */
	ecPoint G;  /* base point */
        mpz_t bp_ord; /* order of base point */
	mpz_t cof ; /* cofactor #E(F_p)/ord */

} ecParams;

typedef struct {
	mpz_t group_ord;
	ecPoint point;
} ecGroup;


typedef struct {
	mpz_t f_ord; /* prime order of field */
	mpz_t coeff_1; mpz_t coeff_0; /* coefficients y^2 = x^3 + a x + b */
	ecGroup G_1; ecGroup G_2; ecGroup G_3; /* finite acyclic groups */
	ecPoint (*pairing) (ecPoint, ecPoint); /* pointer to pairing function */
        } pairingEcParams;

typedef struct {
	mpz_t privKey;
	ecPoint pubKey;
} keyPair;


keyPair generateKeyPair (ecParams params){
	/* randomly select and integer d in the interval [1, params.bp_ord -1]
	 * compute Q = dG
	 * rerurn {d, Q} */
}	

bool validatePubKey (ecPoint pubKey){
	/* validate per the rules page 24 in the document */
	return true;
}

/* modular pairing */

ecPoint pair(ecPoint P, ecPiont Q){
}


