use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::Curve};
use pairing::{bls12_381::{G1Affine, G2Affine}, Field};
use rand::*;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct ComEqDiffGrpsProof<C_1: Curve, C_2: Curve<Scalar = C_1::Scalar>> {
    challenge:        C_1::Scalar,
    randomised_point: (C_1,C_2),
    witness:          (C_1::Scalar, C_1::Scalar, C_1::Scalar)
}

pub fn prove_com_eq_diff_grps<C_1: Curve, C_2: Curve<Scalar=C_1::Scalar>, R: Rng>(
    csprng: &mut R,
    public: &(C_1, C_2),
    secret: &(C_1::Scalar,C_1::Scalar,C_1::Scalar),
    coeff: &((C_1,C_1), (C_2,C_2))
) -> ComEqDiffGrpsProof<C_1, C_2> {
    let(public_1, public_2) = public;
    let (s_1, s_2, s_3) = secret;
    let ((g_1, h_1), (g_2, h_2)) = coeff;
    let mut hasher = Sha256::new();
    hasher.input(&*public_1.curve_to_bytes());
    hasher.input(&*public_2.curve_to_bytes());
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut w_1 = secret.0.clone();
    let mut w_2 = secret.1.clone();
    let mut w_3 = secret.2.clone();
    let mut challenge = C_1::Scalar::zero();
    let mut randomised_point = (C_1::zero_point(), C_2::zero_point());
    while !suc {
        let mut hasher2 = hasher.clone();
        let (r_1, r_2, r_3) = (C_1::generate_scalar(csprng), C_1::generate_scalar(csprng), C_1::generate_scalar(csprng)) ;
        let rp_1 = g_1.mul_by_scalar(&r_1).plus_point(&h_1.mul_by_scalar(&r_2));
        let rp_2 = g_2.mul_by_scalar(&r_1).plus_point(&h_2.mul_by_scalar(&r_3));
        hasher2.input(&*rp_1.curve_to_bytes());
        hasher2.input(&*rp_2.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match C_1::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if x == C_1::Scalar::zero() {
                    println!("x = 0");
                } else {
                    challenge = x;
                    randomised_point = (rp_1, rp_2);
                    w_1.mul_assign(&challenge);
                    w_1.negate();
                    w_1.add_assign(&r_1);
                    w_2.mul_assign(&challenge);
                    w_2.negate();
                    w_2.add_assign(&r_2);
                    w_3.mul_assign(&challenge);
                    w_3.negate();
                    w_3.add_assign(&r_3);
                    suc = true;
                }
            }
        }
    }

    ComEqDiffGrpsProof {
        challenge,
        randomised_point,
        witness: (w_1, w_2, w_3),
    }
}

pub fn verify_com_eq_diff_grps<C_1: Curve, C_2:Curve<Scalar=C_1::Scalar>>(coeff: &((C_1, C_1), (C_2, C_2)), public: &(C_1, C_2), proof: &ComEqDiffGrpsProof<C_1, C_2>) -> bool {
    let mut hasher = Sha256::new();
    let (public_1, public_2) = public;
    let ((g_1, h_1), (g_2, h_2)) = coeff;
    let (w_1, w_2, w_3) = proof.witness;
    hasher.input(&*public_1.curve_to_bytes());
    hasher.input(&*public_2.curve_to_bytes());
    let (rp_1, rp_2) = proof.randomised_point;
    hasher.input(&*rp_1.curve_to_bytes());
    hasher.input(&*rp_2.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match C_1::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            if c!= proof.challenge {
                false
            } else {
                rp_1 == public_1.mul_by_scalar(&c).plus_point(&g_1.mul_by_scalar(&w_1)).plus_point(&h_1.mul_by_scalar(&w_2)) &&
                    rp_2 == public_2.mul_by_scalar(&c).plus_point(&g_2.mul_by_scalar(&w_1)).plus_point(&h_2.mul_by_scalar(&w_3))
            }
        }
    }
}

#[test]
pub fn test_com_eq_diff_grps() {
    let mut csprng = thread_rng();
    for i in 0..100 {
        let (s_1, s_2, s_3) = (G1Affine::generate_scalar(&mut csprng),G1Affine::generate_scalar(&mut csprng),G1Affine::generate_scalar(&mut csprng));
        let ((g_1, h_1), (g_2, h_2)) = ((G1Affine::generate(&mut csprng), G1Affine::generate(&mut csprng)), (G2Affine::generate(&mut csprng), G2Affine::generate(&mut csprng))); 
        let public = (g_1.mul_by_scalar(&s_1).plus_point(&h_1.mul_by_scalar(&s_2)), g_2.mul_by_scalar(&s_1).plus_point(&h_2.mul_by_scalar(&s_3)));
        let secret = (s_1, s_2, s_3);
        let coeff = ((g_1, h_1), (g_2, h_2));
        let proof = prove_com_eq_diff_grps::<G1Affine, G2Affine, ThreadRng>(&mut csprng, &public, &secret, &coeff);
        assert!(verify_com_eq_diff_grps(&coeff, &public, &proof));
    }
}

