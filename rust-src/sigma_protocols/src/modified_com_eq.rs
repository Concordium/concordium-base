use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::Curve};
use pairing::{bls12_381::G1, Field};
use rand::*;
use sha2::{Digest, Sha256};

pub struct ModifiedComEqProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: (Vec<T>, T),
    witness:          (T::Scalar, Vec<T::Scalar>, Vec<T::Scalar>),
}

pub fn prove_com_eq<T: Curve, R: Rng>(
    evaluation: &(Vec<T>, T),                  
    coeff: &(T, T, T, T, Vec<T>),                    
    secret: &(T::Scalar, Vec<T::Scalar>, Vec<T::Scalar>), 
    csprng: &mut R,
) -> ModifiedComEqProof<T> {
    let ( p,q, g, h, gxs) = coeff;
    let (sec, bxs, axs) = secret;
    let (cxs, y) = evaluation;
    let n = cxs.len();
    assert_eq!(axs.len(), n);
    assert_eq!(bxs.len(), n);
    assert_eq!(gxs.len(), n);
    let mut suc = false;
    let mut u = T::zero_point();
    let mut vxs = vec![T::zero_point(); n];
    let mut hasher = Sha256::new();
    let mut hash = [0u8; 32];
    let mut challenge = T::Scalar::zero();
    let mut zxs = axs.clone();
    let mut wxs = bxs.clone();
    let mut wit = sec.clone(); 
    let mut rands = vec![(T::Scalar::zero(), T::Scalar::zero()); n];
    let mut a_rand = T::Scalar::zero();
    for ev in cxs.iter() {
        hasher.input(&*ev.curve_to_bytes());
    }
    hasher.input(&*y.curve_to_bytes());
    while !suc {
        let mut hasher2 = hasher.clone();
        let mut tmp_u = T::zero_point();
        for i in 0..n {
            let r_i = T::generate_scalar(csprng);
            let s_i = T::generate_scalar(csprng);
            rands[i] = (r_i, s_i);
            tmp_u = tmp_u.plus_point(&gxs[i].mul_by_scalar(&r_i));
            vxs[i] = g.mul_by_scalar(&r_i).plus_point(&h.mul_by_scalar(&s_i));
            hasher2.input(&*vxs[i].curve_to_bytes());
        }
        a_rand = T::generate_scalar(csprng);
        tmp_u = tmp_u.plus_point(&q.mul_by_scalar(&a_rand));
        tmp_u = tmp_u.plus_point(&p);
        hasher2.input(&*tmp_u.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if !(x == T::Scalar::zero()) {
                    challenge = x;
                    u = tmp_u;
                    for i in 0..n {
                        let (r_i, s_i) = rands[i];
                        zxs[i].mul_assign(&challenge);
                        zxs[i].negate();
                        zxs[i].add_assign(&r_i);
                        wxs[i].mul_assign(&challenge);
                        wxs[i].negate();
                        wxs[i].add_assign(&s_i);
                    }
                    wit.mul_assign(&challenge);
                    wit.negate();
                    wit.add_assign(&a_rand);
                    suc = true;
                }
            }
        }
    }
    

    ModifiedComEqProof {
        challenge,
        randomised_point: (vxs, u),
        witness: (wit, wxs, zxs),
    }
}

pub fn verify_com_eq<T: Curve>(
    evaluation: &(Vec<T>, T),
    coeff: &(T, T, T, T, Vec<T>),
    proof: &ModifiedComEqProof<T>,
) -> bool {
    let challenge = &proof.challenge;
    let (vxs, u) = &proof.randomised_point;
    let (wit, wxs, zxs) = &proof.witness;
    let (p,q, g, h, gxs) = coeff;
    let (cxs, y) = evaluation;
    let n = cxs.len();
    assert_eq!(wxs.len(), n);
    assert_eq!(vxs.len(), n);
    let mut u_c = y.mul_by_scalar(challenge);
    for i in 0..n {
        u_c = u_c.plus_point(&gxs[i].mul_by_scalar(&zxs[i]));
        let v_i = cxs[i]
            .mul_by_scalar(challenge)
            .plus_point(&g.mul_by_scalar(&zxs[i]))
            .plus_point(&h.mul_by_scalar(&wxs[i]));
        if v_i != vxs[i] {
            return false;
        }
    }
    let mut p_exp = challenge.clone();
    p_exp.negate();
    p_exp.add_assign(&T::Scalar::one());
    u_c =u_c.plus_point(&q.mul_by_scalar(&wit));
    u_c= u_c.plus_point(&p.mul_by_scalar(&p_exp));
    if *u == u_c {
        let mut hasher = Sha256::new();
        let mut hash = [0u8; 32];
        for ev in cxs.iter() {
            hasher.input(&*ev.curve_to_bytes());
        }
        hasher.input(&*y.curve_to_bytes());
        for p in vxs.iter() {
            hasher.input(&*p.curve_to_bytes());
        }
        hasher.input(&*u.curve_to_bytes());
        hash.copy_from_slice(hasher.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Ok(x) => {
                if x == *challenge {
                    return true;
                } else {
                    return false;
                }
            }
            Err(_) => {
                false
            }
        }
    } else {

        false
    }
}

#[test]
pub fn prove_verify_modified_com_eq() {
    let mut csprng = thread_rng();
    for i in 1..20 {
        let mut axs = vec![<G1 as Curve>::Scalar::zero(); i];
        let mut bxs = vec![<G1 as Curve>::Scalar::zero(); i];
        let mut gxs = vec![<G1 as Curve>::zero_point(); i];
        let g = G1::generate(&mut csprng);
        let h = G1::generate(&mut csprng);
        let q = G1::generate(&mut csprng);
        let p = G1::generate(&mut csprng);
        let mut cxs = vec![G1::zero_point(); i];
        let mut y = G1::zero_point();
        let sec = G1::generate_scalar(&mut csprng);

        for j in 0..i {
            axs[j] = G1::generate_scalar(&mut csprng);
            bxs[j] = G1::generate_scalar(&mut csprng);
            gxs[j] = G1::generate(&mut csprng);
            y = y.plus_point(&gxs[j].mul_by_scalar(&axs[j]));
            cxs[j] = cxs[j]
                .plus_point(&g.mul_by_scalar(&axs[j]))
                .plus_point(&h.mul_by_scalar(&bxs[j]));
        }
        y = y.plus_point(&q.mul_by_scalar(&sec));
        y= y.plus_point(&p);
        let coeff = (p, q, g, h, gxs);
        let evaluation = (cxs, y);
        let proof = prove_com_eq(&evaluation, &coeff, &(sec, bxs, axs), &mut csprng);
        assert!(verify_com_eq(&evaluation, &coeff, &proof));
    }
}

//   let coeff = G1Affine::generate(&mut csprng);
// let secret   = G1Affine::generate_scalar(&mut csprng);
// let evaluation = coeff.mul_by_scalar(&secret);
// let mut proof = prove_dlog(&evaluation, &coeff, &secret,  &mut csprng);
// assert!(verify_dlog(&evaluation, &coeff, &proof));
// let wrong_a = G1Affine::generate(&mut csprng);
// let DlogProof(c,(a,z)) = proof;
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(c,(wrong_a, z))));
// let wrong_c = G1Affine::generate_scalar(&mut csprng);
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(wrong_c,(a, z))));
// let wrong_z = G1Affine::generate_scalar(&mut csprng);
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(c, (a, wrong_z))));
//
// }
