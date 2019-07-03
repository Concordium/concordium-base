use curve_arithmetic::curve_arithmetic::Curve;
use pairing::Field;
use rand::*;
use sha2::{Digest, Sha256};

use failure::Error;
use std::io::Cursor;

use crate::common::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComMultProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: ([T; 3], T),
    witness:          ([(T::Scalar, T::Scalar); 3], T::Scalar),
}

impl<T: Curve> ComMultProof<T> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let out_len = T::SCALAR_LENGTH + 4 * T::GROUP_ELEMENT_LENGTH + 7 * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(out_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        for elem in &self.randomised_point.0 {
            write_curve_element::<T>(&elem, &mut bytes);
        }
        write_curve_element::<T>(&self.randomised_point.1, &mut bytes);
        for elem in &self.witness.0 {
            write_curve_scalar::<T>(&elem.0, &mut bytes);
            write_curve_scalar::<T>(&elem.1, &mut bytes);
        }
        write_curve_scalar::<T>(&self.witness.1, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; T::SCALAR_LENGTH];
        let mut group_buffer = vec![0; T::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let randomised_point = (
            [
                read_curve::<T>(bytes, &mut group_buffer)?,
                read_curve::<T>(bytes, &mut group_buffer)?,
                read_curve::<T>(bytes, &mut group_buffer)?,
            ],
            read_curve::<T>(bytes, &mut group_buffer)?,
        );
        let witness = (
            [
                (
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                ),
                (
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                ),
                (
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                    read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
                ),
            ],
            read_curve_scalar::<T>(bytes, &mut scalar_buffer)?,
        );
        Ok(ComMultProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}

pub fn prove_com_mult<T: Curve, R: Rng>(
    csprng: &mut R,
    public: &[T; 3],
    secret: &[(T::Scalar, T::Scalar); 3],
    coeff: &[T; 2],
) -> ComMultProof<T> {
    let mut hasher = Sha256::new();
    hasher.input(&*public[0].curve_to_bytes());
    hasher.input(&*public[1].curve_to_bytes());
    hasher.input(&*public[2].curve_to_bytes());
    let [public_1, public_2, public_3] = public;
    let [g, h] = coeff;
    // let [s_11, s_12, s_13, s_21,s_22, s_23] = secret;
    let mut randomised_point = [T::zero_point(); 3];
    let mut a_randomised_point = T::zero_point();
    let mut witness = [(T::Scalar::zero(), T::Scalar::zero()); 3];
    let mut a_witness = T::Scalar::zero();
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut rands = [(T::Scalar::zero(), T::Scalar::zero()); 3];
    let mut challenge = T::Scalar::zero();
    while !suc {
        let mut hasher2 = hasher.clone();
        for i in 0..3 {
            let r_i = T::generate_scalar(csprng);
            let t_i = T::generate_scalar(csprng);
            let v_i = g.mul_by_scalar(&r_i).plus_point(&h.mul_by_scalar(&t_i));
            rands[i] = (r_i, t_i);
            randomised_point[i] = v_i;
        }
        let r_2 = rands[1].0;
        let a_rand = T::generate_scalar(csprng);
        a_randomised_point = public_1
            .mul_by_scalar(&r_2)
            .plus_point(&h.mul_by_scalar(&a_rand));
        for rp in &randomised_point {
            hasher2.input(&rp.curve_to_bytes());
        }
        hasher2.input(&*a_randomised_point.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if x == T::Scalar::zero() {
                } else {
                    challenge = x;
                    for i in 0..3 {
                        let (mut s_1i, mut s_2i) = secret[i].clone();
                        let (r_i, t_i) = rands[i];
                        s_1i.mul_assign(&challenge);
                        s_1i.negate();
                        s_1i.add_assign(&r_i);

                        s_2i.mul_assign(&challenge);
                        s_2i.negate();
                        s_2i.add_assign(&t_i);
                        witness[i] = (s_1i, s_2i);
                    }
                    let mut rel = secret[1].0;
                    rel.mul_assign(&secret[0].1);
                    rel.negate();
                    rel.add_assign(&secret[2].1);
                    a_witness = rel;
                    a_witness.mul_assign(&challenge);
                    a_witness.negate();
                    a_witness.add_assign(&a_rand);
                    suc = true;
                }
            }
        }
    }
    ComMultProof {
        challenge,
        randomised_point: (randomised_point, a_randomised_point),
        witness: (witness, a_witness),
    }
}

pub fn verify_com_mult<T: Curve>(coeff: &[T; 2], public: &[T; 3], proof: &ComMultProof<T>) -> bool {
    let mut hasher = Sha256::new();
    // let (g_1, h_1, g, h) = base;
    // let (e_1, e_2, e_3) = public;
    let [g, h] = coeff;
    hasher.input(&*public[0].curve_to_bytes());
    hasher.input(&*public[1].curve_to_bytes());
    hasher.input(&*public[2].curve_to_bytes());
    let (witness, a_witness) = proof.witness;
    let (randomised_point, a_randomised_point) = proof.randomised_point;
    for rp in randomised_point.iter() {
        hasher.input(&*rp.curve_to_bytes());
    }
    hasher.input(&*a_randomised_point.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match T::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            if c != proof.challenge {
                return false;
            }
            for i in 0..3 {
                let (w_1, w_2) = witness[i];
                let v = randomised_point[i];
                let retrieved_v = public[i]
                    .mul_by_scalar(&c)
                    .plus_point(&g.mul_by_scalar(&w_1))
                    .plus_point(&h.mul_by_scalar(&w_2));
                if v != retrieved_v {
                    return false;
                }
            }
            a_randomised_point
                == public[2]
                    .mul_by_scalar(&c)
                    .plus_point(&public[0].mul_by_scalar(&witness[1].0))
                    .plus_point(&h.mul_by_scalar(&a_witness))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    #[test]
    pub fn test_com_mult() {
        let mut csprng = thread_rng();
        let mut secret: [(<G1 as Curve>::Scalar, <G1 as Curve>::Scalar); 3] =
            [(<G1 as Curve>::Scalar::zero(), <G1 as Curve>::Scalar::zero()); 3];
        let mut coeff: [G1; 2] = [G1::zero_point(); 2];
        let mut public: [G1; 3] = [G1::zero_point(); 3];
        for _ in 0..100 {
            for i in 0..2 {
                secret[i] = (
                    G1::generate_scalar(&mut csprng),
                    G1::generate_scalar(&mut csprng),
                );
            }
            let mut a_3 = secret[0].0.clone();
            a_3.mul_assign(&secret[1].0);
            secret[2] = (a_3, G1::generate_scalar(&mut csprng));
            coeff[0] = G1::generate(&mut csprng);
            coeff[1] = G1::generate(&mut csprng);
            for i in 0..3 {
                public[i] = coeff[0]
                    .mul_by_scalar(&secret[i].0)
                    .plus_point(&coeff[1].mul_by_scalar(&secret[i].1));
            }
            let proof = prove_com_mult(&mut csprng, &public, &secret, &coeff);
            assert!(verify_com_mult(&coeff, &public, &proof));
        }
    }

    #[test]
    pub fn test_com_mult_proof_serialization() {
        let mut csprng = thread_rng();
        let challenge = G1::generate_scalar(&mut csprng);
        let randomised_point = (
            [
                G1::generate(&mut csprng),
                G1::generate(&mut csprng),
                G1::generate(&mut csprng),
            ],
            G1::generate(&mut csprng),
        );
        let witness = (
            [
                (
                    G1::generate_scalar(&mut csprng),
                    G1::generate_scalar(&mut csprng),
                ),
                (
                    G1::generate_scalar(&mut csprng),
                    G1::generate_scalar(&mut csprng),
                ),
                (
                    G1::generate_scalar(&mut csprng),
                    G1::generate_scalar(&mut csprng),
                ),
            ],
            G1::generate_scalar(&mut csprng),
        );
        let cp = ComMultProof {
            challenge,
            randomised_point,
            witness,
        };
        let bytes = cp.to_bytes();
        let cpp = ComMultProof::from_bytes(&mut Cursor::new(&bytes));
        assert!(cpp.is_ok());
        assert_eq!(cp, cpp.unwrap());
    }
}
