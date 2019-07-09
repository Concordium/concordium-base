use curve_arithmetic::curve_arithmetic::*;
use curve_arithmetic::serialization::*;
use pairing::Field;
use rand::*;
use sha2::{Digest, Sha256};

use failure::Error;
use std::io::Cursor;



//proof that you know values (m_1,...,m_n), t, (r_1,...,n) such 
//e(a,X') . Prod e(a,Y_j')^m_j . e(a,g')^t = e(b,g')
//C_j = g^m_j h^_r_j
//for public values a, b, C_j in G_1, and  X', Y_j', g' in G_2 
//and known pairing e
#[derive(Clone, Debug)]
pub struct ComEqSigProof<P: Pairing> {
    challenge:        P::ScalarField,
    randomised_point: (P::G_2, Vec<P::G_1>) ,
    witness:          ((P::ScalarField, Vec<P::ScalarField>), Vec<P::ScalarField>),
}

impl<P:Pairing> PartialEq for ComEqSigProof<P>{
    fn eq(&self, other:&Self) -> bool{
        self.challenge == other.challenge &&
            self.randomised_point == other.randomised_point &&
            self.witness == other.witness
    }
}


impl<P: Pairing> ComEqSigProof<P> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rp_len = self.randomised_point.1.len();
        let witness1_len = (self.witness.0).1.len();
        let witness2_len = self.witness.1.len();
        let bytes_len = P::SCALAR_LENGTH
            + P::G_2::GROUP_ELEMENT_LENGTH
            + rp_len  * P::G_1::GROUP_ELEMENT_LENGTH
            + (1 + witness1_len  + witness2_len) * P::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<P::G_2>(&self.challenge, &mut bytes);
        write_curve_element::<P::G_2>(&self.randomised_point.0, &mut bytes);
        write_curve_elements::<P::G_1>(&self.randomised_point.1, &mut bytes);
        write_curve_scalar::<P::G_2>(&(self.witness.0).0, &mut bytes);
        write_curve_scalars::<P::G_2>(&(self.witness.0).1, &mut bytes);
        write_curve_scalars::<P::G_2>(&self.witness.1, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; P::SCALAR_LENGTH];
        let mut group2_buffer = vec![0; P::G_2::GROUP_ELEMENT_LENGTH];
        let mut group1_buffer = vec![0; P::G_1::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<P::G_2>(bytes, &mut scalar_buffer)?;
        let rp1 = read_curve::<P::G_2>(bytes, &mut group2_buffer)?;
        let rp2 = read_curve_elements::<P::G_1>(bytes, &mut group1_buffer)?;
        let w0 = read_curve_scalar::<P::G_2>(bytes, &mut scalar_buffer)?;
        let w1 = read_curve_scalars::<P::G_2>(bytes, &mut scalar_buffer)?;
        let w2 = read_curve_scalars::<P::G_2>(bytes, &mut scalar_buffer)?;
        Ok(ComEqSigProof {
            challenge: challenge,
            randomised_point: (rp1, rp2),
            witness: ((w0, w1), w2),
        })
    }
}

pub fn prove_com_eq_sig<P: Pairing, R: Rng>(
    evaluation: &((P::G_1, P::G_2), Vec<P::G_1>),
    coeff: &((P::G_1, P::G_2), (P::G_1, P::G_2), (P::G_1, Vec<P::G_2>), (P::G_1, P::G_1)),
    secret: &((P::ScalarField, Vec<P::ScalarField>), Vec<P::ScalarField>),
    csprng: &mut R,
) -> ComEqSigProof<P> {
    let ((eval_pair, eval), comm_vec) = evaluation;
    let ((_p_pair, p), (_q_pair,q), (_gxs_pair, gxs) , (g, h)) = coeff;
    let ((q_sec, gxs_sec), pedersen_rands) = secret;
    let n = comm_vec.len();
    assert_eq!(gxs_sec.len(), n);
    assert_eq!(pedersen_rands.len(), n);
    assert_eq!(gxs.len(), n);
    let mut suc = false;
    //randomised points 
    let mut u = <P::G_2 as Curve>::zero_point();
    let mut vxs = vec![<P::G_1 as Curve>::zero_point(); n];

    //let mut rands = vec![(T::Scalar::zero(), T::Scalar::zero()); n];
    let mut challenge = <P::G_2 as Curve>::Scalar::zero();

    let mut q_wit = q_sec.clone();
    let mut q_rand = <P::G_2 as Curve>::Scalar::zero();

    let mut gxs_wit = gxs_sec.clone();
    let mut gxs_rands = vec![<P::G_2 as Curve>::Scalar::zero(); n];

    let mut pedersen_rands_wit = pedersen_rands.clone();
    let mut pedersen_rands_rands = vec![<P::G_1 as Curve>::Scalar::zero(); n];

    let mut hasher = Sha256::new();
    let mut hash = [0u8; 32];
    //hashing evaluations

    for ev in comm_vec.iter() {
        hasher.input(&*ev.curve_to_bytes());
    }
    hasher.input(&*eval_pair.curve_to_bytes());
    hasher.input(&*eval.curve_to_bytes());

    while !suc {
        let mut hasher2 = hasher.clone();
        let mut tmp_u = <P::G_2 as Curve>::zero_point();
        for i in 0..n {
            gxs_rands[i] = <P::G_2 as Curve>::generate_scalar(csprng);
            pedersen_rands_rands[i] = <P::G_1 as Curve>::generate_scalar(csprng);
            //rands[i] = (r_i, s_i);
            tmp_u = tmp_u.plus_point(&gxs[i].mul_by_scalar(&gxs_rands[i]));
            vxs[i] = g.mul_by_scalar(&gxs_rands[i]).plus_point(&h.mul_by_scalar(&pedersen_rands_rands[i]));
            hasher2.input(&*vxs[i].curve_to_bytes());
        }
        q_rand = <P::G_2 as Curve>::generate_scalar(csprng);
        tmp_u = tmp_u.plus_point(&q.mul_by_scalar(&q_rand));
        tmp_u = tmp_u.plus_point(&p);
        hasher2.input(&*tmp_u.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match <P::G_2 as Curve>::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if !(x == <P::G_2 as Curve>::Scalar::zero()) {
                    challenge = x;
                    u = tmp_u;
                    for i in 0..n {
                        gxs_wit[i].mul_assign(&challenge);
                        gxs_wit[i].negate();
                        gxs_wit[i].add_assign(&gxs_rands[i]);

                        pedersen_rands_wit[i].mul_assign(&challenge);
                        pedersen_rands_wit[i].negate();
                        pedersen_rands_wit[i].add_assign(&pedersen_rands_rands[i]);
                    }
                    q_wit.mul_assign(&challenge);
                    q_wit.negate();
                    q_wit.add_assign(&q_rand);
                    suc = true;
                }
            }
        }
    }

    ComEqSigProof {
        challenge,
        randomised_point: (u, vxs),
        witness: ((q_wit, gxs_wit), pedersen_rands_wit),
    }
}

pub fn verify_com_eq_sig<P: Pairing>(
    evaluation: &((P::G_1, P::G_2), Vec<P::G_1>),
    coeff: &((P::G_1, P::G_2), (P::G_1, P::G_2), (P::G_1, Vec<P::G_2>), (P::G_1, P::G_1)),
    proof: &ComEqSigProof<P>,
) -> bool {
    let challenge = &proof.challenge;
    let (u, vxs) = &proof.randomised_point;
    let ((q_wit, gxs_wit), pedersen_rands_wit) = &proof.witness;
    let ((p_pair, p), (q_pair,q), (gxs_pair, gxs) , (g, h)) = coeff;
    let ((eval_pair, eval), comm_vec) = evaluation;
    let n = comm_vec.len();
    assert_eq!(gxs_wit.len(), n);
    assert_eq!(pedersen_rands_wit.len(), n);
    assert_eq!(vxs.len(), n);
    let  u_1 = P::pair(*eval_pair,eval.mul_by_scalar(challenge));
    let mut tmp_u = <P::G_2 as Curve>::zero_point();
    for i in 0..n {
        tmp_u = tmp_u.plus_point(&gxs[i].mul_by_scalar(&gxs_wit[i]));
        let v_i = comm_vec[i]
            .mul_by_scalar(challenge)
            .plus_point(&g.mul_by_scalar(&gxs_wit[i]))
            .plus_point(&h.mul_by_scalar(&pedersen_rands_wit[i]));
        if v_i != vxs[i] {
            println!("v_{} false", i);
            return false;
        }
    }
    let mut u_c = <P::TargetField as Field>::one();
    let u_2 = P::pair(*gxs_pair, tmp_u);
    let mut p_exp = challenge.clone();
    p_exp.negate();
    p_exp.add_assign(&<P::G_2 as Curve>::Scalar::one());
    let u_4 = P::pair(*p_pair, p.mul_by_scalar(&p_exp));
    let u_3 = P::pair(*q_pair, q.mul_by_scalar(&q_wit));
    u_c.mul_assign(&u_1);
    u_c.mul_assign(&u_2);
    u_c.mul_assign(&u_3);
    u_c.mul_assign(&u_4);
    let paired_u = P::pair(*gxs_pair, *u);
    if paired_u == u_c {
        let mut hasher = Sha256::new();
        let mut hash = [0u8; 32];
        for ev in comm_vec.iter() {
            hasher.input(&*ev.curve_to_bytes());
        }
        hasher.input(&*eval_pair.curve_to_bytes());
        hasher.input(&*eval.curve_to_bytes());
        for p in vxs.iter() {
            hasher.input(&*p.curve_to_bytes());
        }
        hasher.input(&*u.curve_to_bytes());
        hash.copy_from_slice(hasher.result().as_slice());
        match <P::G_2 as Curve>::bytes_to_scalar(&hash) {
            Ok(x) => x == *challenge,
            Err(_) => false,
        }
    } else {
        println!("paired u != u_c");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use pairing::bls12_381::G1Affine;
    use pairing::bls12_381::G2Affine;
    //use curve_arithmetic::curve_arithmetic::*;

    /*
     * pub fn prove_mod_com_eq<P: Pairing, R: Rng>(
      evaluation: &((P::G_1, P::G_2), Vec<P::G_1>),
      coeff: &((P::G_1, P::G_2), (P::G_1, P::G_2), (P::G_1, Vec<P::G_2>), (P::G_1, P::G_1)),
      secret: &((P::ScalarField, Vec<P::ScalarField>), Vec<P::ScalarField>),
      csprng: &mut R,
  ) -> ModifiedComEqProof<P> {
        let ((eval_pair, eval), comm_vec) = evaluation;
      let ((p_pair, p), (q_pair,q), (gxs_pair, gxs) , (g, h)) = coeff;
      let ((q_sec, gxs_sec), pedersen_rands) = secret;
      let n = comm_vec.len();
   */
    #[test]
    pub fn prove_verify_com_eq_sig() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut y_sk = vec![<Bls12 as Pairing>::ScalarField::zero(); i];
            let mut y_pk = vec![<Bls12 as Pairing>::G_2::zero_point(); i];
            let x_sk = <G2Affine as Curve>::generate_scalar(&mut csprng);
            let x_pk = <G2Affine as Curve>::one_point().mul_by_scalar(&x_sk);
            let a_1 = <G1Affine as Curve>::generate(&mut csprng);
            let mut a_2_exp = x_sk;
            //let mut a_2_exp = <Bls12 as Pairing>::ScalarField::zero();

            let mut att_list = vec![<Bls12 as Pairing>::ScalarField::zero(); i];
            let (g,h) = (<G1Affine as Curve>::generate(&mut csprng), <G1Affine as Curve>::generate(&mut csprng));
            let mut comm_vec = vec![<G1Affine as Curve>::zero_point(); i];
            let mut pedersen_rands = vec![<Bls12 as Pairing>::ScalarField::zero(); i];

            for j in 0..i {
                y_sk[j] = <Bls12 as Pairing>::generate_scalar(&mut csprng);
                y_pk[j] = <G2Affine  as Curve>::one_point().mul_by_scalar(&y_sk[j]);
                att_list[j] = <Bls12 as Pairing>::generate_scalar(&mut csprng);
                pedersen_rands[j] = <Bls12 as Pairing>::generate_scalar(&mut csprng);
                let mut tmp = y_sk[j];
                tmp.mul_assign(&att_list[j]);
                a_2_exp.add_assign(&tmp);
                comm_vec[j] = g.mul_by_scalar(&att_list[j]).plus_point(&h.mul_by_scalar(&pedersen_rands[j]));
            }
            let a_2 = a_1.mul_by_scalar(&a_2_exp);
        
            let (r, t) = (<Bls12 as Pairing>::generate_scalar(&mut csprng),<Bls12 as Pairing>::generate_scalar(&mut csprng));
            let (a_1_hid, a_2_hid) = (a_1.mul_by_scalar(&r), (a_2.plus_point(&a_1.mul_by_scalar(&t))).mul_by_scalar(&r));
            let eval_pair = a_2_hid; let eval = <G2Affine as Curve>::one_point();
            let p_pair = a_1_hid; let p = x_pk;
            let q_pair = a_1_hid; let q = <G2Affine as Curve>::one_point();
            let gxs_pair = a_1_hid; let gxs = y_pk;
            let q_sec = t; let gxs_sec = att_list;
            let evaluation = ((eval_pair, eval), comm_vec);
            let coeff = ((p_pair, p), (q_pair, q), (gxs_pair, gxs), (g,h));
            let secret = ((q_sec, gxs_sec), pedersen_rands);


            let proof = prove_com_eq_sig::<Bls12, ThreadRng>(&evaluation, &coeff, &secret, &mut csprng);
            assert!(verify_com_eq_sig(&evaluation, &coeff, &proof));

            let wrong_q_sec = <Bls12 as Pairing>::generate_scalar(&mut csprng);
            let wrong_secret = ((wrong_q_sec, (secret.0).1), secret.1);
            let wrong_proof = prove_com_eq_sig::<Bls12, ThreadRng>(&evaluation, &coeff, &wrong_secret, &mut csprng);
            assert!(!verify_com_eq_sig(&evaluation, &coeff, &wrong_proof));
        }



    }

    /*
     * pub struct ModifiedComEqProof<P: Pairing> {
      challenge:        P::ScalarField,
      randomised_point: (P::G_2, Vec<P::G_1>) ,
      witness:          ((P::ScalarField, Vec<P::ScalarField>), Vec<P::ScalarField>),
  }
  */
    #[test]
    pub fn test_com_eq_sig_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let challenge = <Bls12 as Pairing>::generate_scalar(&mut csprng);
            let lrp2 = csprng.gen_range(1, 30);
            let mut rp2 = Vec::with_capacity(lrp2);
            for _ in 0..lrp2 {
                rp2.push(<G1Affine as Curve>::generate(&mut csprng));
            }
            let rp1 = <G2Affine as Curve>::generate(&mut csprng);
            let lw1 = csprng.gen_range(1, 87);
            let mut w1 = Vec::with_capacity(lw1);
            for _ in 0..lw1 {
                w1.push(<Bls12 as Pairing>::generate_scalar(&mut csprng));
            }
            let lw2 = csprng.gen_range(1, 100);
            let mut w2 = Vec::with_capacity(lw1);
            for _ in 0..lw2 {
                w2.push(<Bls12 as Pairing>::generate_scalar(&mut csprng));
            }
            let cep = ComEqSigProof::<Bls12> {
                challenge,
                randomised_point: (rp1, rp2),
                witness: ((<Bls12 as Pairing>::generate_scalar(&mut csprng), w1), w2),
            };
            let bytes = cep.to_bytes();
            let cepp = ComEqSigProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(cepp.is_ok());
            assert_eq!(cep, cepp.unwrap());
        }
    }
}

