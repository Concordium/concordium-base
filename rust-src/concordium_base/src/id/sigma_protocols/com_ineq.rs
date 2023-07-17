//! The module provides the implementation of the sigma protocol for "proof of
//! inequality for committed value and public value". This protocol enables one
//! to prove that a committed value is not equal to a public one, without
//! revealing the value.

use super::{
    com_mult::{ComMult, ComMultSecret, Witness as ComMultWitness},
    common::{prove as sigma_prove, verify as sigma_verify, SigmaProof},
};
use crate::{
    common::*,
    curve_arithmetic::Curve,
    pedersen_commitment::{Commitment, CommitmentKey, Randomness, Value},
    random_oracle::RandomOracle,
};
use ff::Field;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Witness<C: Curve> {
    // The witness consists of a com_mult witness and a commitment.
    com_mult_witness: SigmaProof<ComMultWitness<C>>,
    aux_com:          Commitment<C>,
}

/// Function for proving that a committed value `value` is different from
///  `pub_value`. The parameters are
/// - `com_key` - the commitment key used to commit to the value
/// - `value` - the value inside the commitment
/// - `value_tilde` - the randomness used to commit
/// - `pub_value` - the public value claimed to be different from `value`
/// - `csprng` - a cryptographically secure random number generator

pub fn prove_com_ineq<R: rand::Rng, C: Curve>(
    com_key: &CommitmentKey<C>,
    value: &Value<C>,
    value_tilde: &Randomness<C>,
    pub_value: C::Scalar,
    csprng: &mut R,
) -> Option<Witness<C>> {
    let mut transcript = RandomOracle::domain(b"InequalityProof");

    let c = com_key.hide(&value, value_tilde);
    transcript.append_message(b"commitmentKey", &com_key);
    transcript.append_message(b"public commitment", &c);
    transcript.append_message(b"public value", &pub_value);

    // Compute value - pub_value
    let mut diff = pub_value;
    diff.negate();
    diff.add_assign(value);

    // Compute the inverse of (value - pub_value)
    let diff_inv = diff.inverse()?;

    // Generate commitment cmm_1 to `diff` using the given randomness `value_tilde`.
    // This allows the verifier to compute cmm_1 from public commitment
    // c=g^{value} h^{value_tilde} for com_key=(g, h).
    let diff_val = Value::new(diff);
    let diff_inv_val = Value::new(diff_inv);
    let cmm_1 = com_key.hide(&diff_val, value_tilde);
    let (cmm_2, r_2) = com_key.commit(&diff_inv_val, csprng);
    //  This is a commitment to 1 with randomness 0. Alternatively, one could use
    // cmm_3 = com_key.hide(one, zero).
    let cmm_3 = Commitment(com_key.g);

    // This is the com-mult proof in section 9.2.10 from the Bluepaper. It proves
    // that the product of the values in the first two commitments equals the one in
    // the last commitment.
    let prover = ComMult {
        cmms:    [cmm_1, cmm_2, cmm_3],
        cmm_key: *com_key,
    };

    let secret = ComMultSecret {
        values: [diff_val, diff_inv_val],
        rands:  [value_tilde.clone(), r_2, Randomness::<C>::zero()],
    };

    let partial_proof = sigma_prove(&mut transcript, &prover, secret, csprng)?;
    Some(Witness {
        com_mult_witness: partial_proof,
        aux_com:          cmm_2,
    })
}

/// Function for verifying that a value inside a commitment is not equal to a
/// public value `pub_value`. The parameters are
/// - `com_key` - the commitment key used to commit to the value
/// - `c` - the commitment to the value
/// - `pub_value` - the public value claimed to be different from the committed
///   value
/// - `proof` - the proof
///
/// The function outputs a bool, indicating whether the proof is correct or not.

pub fn verify_com_ineq<C: Curve>(
    com_key: &CommitmentKey<C>,
    c: &Commitment<C>,
    pub_value: C::Scalar,
    proof: &Witness<C>,
) -> bool {
    let Witness {
        com_mult_witness,
        aux_com,
    } = proof;
    let mut transcript = RandomOracle::domain(b"InequalityProof");
    transcript.append_message(b"commitmentKey", &com_key);
    transcript.append_message(b"public commitment", &c);
    transcript.append_message(b"public value", &pub_value);

    // Compute commitment cmm_1 to the committed value - pub_value from public input
    let mut minus_pub_value = pub_value;
    minus_pub_value.negate();
    let g_minus_pub_value = com_key.g.mul_by_scalar(&minus_pub_value);

    let cmm_1: C = c.plus_point(&g_minus_pub_value);
    let cmm_3 = Commitment(com_key.g);

    let com_mult = ComMult {
        cmms:    [Commitment(cmm_1), *aux_com, cmm_3],
        cmm_key: *com_key,
    };
    sigma_verify(&mut transcript, &com_mult, com_mult_witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use pairing::bls12_381::{Fr, G1};

    #[test]
    fn test_com_ineq_correctness() {
        let mut csprng = rand::thread_rng();
        let com_key: CommitmentKey<_> = CommitmentKey::<G1>::generate(&mut csprng);

        let value = Value::<G1>::new(Fr::from_str("20000102").unwrap());
        let pub_value = Fr::from_str("20000103").unwrap();

        let (cmm_1, value_tilde) = com_key.commit(&value, &mut csprng);

        let proof = prove_com_ineq(&com_key, &value, &value_tilde, pub_value, &mut csprng)
            .expect("Proving should succeed.");
        assert!(
            verify_com_ineq(&com_key, &cmm_1, pub_value, &proof),
            "Incorrect inequality proof."
        );
    }

    #[test]
    fn test_com_ineq_soundness() {
        let mut csprng = rand::thread_rng();
        let com_key: CommitmentKey<_> = CommitmentKey::<G1>::generate(&mut csprng);

        // Generate a valid proof
        let value = Value::<G1>::new(Fr::from_str("20000102").unwrap());
        let pub_value = Fr::from_str("20000103").unwrap();
        let (cmm_1, value_tilde) = com_key.commit(&value, &mut csprng);
        let proof = prove_com_ineq(&com_key, &value, &value_tilde, pub_value, &mut csprng)
            .expect("Proving should succeed.");

        // Make the proof invalid by changing parameters
        let wrong_com_key = CommitmentKey::<G1>::generate(&mut csprng);
        let wrong_pub_value = Fr::from_str("20000102").unwrap();
        let wrong_proof = Witness {
            aux_com:          Commitment(G1::generate(&mut csprng)),
            com_mult_witness: proof.com_mult_witness.clone(),
        };

        // Verify failure for invalid parameters
        assert!(!verify_com_ineq(&wrong_com_key, &cmm_1, pub_value, &proof));
        assert!(!verify_com_ineq(&com_key, &cmm_1, wrong_pub_value, &proof));
        assert!(!verify_com_ineq(&com_key, &cmm_1, pub_value, &wrong_proof));

        // Proof generation should fail as committed value and public value are
        // identical.
        assert_eq!(
            prove_com_ineq(&com_key, &value, &value_tilde, wrong_pub_value, &mut csprng),
            None
        );
    }
}
