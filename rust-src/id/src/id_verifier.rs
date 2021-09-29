use crate::{types::*, utils};
use bulletproofs::range_proof::{verify_efficient, Generators, RangeProof, VerificationError};
use curve_arithmetic::Curve;
use ff::Field;
use pedersen_scheme::{
    Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
};
use random_oracle::RandomOracle;
use sha2::{Digest, Sha256};

/// Function for opening an attribute inside a commitment. The arguments are
/// - keys - the commitments keys used to commit to the attribute
/// - attribute - the attribute claimed to be inside the commitment
/// - r - the randomness used to commit
/// - c - the commitment
///
/// The function outputs a bool, indicicating whether the commitment contains
/// the given attribute.
pub fn verify_attribute<C: Curve, AttributeType: Attribute<C::Scalar>>(
    keys: &PedersenKey<C>,
    attribute: &AttributeType,
    r: &PedersenRandomness<C>,
    c: &Commitment<C>,
) -> bool {
    let s = Value::new(attribute.to_field_element());
    keys.open(&s, &r, &c)
}

/// Function for verifying a range proof about an attribute inside a commitment.
/// The arguments are
/// - keys - the commitments keys used to commit to the attribute
/// - gens - the bulletproof generators needed for range proofs
/// - lower - the lower bound of the range
/// - upper - the upper bound of the range
/// - c - the commitment to the attribute
/// - proof - the range proof about the attribute inside the commitment
///
/// The function outputs a bool, indicating whether the proof is correct or not,
/// i.e., wether is attribute inside the commitment lies in [lower,upper).
/// This is done by verifying that the attribute inside the commitment satisfies
/// that attribute-upper+2^n and attribute-lower lie in [0, 2^n).
/// For further details about this technique, see page 15 in https://arxiv.org/pdf/1907.06381.pdf.
pub fn verify_attribute_range<C: Curve, AttributeType: Attribute<C::Scalar>>(
    keys: &PedersenKey<C>,
    gens: &Generators<C>,
    lower: &AttributeType,
    upper: &AttributeType,
    c: &Commitment<C>,
    proof: &RangeProof<C>,
) -> Result<(), VerificationError> {
    let mut transcript = RandomOracle::domain("attribute_range_proof");
    let a = lower.to_field_element();
    let b = upper.to_field_element();
    let zero_randomness = PedersenRandomness::<C>::zero();
    let com_a = keys.hide_worker(&a, &zero_randomness);
    let com_b = keys.hide_worker(&b, &zero_randomness);
    let two = C::scalar_from_u64(2);
    let two_n = two.pow(&[64]);
    let com_2n = keys.hide_worker(&two_n, &zero_randomness);
    let com_delta_minus_b_plus_2n = Commitment(c.0.minus_point(&com_b.0).plus_point(&com_2n.0));
    let com_delta_minus_a = Commitment(c.0.minus_point(&com_a.0));

    verify_efficient(
        &mut transcript,
        64,
        &[com_delta_minus_b_plus_2n, com_delta_minus_a],
        proof,
        gens,
        keys,
    )
}

/// Function for verifying account ownership. The arguments are
/// - public_data - the public keys (and threshold) of the prover. These should
///   be read from chain by looking up the account. If they are not present on
///   chain, the verifier should reject the proof.
/// - account - the account address of the account that the prover claims to
///   own.
/// - challenge - the challenge that the verifier gave to the prover.
/// - proof - the prover's proof.
///
/// The function outputs a bool, indicating whether the proof is correct or not,
/// i.e., it checks the signatures inside the proof.
pub fn verify_account_ownership(
    public_data: &CredentialPublicKeys,
    account: AccountAddress,
    challenge: &[u8],
    proof: &AccountOwnershipProof,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(account.0);
    hasher.update([0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    hasher.update(b"account_ownership_proof");
    hasher.update(&challenge);
    let to_sign = &hasher.finalize();
    utils::verify_account_ownership_proof(&public_data.keys, public_data.threshold, &proof, to_sign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::AttributeKind, id_prover::*};
    use crypto_common::types::{KeyIndex, KeyPair};
    use pairing::bls12_381::G1;
    use rand::*;
    use std::collections::btree_map::BTreeMap;

    #[test]
    fn test_verify_account_ownership() {
        let mut csprng = thread_rng();

        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };

        let pub_data = cred_data.get_cred_key_info();

        let reg_id: G1 = Curve::hash_to_group(b"some_bytes");
        let account_address = AccountAddress::new(&reg_id);
        let challenge = b"13549686546546546854651357687354";

        let proof = prove_ownership_of_account(cred_data, account_address, challenge);

        assert!(verify_account_ownership(
            &pub_data,
            account_address,
            challenge,
            &proof
        ));
    }

    #[test]
    fn test_verify_attribute() {
        let mut csprng = thread_rng();
        let keys = PedersenKey::<G1>::generate(&mut csprng);
        let attribute = AttributeKind("some attribute value".to_string());
        let value = Value::<G1>::new(attribute.to_field_element());
        let (commitment, randomness) = keys.commit(&value, &mut csprng);

        assert!(
            verify_attribute(&keys, &attribute, &randomness, &commitment),
            "Incorrect opening of attribute."
        );
    }

    #[test]
    fn test_verify_attribute_in_range() {
        let mut csprng = thread_rng();
        let global = GlobalContext::<G1>::generate(String::from("genesis_string"));
        let keys = global.on_chain_commitment_key;
        let gens = global.bulletproof_generators();
        let lower = AttributeKind("20000102".to_string());
        let attribute = AttributeKind("20000102".to_string());
        let upper = AttributeKind("20000103".to_string());
        let value = Value::<G1>::new(attribute.to_field_element());
        let (commitment, randomness) = keys.commit(&value, &mut csprng);
        let maybe_proof =
            prove_attribute_in_range(&gens, &keys, &attribute, &lower, &upper, &randomness);
        if let Some(proof) = maybe_proof {
            assert_eq!(
                verify_attribute_range(&keys, &gens, &lower, &upper, &commitment, &proof),
                Ok(()),
                "Incorrect range proof."
            );
        } else {
            assert!(false, "Failed to produce proof.");
        };
    }
}
