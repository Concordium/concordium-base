use crate::{types::*, utils};
use bulletproofs::range_proof::{verify_efficient, Generators, RangeProof};
use curve_arithmetic::Curve;
use ff::Field;
use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey as PedersenKey,
    randomness::Randomness as PedersenRandomness, value::Value,
};
use random_oracle::RandomOracle;
use sha2::{Digest, Sha256};

pub fn verify_attribute<C: Curve, AttributeType: Attribute<C::Scalar>>(
    keys: &PedersenKey<C>,
    attribute: &AttributeType,
    r: &PedersenRandomness<C>,
    c: &Commitment<C>,
) -> bool {
    let s = Value::new(attribute.to_field_element());
    keys.open(&s, &r, &c)
}

pub fn verify_attribute_range<C: Curve, AttributeType: Attribute<C::Scalar>>(
    keys: &PedersenKey<C>,
    gens: &Generators<C>,
    lower: &AttributeType,
    upper: &AttributeType,
    c: &Commitment<C>,
    proof: &RangeProof<C>,
) -> bool {
    let mut transcript = RandomOracle::domain("attribute_range_proof");
    let a = lower.to_field_element();
    let b = upper.to_field_element();
    let zero_randomness = PedersenRandomness::<C>::new(C::Scalar::zero());
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
    .is_ok()
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
    use crate::id_prover::*;
    use crypto_common::{serde_impls::KeyPairDef, types::KeyIndex};
    use pairing::bls12_381::G1;
    use rand::*;
    use std::collections::btree_map::BTreeMap;

    #[test]
    fn test_verify_account_ownership() {
        let mut csprng = thread_rng();

        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPairDef::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPairDef::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPairDef::generate(&mut csprng));
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
}
