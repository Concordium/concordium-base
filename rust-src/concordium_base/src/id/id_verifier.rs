//! This module exposes functions for verifying various proofs of statements
//! about a credential on accounts.

use std::{borrow::Borrow, collections::BTreeMap};

use super::{types::*, utils};
use crate::bulletproofs::{
    range_proof::{verify_efficient, RangeProof, VerificationError},
    set_membership_proof::verify as verify_set_membership,
    set_non_membership_proof::verify as verify_set_non_membership,
    utils::Generators,
};

use super::{
    id_proof_types::*,
    sigma_protocols::{common::verify as sigma_verify, dlog::Dlog},
};
use crate::{
    curve_arithmetic::Curve,
    pedersen_commitment::{
        Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
    },
    random_oracle::RandomOracle,
};
use ff::Field;
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
    keys.open(&s, r, c)
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
/// that `attribute-upper+2^n` and attribute-lower lie in `[0, 2^n)`.
/// For further details about this technique, see page 15 in <https://arxiv.org/pdf/1907.06381.pdf>.
#[allow(clippy::too_many_arguments)]
pub fn verify_attribute_range<C: Curve, AttributeType: Attribute<C::Scalar>>(
    version: &ProofVersion,
    transcript: &mut RandomOracle,
    keys: &PedersenKey<C>,
    gens: &Generators<C>,
    lower: &AttributeType,
    upper: &AttributeType,
    c: &Commitment<C>,
    proof: &RangeProof<C>,
) -> Result<(), VerificationError> {
    let a = lower.to_field_element();
    let b = upper.to_field_element();
    match version {
        ProofVersion::Version1 => {
            let mut transcript_v1 = RandomOracle::domain("attribute_range_proof");
            verify_attribute_range_helper(
                &ProofVersion::Version1,
                &mut transcript_v1,
                keys,
                gens,
                a,
                b,
                c,
                proof,
            )
        }
        ProofVersion::Version2 => {
            transcript.add_bytes(b"AttributeRangeProof");
            transcript.append_message(b"a", &a);
            transcript.append_message(b"b", &b);
            verify_attribute_range_helper(
                &ProofVersion::Version2,
                transcript,
                keys,
                gens,
                a,
                b,
                c,
                proof,
            )
        }
    }
}

/// Helper functionf for verifying range proofs.
#[allow(clippy::too_many_arguments)]
fn verify_attribute_range_helper<C: Curve>(
    version: &ProofVersion,
    transcript: &mut RandomOracle,
    keys: &PedersenKey<C>,
    gens: &Generators<C>,
    a: C::Scalar,
    b: C::Scalar,
    c: &Commitment<C>,
    proof: &RangeProof<C>,
) -> Result<(), VerificationError> {
    let zero_randomness = PedersenRandomness::<C>::zero();
    let com_a = keys.hide_worker(&a, &zero_randomness);
    let com_b = keys.hide_worker(&b, &zero_randomness);
    let two = C::scalar_from_u64(2);
    let two_n = two.pow([64]);
    let com_2n = keys.hide_worker(&two_n, &zero_randomness);
    let com_delta_minus_b_plus_2n = Commitment(c.0.minus_point(&com_b.0).plus_point(&com_2n.0));
    let com_delta_minus_a = Commitment(c.0.minus_point(&com_a.0));

    verify_efficient(
        version,
        transcript,
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
    hasher.update(challenge);
    let to_sign = &hasher.finalize();
    utils::verify_account_ownership_proof(&public_data.keys, public_data.threshold, proof, to_sign)
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> StatementWithContext<C, AttributeType> {
    /// Function for verifying a proof of a statement.
    /// The arguments are
    /// - `challenge` - slice to challenge bytes chosen by the verifier
    /// - `global` - the on-chain cryptographic parameters
    /// - `commitments` - the on-chain commitments of the relevant credential
    /// The function returns `true` if the statement is true.
    /// If the statement is false, the function returns false with overwhelming
    /// probability.
    pub fn verify(
        &self,
        version: &ProofVersion,
        challenge: &[u8],
        global: &GlobalContext<C>,
        commitments: &CredentialDeploymentCommitments<C>,
        proofs: &Proof<C, AttributeType>,
    ) -> bool {
        self.statement.verify(
            version,
            challenge,
            global,
            &self.credential,
            commitments,
            proofs,
        )
    }
}

impl<
        C: Curve,
        TagType: std::cmp::Ord + crate::common::Serialize,
        AttributeType: Attribute<C::Scalar>,
    > AtomicStatement<C, TagType, AttributeType>
{
    pub(crate) fn verify<Q: std::cmp::Ord + Borrow<TagType>>(
        &self,
        version: &ProofVersion,
        global: &GlobalContext<C>,
        transcript: &mut RandomOracle,
        cmm_attributes: &BTreeMap<Q, Commitment<C>>,
        proof: &AtomicProof<C, AttributeType>,
    ) -> bool {
        match (self, proof) {
            (
                AtomicStatement::RevealAttribute {
                    statement: RevealAttributeStatement { attribute_tag },
                },
                AtomicProof::RevealAttribute { attribute, proof },
            ) => {
                let maybe_com = cmm_attributes.get(attribute_tag);
                if let Some(com) = maybe_com {
                    // There is a commitment to the relevant attribute. We can then check the
                    // proof.
                    let x = attribute.to_field_element();
                    transcript.add_bytes(b"RevealAttributeDlogProof");
                    // x is known to the verifier and should go into the transcript
                    transcript.append_message(b"x", &x);
                    if let ProofVersion::Version2 = version {
                        transcript.append_message(b"keys", &global.on_chain_commitment_key);
                        transcript.append_message(b"C", &com);
                    }
                    let mut minus_x = x;
                    minus_x.negate();
                    let g_minus_x = global.on_chain_commitment_key.g.mul_by_scalar(&minus_x);
                    let public = com.plus_point(&g_minus_x);
                    let verifier = Dlog {
                        public,                                  // C g^-x = h^r
                        coeff: global.on_chain_commitment_key.h, // h
                    };
                    if !sigma_verify(transcript, &verifier, proof) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            (
                AtomicStatement::AttributeInRange { statement },
                AtomicProof::AttributeInRange { proof },
            ) => {
                let maybe_com = cmm_attributes.get(&statement.attribute_tag);
                if let Some(com) = maybe_com {
                    // There is a commitment to the relevant attribute. We can then check the
                    // proof.
                    if super::id_verifier::verify_attribute_range(
                        version,
                        transcript,
                        &global.on_chain_commitment_key,
                        global.bulletproof_generators(),
                        &statement.lower,
                        &statement.upper,
                        com,
                        proof,
                    )
                    .is_err()
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            (
                AtomicStatement::AttributeInSet { statement },
                AtomicProof::AttributeInSet { proof },
            ) => {
                let maybe_com = cmm_attributes.get(&statement.attribute_tag);
                if let Some(com) = maybe_com {
                    let attribute_vec: Vec<_> =
                        statement.set.iter().map(|x| x.to_field_element()).collect();
                    if verify_set_membership(
                        version,
                        transcript,
                        &attribute_vec,
                        com,
                        proof,
                        global.bulletproof_generators(),
                        &global.on_chain_commitment_key,
                    )
                    .is_err()
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            (
                AtomicStatement::AttributeNotInSet { statement },
                AtomicProof::AttributeNotInSet { proof },
            ) => {
                let maybe_com = cmm_attributes.get(&statement.attribute_tag);
                if let Some(com) = maybe_com {
                    let attribute_vec: Vec<_> =
                        statement.set.iter().map(|x| x.to_field_element()).collect();
                    if verify_set_non_membership(
                        version,
                        transcript,
                        &attribute_vec,
                        com,
                        proof,
                        global.bulletproof_generators(),
                        &global.on_chain_commitment_key,
                    )
                    .is_err()
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
        true
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Statement<C, AttributeType> {
    /// Function for verifying a proof of a statement.
    /// The arguments are
    /// - `challenge` - slice to challenge bytes chosen by the verifier
    /// - `global` - the on-chain cryptographic parameters
    /// - `credential` - the credential for which this statement applies
    /// - `commitments` - the on-chain commitments of the relevant credential
    /// The function returns `true` if the statement is true.
    /// If the statement is false, the function returns false with overwhelming
    /// probability.
    pub fn verify(
        &self,
        version: &ProofVersion,
        challenge: &[u8],
        global: &GlobalContext<C>,
        credential: &CredId<C>,
        commitments: &CredentialDeploymentCommitments<C>,
        proofs: &Proof<C, AttributeType>,
    ) -> bool {
        let mut transcript = RandomOracle::domain("Concordium ID2.0 proof");
        transcript.append_message(b"ctx", &global);
        transcript.add_bytes(challenge);
        transcript.append_message(b"credential", credential);
        if self.statements.len() != proofs.proofs.len() {
            return false;
        }
        for (statement, proof) in self.statements.iter().zip(proofs.proofs.iter()) {
            if !statement.verify(
                version,
                global,
                &mut transcript,
                &commitments.cmm_attributes,
                proof,
            ) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::types::{KeyIndex, KeyPair},
        id::{constants::AttributeKind, id_prover::*},
    };
    use pairing::bls12_381::G1;
    use rand::*;
    use std::{
        collections::{btree_map::BTreeMap, BTreeSet},
        convert::TryFrom,
        marker::PhantomData,
    };

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
            threshold: SignatureThreshold::TWO,
        };

        let pub_data = cred_data.get_cred_key_info();

        let reg_id: G1 = Curve::hash_to_group(b"some_bytes");
        let account_address = account_address_from_registration_id(&reg_id);
        let challenge = b"13549686546546546854651357687354";

        let proof = prove_ownership_of_account(&cred_data, account_address, challenge);

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
        let mut transcript = RandomOracle::domain("Test");
        let maybe_proof = prove_attribute_in_range(
            &ProofVersion::Version1,
            &mut transcript.split(),
            &mut thread_rng(),
            gens,
            &keys,
            &attribute,
            &lower,
            &upper,
            &randomness,
        );
        if let Some(proof) = maybe_proof {
            assert_eq!(
                verify_attribute_range(
                    &ProofVersion::Version1,
                    &mut transcript,
                    &keys,
                    gens,
                    &lower,
                    &upper,
                    &commitment,
                    &proof
                ),
                Ok(()),
                "Incorrect version 1 range proof."
            );
        } else {
            panic!("Failed to produce proof.");
        };
        let mut transcript = RandomOracle::domain("Test");
        let maybe_proof = prove_attribute_in_range(
            &ProofVersion::Version2,
            &mut transcript.split(),
            &mut thread_rng(),
            gens,
            &keys,
            &attribute,
            &lower,
            &upper,
            &randomness,
        );
        if let Some(proof) = maybe_proof {
            assert_eq!(
                verify_attribute_range(
                    &ProofVersion::Version2,
                    &mut transcript,
                    &keys,
                    gens,
                    &lower,
                    &upper,
                    &commitment,
                    &proof
                ),
                Ok(()),
                "Incorrect version 2 range proof."
            );
        } else {
            panic!("Failed to produce proof.");
        };
    }

    #[test]
    fn test_verify_attribute_in_range_shift_cheat() {
        let mut csprng = thread_rng();
        let global = GlobalContext::<G1>::generate(String::from("genesis_string"));
        let keys = global.on_chain_commitment_key;
        let gens = global.bulletproof_generators();
        let lower = AttributeKind("20000102".to_string());
        let attribute = AttributeKind("20000102".to_string());
        let upper = AttributeKind("20000103".to_string());
        let value = Value::<G1>::new(attribute.to_field_element());
        let (commitment, randomness) = keys.commit(&value, &mut csprng);
        let mut transcript = RandomOracle::domain("Test");
        let maybe_proof = prove_attribute_in_range(
            &ProofVersion::Version2,
            &mut transcript.split(),
            &mut thread_rng(),
            gens,
            &keys,
            &attribute,
            &lower,
            &upper,
            &randomness,
        );
        let lower_shifted = AttributeKind("20000107".to_string());
        let upper_shifted = AttributeKind("20000108".to_string());
        let five = G1::scalar_from_u64(5);
        let five_value: Value<G1> = Value::new(five);
        let five_com = keys.hide(&five_value, &PedersenRandomness::zero());
        let commitment_shifted = Commitment(commitment.0.plus_point(&five_com));
        if let Some(proof) = maybe_proof {
            assert_eq!(
                verify_attribute_range(
                    &ProofVersion::Version2,
                    &mut transcript,
                    &keys,
                    gens,
                    &lower_shifted,
                    &upper_shifted,
                    &commitment_shifted,
                    &proof
                )
                .is_ok(),
                false,
                "Shifting statement and commitment using same proof should fail."
            );
        } else {
            panic!("Failed to produce proof.");
        };
    }

    // For testing purposes
    struct TestRandomness {
        randomness: BTreeMap<AttributeTag, PedersenRandomness<G1>>,
    }

    impl HasAttributeRandomness<G1> for TestRandomness {
        type ErrorType = ImpossibleError;

        fn get_attribute_commitment_randomness(
            &self,
            attribute_tag: AttributeTag,
        ) -> Result<PedersenRandomness<G1>, Self::ErrorType> {
            match self.randomness.get(&attribute_tag) {
                Some(r) => Ok(r.clone()),
                _ => {
                    let mut csprng = rand::thread_rng();
                    Ok(PedersenRandomness::generate(&mut csprng))
                }
            }
        }
    }

    #[test]
    fn test_verify_id_attributes_proofs() {
        let point: G1 = Curve::hash_to_group(b"some_bytes");
        let cmm_prf = Commitment(point);
        let cmm_max_accounts = Commitment(point);
        let cmm_cred_counter = Commitment(point);
        let attribute_name = AttributeKind(String::from("Foo")); // first name
        let attribute_country = AttributeKind(String::from("DK")); // country
        let attribute_dob = AttributeKind(String::from("19970505")); // dob
        let attribute_doc_expiry = AttributeKind(String::from("20250505")); // doc expiry

        // Reveal first name
        let reveal_statement = RevealAttributeStatement {
            attribute_tag: AttributeTag::from(0u8),
        };

        // Country (not) in set
        let dk = AttributeKind(String::from("DK"));
        let no = AttributeKind(String::from("NO"));
        let se = AttributeKind(String::from("SE"));
        let de = AttributeKind(String::from("DE"));
        let uk = AttributeKind(String::from("UK"));
        let set = BTreeSet::from([dk, no, se, de.clone(), uk.clone()]);
        let set2 = BTreeSet::from([de, uk]);
        let set_statement = AttributeInSetStatement::<G1, _, AttributeKind> {
            attribute_tag: AttributeTag::from(4u8),
            _phantom:      PhantomData::default(),
            set:           set.clone(),
        };

        // DOB in range
        let range_statement = AttributeInRangeStatement {
            attribute_tag: AttributeTag::from(3u8),
            lower:         AttributeKind(String::from("19950505")),
            upper:         AttributeKind(String::from("19990505")),
            _phantom:      PhantomData::default(),
        };

        // full statement
        let full_statement = StatementWithContext {
            credential: point,
            statement:  Statement {
                statements: vec![
                    AtomicStatement::RevealAttribute {
                        statement: reveal_statement,
                    },
                    AtomicStatement::AttributeInSet {
                        statement: set_statement,
                    },
                    AtomicStatement::AttributeInRange {
                        statement: range_statement,
                    },
                ],
            },
        };

        // Some other statements constructed using helper functions
        let statement2 = Statement::new()
            .older_than(18)
            .unwrap()
            .younger_than(35)
            .unwrap()
            .residence_in(set)
            .unwrap()
            .residence_not_in(set2)
            .unwrap()
            .doc_expiry_no_earlier_than(AttributeKind(String::from("20240304")))
            .unwrap();
        let full_statement2 = StatementWithContext {
            credential: point,
            statement:  statement2,
        };

        // Commitments and secret randomness
        let mut csprng = rand::thread_rng();
        let global = GlobalContext::generate(String::from("Some genesis string"));
        let keys = global.on_chain_commitment_key;
        // the commitments the user will prove stuff about. The commitments are
        // on-chain, the randomness is only known to the user.
        let (name_com, name_randomness) = keys.commit(
            &Value::<G1>::new(attribute_name.to_field_element()),
            &mut csprng,
        );
        let (country_com, country_randomness) = keys.commit(
            &Value::<G1>::new(attribute_country.to_field_element()),
            &mut csprng,
        );
        let (dob_com, dob_randomness) = keys.commit(
            &Value::<G1>::new(attribute_dob.to_field_element()),
            &mut csprng,
        );
        let (expiry_com, expiry_randomness) = keys.commit(
            &Value::<G1>::new(attribute_doc_expiry.to_field_element()),
            &mut csprng,
        );

        // the attribute list
        let mut alist = BTreeMap::new();
        alist.insert(AttributeTag::from(0u8), attribute_name);
        alist.insert(AttributeTag::from(3u8), attribute_dob);
        alist.insert(AttributeTag::from(4u8), attribute_country);
        alist.insert(AttributeTag::from(10u8), attribute_doc_expiry);

        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        let attribute_list: AttributeList<_, AttributeKind> = AttributeList {
            valid_to,
            created_at,
            max_accounts: 237,
            alist,
            _phantom: Default::default(),
        };

        // the commitment randomness in a map so it can be looked up when relevant.
        let mut randomness = BTreeMap::new();
        randomness.insert(AttributeTag::from(0u8), name_randomness);
        randomness.insert(AttributeTag::from(3u8), dob_randomness);
        randomness.insert(AttributeTag::from(4u8), country_randomness);
        randomness.insert(AttributeTag::from(10u8), expiry_randomness);

        let attribute_randomness = TestRandomness { randomness };

        // Construct proof of statement from secret
        let challenge = [0u8; 32]; // verifiers challenge
        let proof = full_statement.prove(
            &ProofVersion::Version1,
            &global,
            &challenge,
            &attribute_list,
            &attribute_randomness,
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();

        // Prove the second statement
        let challenge2 = [1u8; 32]; // verifiers challenge
        let proof2 = full_statement2.prove(
            &ProofVersion::Version1,
            &global,
            &challenge2,
            &attribute_list,
            &attribute_randomness,
        );
        assert!(proof2.is_some());
        let proof2 = proof2.unwrap();

        // On chain there is a credential with the commitments
        let mut alist = BTreeMap::new();
        alist.insert(AttributeTag::from(0u8), name_com); // first name
        alist.insert(AttributeTag::from(3u8), dob_com); // dob
        alist.insert(AttributeTag::from(4u8), country_com); // country
        alist.insert(AttributeTag::from(10u8), expiry_com); // id doc expiry

        let coms = CredentialDeploymentCommitments {
            cmm_prf,
            cmm_max_accounts,
            cmm_id_cred_sec_sharing_coeff: vec![],
            cmm_cred_counter,
            cmm_attributes: alist, // The relevant values
        };

        // the verifier uses these commitments to verify the proofs

        let result =
            full_statement.verify(&ProofVersion::Version1, &challenge, &global, &coms, &proof);
        assert!(result, "Version 1 statement should verify.");
        let result2 = full_statement2.verify(
            &ProofVersion::Version1,
            &challenge2,
            &global,
            &coms,
            &proof2,
        );
        assert!(result2, "Version 1 statement 2 should verify.");

        // Version 2 proofs
        let proof = full_statement.prove(
            &ProofVersion::Version2,
            &global,
            &challenge,
            &attribute_list,
            &attribute_randomness,
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();

        // Prove the second statement
        let proof2 = full_statement2.prove(
            &ProofVersion::Version2,
            &global,
            &challenge2,
            &attribute_list,
            &attribute_randomness,
        );
        assert!(proof2.is_some());
        let proof2 = proof2.unwrap();

        let result =
            full_statement.verify(&ProofVersion::Version2, &challenge, &global, &coms, &proof);
        assert!(result, "Version 2 statement should verify.");
        let result2 = full_statement2.verify(
            &ProofVersion::Version2,
            &challenge2,
            &global,
            &coms,
            &proof2,
        );
        assert!(result2, "Version 2 statement 2 should verify.");
    }
}
