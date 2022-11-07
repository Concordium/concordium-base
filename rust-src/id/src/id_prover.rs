//! This module exposes functions for proving statements about credentials on
//! accounts.

use crate::{
    id_proof_types::*,
    sigma_protocols::{
        common::prove as sigma_prove,
        dlog::{Dlog, DlogSecret},
    },
    types::*,
};
use bulletproofs::{
    range_proof::{prove_given_scalars, RangeProof},
    set_membership_proof::prove as prove_set_membership,
    set_non_membership_proof::prove as prove_set_non_membership,
    utils::Generators,
};
use curve_arithmetic::{Curve, Value};
use ed25519_dalek as ed25519;
use ff::Field;
use pedersen_scheme::{CommitmentKey as PedersenKey, Randomness as PedersenRandomness};
use random_oracle::RandomOracle;
use sha2::{Digest, Sha256};

/// Function for producing a proof of a statement.
/// The arguments are
/// - `global` - the on-chain cryptographic parameters
/// - `challenge` - slice to challenge bytes chosen by the verifier
/// - `secret` - the secret data needed to produce the proof
/// Upon success the function will return a proof of the statement
/// wrapped in a `Some`. Otherwise it returns `None`.
impl<C: Curve, AttributeType: Attribute<C::Scalar>> StatementWithContext<C, AttributeType> {
    pub fn prove(
        self,
        global: &GlobalContext<C>,
        challenge: &[u8],
        secret: Secret<C, AttributeType>,
    ) -> Option<Proof<C, AttributeType>> {
        if self.statement.statements.len() != secret.secrets.len() {
            return None;
        }
        let mut proofs: Vec<AtomicProof<C, AttributeType>> =
            Vec::with_capacity(self.statement.statements.len());

        let mut transcript = RandomOracle::domain("id_attribute_proofs");
        transcript.add_bytes(challenge);
        transcript.append_message(b"accountAddress", &self.account);
        transcript.append_message(b"credential", &self.credential);
        let mut csprng = rand::thread_rng();
        for (statement, secret) in self
            .statement
            .statements
            .into_iter()
            .zip(secret.secrets.into_iter())
        {
            match (statement, secret) {
                (AtomicStatement::RevealAttribute { statement }, (attribute, randomness)) => {
                    let x = attribute.to_field_element(); // This is public in the sense that the verifier should learn it
                    transcript.add_bytes(b"RevealAttributeDlogProof");
                    transcript.append_message(b"x", &x);
                    // This is the Dlog proof section 9.2.4 from the Bluepaper.
                    let h = global.on_chain_commitment_key.h;
                    let h_r = h.mul_by_scalar(&randomness);
                    let prover = Dlog {
                        public: h_r, // C g^-x = h^r
                        coeff:  h,   // h
                    };
                    let secret = DlogSecret {
                        secret: Value::new(*randomness),
                    };
                    let proof = sigma_prove(&mut transcript, &prover, secret, &mut csprng)?;
                    proofs.push(AtomicProof::RevealAttribute {
                        attribute_tag: statement.attribute_tag,
                        attribute,
                        proof,
                    });
                }
                (AtomicStatement::AttributeInSet { statement }, (attribute, randomness)) => {
                    let attribute_scalar = attribute.to_field_element();
                    let attribute_vec: Vec<_> =
                        statement.set.iter().map(|x| x.to_field_element()).collect();
                    let proof = prove_set_membership(
                        &mut transcript,
                        &mut csprng,
                        &attribute_vec,
                        attribute_scalar,
                        global.bulletproof_generators(),
                        &global.on_chain_commitment_key,
                        &randomness,
                    )
                    .ok()?;
                    let proof = AtomicProof::AttributeInSet { statement, proof };
                    proofs.push(proof);
                }
                (AtomicStatement::AttributeNotInSet { statement }, (attribute, randomness)) => {
                    let attribute_scalar = attribute.to_field_element();
                    let attribute_vec: Vec<_> =
                        statement.set.iter().map(|x| x.to_field_element()).collect();
                    let proof = prove_set_non_membership(
                        &mut transcript,
                        &mut csprng,
                        &attribute_vec,
                        attribute_scalar,
                        global.bulletproof_generators(),
                        &global.on_chain_commitment_key,
                        &randomness,
                    )
                    .ok()?;
                    let proof = AtomicProof::AttributeNotInSet { statement, proof };
                    proofs.push(proof);
                }
                (AtomicStatement::AttributeInRange { statement }, (attribute, randomness)) => {
                    let proof = prove_attribute_in_range(
                        global.bulletproof_generators(),
                        &global.on_chain_commitment_key,
                        &attribute,
                        &statement.lower,
                        &statement.upper,
                        &randomness,
                    )?;
                    let proof = AtomicProof::AttributeInRange { statement, proof };
                    proofs.push(proof);
                }
            }
        }
        let account = self.account;
        let credential = self.credential;
        Some(Proof {
            account,
            credential,
            proofs,
        })
    }
}

/// Function for proving ownership of an account. The parameters are
/// - data - the CredentialData containing the private keys of the prover
/// - account - the account address of the account that the prover claims to own
/// - challenge - a challenge produced by the verifier
///
/// The function outputs a proof consisting of signatures on the SHA266 hash of
/// - the account address
/// - 0 written as an u64 integer, i.e., eight 0u8's
/// - the challenge from the verifier
///
/// The reason that the 0's are hashed is to make sure that the hash that is
/// signed cannot coincide with a hash of transaction. When hashing a
/// transaction, the bytestring that is hashed begins with the account address
/// followed by the nonce. For a transaction to be valid, the nonce must be > 0,
/// so by hashing 0 in function below, we are sure that what is signed does not
/// coincide with the hash of a transaction (assuming that SHA256 is
/// collision-resistant).
pub fn prove_ownership_of_account(
    data: &CredentialData,
    account: AccountAddress,
    challenge: &[u8],
) -> AccountOwnershipProof {
    let mut hasher = Sha256::new();
    hasher.update(account.0);
    hasher.update([0u8; 8]);
    hasher.update(b"account_ownership_proof");
    hasher.update(&challenge);
    let to_sign = &hasher.finalize();
    let sigs = data
        .keys
        .iter()
        .map(|(&idx, kp)| {
            let expanded_sk = ed25519::ExpandedSecretKey::from(&kp.secret);
            (idx, expanded_sk.sign(to_sign, &kp.public).into())
        })
        .collect();
    AccountOwnershipProof { sigs }
}

/// Function for proving that an attribute inside a commitment is in a range of
/// the form [a,b). The parameters are
/// - gens - the bulletproof generators needed for range proofs
/// - keys - the commitments keys used to commit to the attribute
/// - attribute - the attribute inside the commitment
/// - lower - the lower bound of the range
/// - upper - the upper bound of the range
///
/// The function outputs a proof that the attribute is in the given range, i.e.
/// that lower <= attribute < upper.
/// This is done by proving that attribute-upper+2^n and attribute-lower lie in
/// [0, 2^n). For further details about this technique, see page 15 in https://arxiv.org/pdf/1907.06381.pdf.
pub fn prove_attribute_in_range<C: Curve, AttributeType: Attribute<C::Scalar>>(
    gens: &Generators<C>,
    keys: &PedersenKey<C>,
    attribute: &AttributeType,
    lower: &AttributeType,
    upper: &AttributeType,
    r: &PedersenRandomness<C>,
) -> Option<RangeProof<C>> {
    let mut transcript = RandomOracle::domain("attribute_range_proof");
    let mut csprng = rand::thread_rng();
    let delta = attribute.to_field_element();
    let a = lower.to_field_element();
    let b = upper.to_field_element();
    let mut scalar1 = delta;
    let two = C::scalar_from_u64(2);
    let two_n = two.pow(&[64]);
    scalar1.add_assign(&two_n);
    scalar1.sub_assign(&b);
    let mut scalar2 = delta;
    scalar2.sub_assign(&a);
    let rand1 = r.clone();
    let rand2 = r.clone();
    prove_given_scalars(
        &mut transcript,
        &mut csprng,
        64,
        2,
        &[scalar1, scalar2],
        gens,
        keys,
        &[rand1, rand2],
    )
}
