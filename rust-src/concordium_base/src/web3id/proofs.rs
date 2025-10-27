use crate::random_oracle::StructuredDigest;
use crate::{
    curve_arithmetic::Curve,
    id::types::{Attribute, GlobalContext},
    pedersen_commitment,
    random_oracle::RandomOracle,
};

use crate::web3id::{
    Challenge, CommitmentInputs, CredentialHolderId, CredentialProof, CredentialStatement,
    CredentialsInputs, LinkingProof, Presentation, PresentationVerificationError, ProofError,
    ProofMetadata, Request, SignedCommitments, WeakLinkingProof, Web3IdSigner,
    COMMITMENT_SIGNATURE_DOMAIN_STRING, LINKING_DOMAIN_STRING,
};
use ed25519_dalek::Verifier;

use crate::cis4_types::IssuerKey;
use crate::curve_arithmetic::Pairing;
use crate::id::id_proof_types::{AtomicStatement, ProofVersion};
use crate::id::identity_attributes_credentials;
use crate::id::identity_attributes_credentials::IdentityAttributeHandling;
use crate::id::types::{IdentityAttribute, IpContextOnly};
use concordium_contracts_common::ContractAddress;
use std::collections::BTreeMap;

/// Append a `web3id::Challenge` to the state of the random oracle.
/// Newly added challenge variants should use a tag/version, as well as labels for each struct field
/// as domain name separators to ensure every part of the challenge is accounted for.
/// Each challenge variant should contribute uniquely to the random oracle.
fn append_challenge(digest: &mut impl StructuredDigest, challenge: &Challenge) {
    match challenge {
        Challenge::Sha256(hash_bytes) => {
            // No tag/version `V0` is added to be backward compatible with old proofs and requests.
            digest.add_bytes(hash_bytes);
        }
        Challenge::V1(context) => {
            // A zero sha256 hash is prepended to ensure this output
            // is different to any `Sha256` challenge.
            digest.add_bytes([0u8; 32]);
            // Add tag/version `V1` to the random oracle.
            digest.add_bytes("V1");
            digest.add_bytes("Context");
            digest.append_message("given", &context.given);
            digest.append_message("requested", &context.requested);
        }
    }
}

impl<C: Curve> SignedCommitments<C> {
    /// Verify signatures on the commitments in the context of the holder's
    /// public key, and the issuer contract.
    pub fn verify_signature(
        &self,
        holder: &CredentialHolderId,
        issuer_pk: &IssuerKey,
        issuer_contract: ContractAddress,
    ) -> bool {
        use crate::common::Serial;
        let mut data = COMMITMENT_SIGNATURE_DOMAIN_STRING.to_vec();
        holder.serial(&mut data);
        issuer_contract.serial(&mut data);
        self.commitments.serial(&mut data);
        issuer_pk.public_key.verify(&data, &self.signature).is_ok()
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    Presentation<P, C, AttributeType>
{
    /// Get an iterator over the metadata for each of the verifiable credentials
    /// in the order they appear in the presentation.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = ProofMetadata> + '_ {
        self.verifiable_credential.iter().map(|cp| cp.metadata())
    }

    /// Verify a presentation in the context of the provided public data and
    /// cryptographic parameters.
    ///
    /// In case of success returns the [`Request`] for which the presentation
    /// verifies.
    ///
    /// **NB:** This only verifies the cryptographic consistentcy of the data.
    /// It does not check metadata, such as expiry. This should be checked
    /// separately by the verifier.
    pub fn verify<'a>(
        &self,
        params: &GlobalContext<C>,
        public: impl ExactSizeIterator<Item = &'a CredentialsInputs<P, C>>,
    ) -> Result<Request<C, AttributeType>, PresentationVerificationError> {
        let mut transcript = RandomOracle::domain("ConcordiumWeb3ID");
        append_challenge(&mut transcript, &self.presentation_context);
        transcript.append_message(b"ctx", &params);

        let mut request = Request {
            challenge: self.presentation_context.clone(),
            credential_statements: Vec::new(),
        };

        // Compute the data that the linking proof signed.
        let to_sign =
            linking_proof_message_to_sign(&self.presentation_context, &self.verifiable_credential);

        let mut linking_proof_iter = self.linking_proof.proof_value.iter();

        if public.len() != self.verifiable_credential.len() {
            return Err(PresentationVerificationError::InconsistentPublicData);
        }

        for (cred_public, cred_proof) in public.zip(&self.verifiable_credential) {
            request.credential_statements.push(cred_proof.statement());
            if let CredentialProof::Web3Id { holder: owner, .. } = &cred_proof {
                let Some(sig) = linking_proof_iter.next() else {
                    return Err(PresentationVerificationError::MissingLinkingProof);
                };
                if owner.public_key.verify(&to_sign, &sig.signature).is_err() {
                    return Err(PresentationVerificationError::InvalidLinkinProof);
                }
            }
            if !verify_single_credential(params, &mut transcript, cred_proof, cred_public) {
                return Err(PresentationVerificationError::InvalidCredential);
            }
        }

        // No bogus signatures should be left.
        if linking_proof_iter.next().is_none() {
            Ok(request)
        } else {
            Err(PresentationVerificationError::ExcessiveLinkingProof)
        }
    }
}

/// Verify a single credential. This only checks the cryptographic parts and
/// ignores the metadata such as issuance date.
fn verify_single_credential<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    global: &GlobalContext<C>,
    transcript: &mut RandomOracle,
    cred_proof: &CredentialProof<P, C, AttributeType>,
    public: &CredentialsInputs<P, C>,
) -> bool {
    match (&cred_proof, public) {
        (
            CredentialProof::Account {
                network: _,
                cred_id: _,
                proofs,
                created: _,
                issuer: _,
            },
            CredentialsInputs::Account { commitments },
        ) => {
            for (statement, proof) in proofs.iter() {
                if !statement.verify(
                    ProofVersion::Version2,
                    global,
                    transcript,
                    commitments,
                    proof,
                ) {
                    return false;
                }
            }
        }
        (
            CredentialProof::Identity {
                proofs,
                id_attr_cred_info,
                ..
            },
            CredentialsInputs::Identity { ip_info, ars_infos },
        ) => {
            if !identity_attributes_credentials::verify_identity_attributes(
                global,
                IpContextOnly {
                    ip_info,
                    ars_infos: &ars_infos.anonymity_revokers,
                },
                id_attr_cred_info,
                transcript,
            )
            .is_ok()
            {
                return false;
            }

            let cmm_attributes: BTreeMap<_, _> = id_attr_cred_info
                .values
                .attributes
                .iter()
                .filter_map(|(tag, attr)| match attr {
                    IdentityAttribute::Committed(cmm) => Some((*tag, cmm.clone())),
                    _ => None,
                })
                .collect();

            for (statement, proof) in proofs.iter() {
                if !statement.verify(
                    ProofVersion::Version2,
                    global,
                    transcript,
                    &cmm_attributes,
                    proof,
                ) {
                    return false;
                }
            }
        }
        (
            CredentialProof::Web3Id {
                network: _proof_network,
                contract: proof_contract,
                commitments,
                proofs,
                created: _,
                holder: owner,
                ty: _,
            },
            CredentialsInputs::Web3 { issuer_pk },
        ) => {
            if !commitments.verify_signature(owner, issuer_pk, *proof_contract) {
                return false;
            }
            for (statement, proof) in proofs.iter() {
                if !statement.verify(
                    ProofVersion::Version2,
                    global,
                    transcript,
                    &commitments.commitments,
                    proof,
                ) {
                    return false;
                }
            }
        }
        _ => return false, // mismatch in data
    }
    true
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialStatement<C, AttributeType> {
    fn prove<P: Pairing<ScalarField = C::Scalar>, Signer: Web3IdSigner>(
        self,
        global: &GlobalContext<C>,
        ro: &mut RandomOracle,
        csprng: &mut impl rand::Rng,
        input: CommitmentInputs<P, C, AttributeType, Signer>,
    ) -> Result<CredentialProof<P, C, AttributeType>, ProofError> {
        match (self, input) {
            (
                CredentialStatement::Account {
                    network,
                    cred_id,
                    statement,
                },
                CommitmentInputs::Account {
                    values,
                    randomness,
                    issuer,
                },
            ) => {
                let mut proofs = Vec::new();
                for statement in statement {
                    let proof = statement
                        .prove(
                            ProofVersion::Version2,
                            global,
                            ro,
                            csprng,
                            values,
                            randomness,
                        )
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let created = chrono::Utc::now();
                Ok(CredentialProof::Account {
                    cred_id,
                    proofs,
                    network,
                    created,
                    issuer,
                })
            }
            (
                CredentialStatement::Identity {
                    network, statement, ..
                },
                CommitmentInputs::Identity {
                    ip_context,
                    id_object,
                    id_object_use_data,
                },
            ) => {
                let attributes_handling: BTreeMap<_, _> = statement
                    .iter()
                    .map(|stmt| match stmt {
                        AtomicStatement::RevealAttribute { statement } => {
                            (statement.attribute_tag, IdentityAttributeHandling::Commit)
                        }
                        AtomicStatement::AttributeInRange { statement } => {
                            (statement.attribute_tag, IdentityAttributeHandling::Commit)
                        }
                        AtomicStatement::AttributeInSet { statement } => {
                            (statement.attribute_tag, IdentityAttributeHandling::Commit)
                        }
                        AtomicStatement::AttributeNotInSet { statement } => {
                            (statement.attribute_tag, IdentityAttributeHandling::Commit)
                        }
                    })
                    .collect();

                let (id_attr_cred_info, id_attr_cmm_rand) =
                    identity_attributes_credentials::prove_identity_attributes(
                        global,
                        ip_context,
                        id_object,
                        id_object_use_data,
                        &attributes_handling,
                        ro,
                    )
                    .expect("todo");

                let mut proofs = Vec::new();
                for statement in statement {
                    let proof = statement
                        .prove(
                            ProofVersion::Version2,
                            global,
                            ro,
                            csprng,
                            &id_object.get_attribute_list().alist,
                            &id_attr_cmm_rand.attributes_rand,
                        )
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let created = chrono::Utc::now();
                Ok(CredentialProof::Identity {
                    proofs,
                    network,
                    created,
                    id_attr_cred_info,
                })
            }
            (
                CredentialStatement::Web3Id {
                    network,
                    contract,
                    credential,
                    statement,
                    ty,
                },
                CommitmentInputs::Web3Issuer {
                    signature,
                    values,
                    randomness,
                    signer,
                },
            ) => {
                let mut proofs = Vec::new();
                if credential != signer.id().into() {
                    return Err(ProofError::InconsistentIds);
                }
                if values.len() != randomness.len() {
                    return Err(ProofError::InconsistentValuesAndRandomness);
                }

                // We use the same commitment key to commit to values for all the different
                // attributes. TODO: This is not ideal, but is probably fine
                // since the tags are signed as well, so you cannot switch one
                // commitment for another. We could instead use bulletproof generators, that
                // would be cleaner.
                let cmm_key = &global.on_chain_commitment_key;

                let mut commitments = BTreeMap::new();
                for ((vi, value), (ri, randomness)) in values.iter().zip(randomness.iter()) {
                    if vi != ri {
                        return Err(ProofError::InconsistentValuesAndRandomness);
                    }
                    commitments.insert(
                        ri.clone(),
                        cmm_key.hide(
                            &pedersen_commitment::Value::<C>::new(value.to_field_element()),
                            randomness,
                        ),
                    );
                }
                // TODO: For better user experience/debugging we could check the signature here.
                let commitments = SignedCommitments {
                    signature,
                    commitments,
                };
                for statement in statement {
                    let proof = statement
                        .prove(
                            ProofVersion::Version2,
                            global,
                            ro,
                            csprng,
                            values,
                            randomness,
                        )
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let created = chrono::Utc::now();
                Ok(CredentialProof::Web3Id {
                    commitments,
                    proofs,
                    network,
                    contract,
                    created,
                    holder: signer.id().into(),
                    ty,
                })
            }
            _ => Err(ProofError::CommitmentsStatementsMismatch),
        }
    }
}

fn linking_proof_message_to_sign<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    challenge: &Challenge,
    proofs: &[CredentialProof<P, C, AttributeType>],
) -> Vec<u8> {
    use crate::common::Serial;
    use sha2::Digest;
    // hash the context and proof.
    let mut out = sha2::Sha512::new();
    append_challenge(&mut out, challenge);
    proofs.serial(&mut out);
    let mut msg = LINKING_DOMAIN_STRING.to_vec();
    msg.extend_from_slice(&out.finalize());
    msg
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Request<C, AttributeType> {
    /// Construct a proof for the [`Request`] using the provided cryptographic
    /// parameters and secrets.
    pub fn prove<'a, P: Pairing<ScalarField = C::Scalar>, Signer: 'a + Web3IdSigner>(
        self,
        params: &GlobalContext<C>,
        attrs: impl ExactSizeIterator<Item = CommitmentInputs<'a, P, C, AttributeType, Signer>>,
    ) -> Result<Presentation<P, C, AttributeType>, ProofError>
    where
        AttributeType: 'a,
    {
        let mut proofs = Vec::with_capacity(attrs.len());
        let mut transcript = RandomOracle::domain("ConcordiumWeb3ID");
        append_challenge(&mut transcript, &self.challenge);
        transcript.append_message(b"ctx", &params);
        let mut csprng = rand::thread_rng();
        if self.credential_statements.len() != attrs.len() {
            return Err(ProofError::CommitmentsStatementsMismatch);
        }
        let mut signers = Vec::new();
        for (cred_statement, attributes) in self.credential_statements.into_iter().zip(attrs) {
            if let CommitmentInputs::Web3Issuer { signer, .. } = attributes {
                signers.push(signer);
            }
            let proof = cred_statement.prove(params, &mut transcript, &mut csprng, attributes)?;
            proofs.push(proof);
        }
        let to_sign = linking_proof_message_to_sign(&self.challenge, &proofs);
        // Linking proof
        let mut proof_value = Vec::new();
        for signer in signers {
            let signature = signer.sign(&to_sign);
            proof_value.push(WeakLinkingProof { signature });
        }
        let linking_proof = LinkingProof {
            created: chrono::Utc::now(),
            proof_value,
        };
        Ok(Presentation {
            presentation_context: self.challenge,
            linking_proof,
            verifiable_credential: proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::CredentialRegistrationID;

    use crate::common;
    use crate::curve_arithmetic::Value;
    use crate::hashes::BlockHash;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::id_proof_types::{
        AtomicStatement, AttributeInRangeStatement, AttributeInSetStatement,
        AttributeNotInSetStatement, RevealAttributeStatement,
    };
    use crate::id::types::{AttributeTag, IpIdentity};
    use crate::web3id::did::Network;
    use crate::web3id::{
        CredentialHolderId, GivenContext, OwnedCommitmentInputs, Sha256Challenge, Web3IdAttribute,
    };
    use concordium_contracts_common::{ContractAddress, Timestamp};
    use rand::{Rng, SeedableRng};
    use std::marker::PhantomData;

    struct AccountCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>,
        credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        cred_id: CredentialRegistrationID,
    }

    impl<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> AccountCredentialsFixture<AttributeType> {
        fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
        }
    }

    fn account_credentials_fixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>(
        attrs: BTreeMap<AttributeTag, AttributeType>,
        global_context: &GlobalContext<ArCurve>,
    ) -> AccountCredentialsFixture<AttributeType> {
        let cred_id_exp = ArCurve::generate_scalar(&mut seed0());
        let cred_id = CredentialRegistrationID::from_exponent(&global_context, cred_id_exp);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut seed0());
            attr_rand.insert(*tag, cmm_rand);
            attr_cmm.insert(*tag, cmm);
        }

        let commitment_inputs = OwnedCommitmentInputs::Account {
            values: attrs,
            randomness: attr_rand,
            issuer: IpIdentity::from(17u32),
        };

        let credential_inputs = CredentialsInputs::Account {
            commitments: attr_cmm,
        };

        AccountCredentialsFixture {
            commitment_inputs,
            credential_inputs,
            cred_id,
        }
    }

    struct Web3CredentialsFixture {
        commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
        credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        cred_id: CredentialHolderId,
        contract: ContractAddress,
        issuer_key: ed25519_dalek::SigningKey,
    }

    impl Web3CredentialsFixture {
        fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
        }
    }

    fn seed0() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }

    fn web3_credentials_fixture(
        attrs: BTreeMap<String, Web3IdAttribute>,
        global_context: &GlobalContext<ArCurve>,
    ) -> Web3CredentialsFixture {
        let signer_key = ed25519_dalek::SigningKey::generate(&mut seed0());
        let cred_id = CredentialHolderId::new(signer_key.verifying_key());

        let issuer_key = ed25519_dalek::SigningKey::generate(&mut seed0());
        let contract = ContractAddress::new(1337, 42);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut seed0());
            attr_rand.insert(tag.clone(), cmm_rand);
            attr_cmm.insert(tag.clone(), cmm);
        }

        let signed_cmms = SignedCommitments::from_secrets(
            &global_context,
            &attrs,
            &attr_rand,
            &cred_id,
            &issuer_key,
            contract,
        )
        .unwrap();

        let commitment_inputs = OwnedCommitmentInputs::Web3Issuer {
            signer: signer_key,
            values: attrs,
            randomness: attr_rand,
            signature: signed_cmms.signature,
        };

        let credential_inputs = CredentialsInputs::Web3 {
            issuer_pk: issuer_key.verifying_key().into(),
        };

        Web3CredentialsFixture {
            commitment_inputs,
            credential_inputs,
            cred_id,
            contract,
            issuer_key,
        }
    }

    /// Test that constructing proofs for web3 only credentials works in the
    /// sense that the proof verifies.
    ///
    /// JSON serialization of requests and presentations is also tested.
    #[test]
    fn test_completeness_web3() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let min_timestamp = chrono::Duration::try_days(Web3IdAttribute::TIMESTAMP_DATE_OFFSET)
            .unwrap()
            .num_milliseconds()
            .try_into()
            .unwrap();

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred_1 = web3_credentials_fixture(
            [
                (17.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    23.to_string(),
                    Web3IdAttribute::String(AttributeKind("ff".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let web3_cred_2 = web3_credentials_fixture(
            [
                (0.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    1.to_string(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
                (
                    2.to_string(),
                    Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(min_timestamp * 2)),
                ),
                (
                    5.to_string(),
                    Web3IdAttribute::String(AttributeKind("testvalue".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: web3_cred_1.contract,
                credential: web3_cred_1.cred_id,
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: "17".into(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: "23".into(),
                            set: [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                            AtomicStatement::RevealAttribute {
                                statement: RevealAttributeStatement {
                                    attribute_tag: "5".into(),
                                },
                            },
                ],
            },
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: web3_cred_2.contract,
                credential: web3_cred_2.cred_id,
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 0.to_string(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.to_string(),
                            set: [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 2.to_string(),
                            lower: Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(
                                min_timestamp,
                            )),
                            upper: Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(
                                min_timestamp * 3,
                            )),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
        ];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [
                    web3_cred_1.commitment_inputs(),
                    web3_cred_2.commitment_inputs(),
                ]
                .into_iter(),
            )
            .expect("prove");

        let public = vec![web3_cred_1.credential_inputs, web3_cred_2.credential_inputs];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );

        let data = serde_json::to_string_pretty(&proof).unwrap();
        assert!(
            serde_json::from_str::<Presentation<IpPairing, ArCurve, Web3IdAttribute>>(&data)
                .is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data).unwrap(),
            request,
            "Cannot deserialize request correctly."
        );
    }

    /// Prove and verify where verification fails because
    /// signature on commitments in invalid.
    #[test]
    fn test_soundness_web3_commitments_signature() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred = web3_credentials_fixture(
            [(17.to_string(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Web3Id {
            ty: [
                "VerifiableCredential".into(),
                "ConcordiumVerifiableCredential".into(),
                "TestCredential".into(),
            ]
            .into_iter()
            .collect(),
            network: Network::Testnet,
            contract: web3_cred.contract,
            credential: web3_cred.cred_id,
            statement: vec![AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: "17".into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            }],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(&global_context, [web3_cred.commitment_inputs()].into_iter())
            .expect("prove");

        // change commitments signature to be invalid
        let CredentialProof::Web3Id { commitments, .. } = &mut proof.verifiable_credential[0]
        else {
            panic!("should be web3 proof");
        };
        commitments.signature = web3_cred.issuer_key.sign(&[0, 1, 2]);
        fix_weak_link_proof(&mut proof, &challenge, web3_cred.commitment_inputs());

        let public = vec![web3_cred.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    fn fix_weak_link_proof(
        proof: &mut Presentation<IpPairing, ArCurve, Web3IdAttribute>,
        challenge: &Challenge,
        cmm_input: CommitmentInputs<IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
    ) {
        let CommitmentInputs::Web3Issuer { signer, .. } = cmm_input else {
            panic!("should be web3 inputs");
        };
        let to_sign = linking_proof_message_to_sign(challenge, &proof.verifiable_credential);
        let signature = signer.sign(&to_sign);
        proof.linking_proof.proof_value[0] = WeakLinkingProof { signature };
    }

    /// Prove and verify where verification fails because
    /// a statements is invalid.
    #[test]
    fn test_soundness_web3_statements() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred = web3_credentials_fixture(
            [
                (17.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    23.to_string(),
                    Web3IdAttribute::String(AttributeKind("ff".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Web3Id {
            ty: [
                "VerifiableCredential".into(),
                "ConcordiumVerifiableCredential".into(),
                "TestCredential".into(),
            ]
            .into_iter()
            .collect(),
            network: Network::Testnet,
            contract: web3_cred.contract,
            credential: web3_cred.cred_id,
            statement: vec![
                AtomicStatement::AttributeInSet {
                    statement: AttributeInSetStatement {
                        attribute_tag: "23".into(),
                        set: [
                            Web3IdAttribute::String(AttributeKind("ff".into())),
                            Web3IdAttribute::String(AttributeKind("aa".into())),
                            Web3IdAttribute::String(AttributeKind("zz".into())),
                        ]
                        .into_iter()
                        .collect(),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: "17".into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
            ],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(&global_context, [web3_cred.commitment_inputs()].into_iter())
            .expect("prove");

        // change statement to be invalid
        let CredentialProof::Web3Id { proofs, .. } = &mut proof.verifiable_credential[0] else {
            panic!("should be web3 proof");
        };
        proofs[1].0 = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.to_string(),
                lower: Web3IdAttribute::Numeric(200),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };
        fix_weak_link_proof(&mut proof, &challenge, web3_cred.commitment_inputs());

        let public = vec![web3_cred.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Prove and verify where verification fails because
    /// linking proof is missing or invalid.
    #[test]
    fn test_soundness_web3_linking_proof() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred = web3_credentials_fixture(
            [(17.to_string(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Web3Id {
            ty: [
                "VerifiableCredential".into(),
                "ConcordiumVerifiableCredential".into(),
                "TestCredential".into(),
            ]
            .into_iter()
            .collect(),
            network: Network::Testnet,
            contract: web3_cred.contract,
            credential: web3_cred.cred_id,
            statement: vec![AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: "17".into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            }],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(&global_context, [web3_cred.commitment_inputs()].into_iter())
            .expect("prove");

        // remove linking proof
        let CredentialProof::Web3Id { proofs, .. } = &mut proof.verifiable_credential[0] else {
            panic!("should be web3 proof");
        };
        proof.linking_proof.proof_value.pop();

        let public = vec![web3_cred.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::MissingLinkingProof);

        // add invalid linking proof
        let CredentialProof::Web3Id { proofs, .. } = &mut proof.verifiable_credential[0] else {
            panic!("should be web3 proof");
        };
        let CommitmentInputs::Web3Issuer { signer, .. } =
            CommitmentInputs::from(&web3_cred.commitment_inputs)
        else {
            panic!("should be web3 inputs");
        };
        let signature = signer.sign(&[0, 1, 2]);
        proof
            .linking_proof
            .proof_value
            .push(WeakLinkingProof { signature });

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidLinkinProof);
    }

    /// Test that constructing proofs for a mixed (both web3 and account credentials
    /// involved) request works in the sense that the proof verifies.
    ///
    /// JSON serialization of requests and presentations is also tested.
    #[test]
    fn test_completeness_web3_and_account() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred_fixture = web3_credentials_fixture(
            [
                (17.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    23.to_string(),
                    Web3IdAttribute::String(AttributeKind("ff".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let acc_cred_fixture = account_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: web3_cred_fixture.contract,
                credential: web3_cred_fixture.cred_id,
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 17.to_string(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: 23u8.to_string(),
                            set: [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
            CredentialStatement::Account {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 3.into(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.into(),
                            set: [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
        ];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [
                    web3_cred_fixture.commitment_inputs(),
                    acc_cred_fixture.commitment_inputs(),
                ]
                .into_iter(),
            )
            .expect("Cannot prove");

        let public = vec![
            web3_cred_fixture.credential_inputs,
            acc_cred_fixture.credential_inputs,
        ];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );

        let data = serde_json::to_string_pretty(&proof).unwrap();
        assert!(
            serde_json::from_str::<Presentation<IpPairing, ArCurve, Web3IdAttribute>>(&data)
                .is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data).unwrap(),
            request,
            "Cannot deserialize request correctly."
        );
    }

    /// Test prove and verify presentation for account credentials.
    #[test]
    fn test_completeness_account() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
                (
                    2.into(),
                    Web3IdAttribute::String(AttributeKind("aa".into())),
                ),
                (
                    5.into(),
                    Web3IdAttribute::String(AttributeKind("testvalue".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![
                        AtomicStatement::AttributeInRange {
                            statement: AttributeInRangeStatement {
                                attribute_tag: 3.into(),
                                lower: Web3IdAttribute::Numeric(80),
                                upper: Web3IdAttribute::Numeric(1237),
                                _phantom: PhantomData,
                            },
                        },
                        AtomicStatement::AttributeInSet {
                            statement: AttributeInSetStatement {
                                attribute_tag: 2.into(),
                                set: [
                                    Web3IdAttribute::String(AttributeKind("ff".into())),
                                    Web3IdAttribute::String(AttributeKind("aa".into())),
                                    Web3IdAttribute::String(AttributeKind("zz".into())),
                                ]
                                .into_iter()
                                .collect(),
                                _phantom: PhantomData,
                            },
                        },
                        AtomicStatement::AttributeNotInSet {
                            statement: AttributeNotInSetStatement {
                                attribute_tag: 1.into(),
                                set: [
                                    Web3IdAttribute::String(AttributeKind("ff".into())),
                                    Web3IdAttribute::String(AttributeKind("aa".into())),
                                    Web3IdAttribute::String(AttributeKind("zz".into())),
                                ]
                                    .into_iter()
                                    .collect(),
                                _phantom: PhantomData,
                            },
                        },
                        AtomicStatement::RevealAttribute {
                            statement: RevealAttributeStatement {
                                attribute_tag: 5.into(),
                            },
                        },

            ],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![acc_cred_fixture.credential_inputs];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for account credentials.
    #[test]
    fn test_completeness_account_attribute_kind() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [
                (3.into(), AttributeKind::from(137)),
                (1.into(), AttributeKind("bb".into())),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![
                // AtomicStatement::AttributeInRange {
                //     statement: AttributeInRangeStatement {
                //         attribute_tag: 3.into(),
                //         lower: AttributeKind::from(80),
                //         upper: AttributeKind::from(1237),
                //         _phantom: PhantomData,
                //     },
                // },
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 1.into(),
                        lower: AttributeKind("aa".into()),
                        upper: AttributeKind("cca".into()),
                        _phantom: PhantomData,
                    },
                },

            ],
        }];

        let request = Request::<ArCurve, AttributeKind> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![acc_cred_fixture.credential_inputs];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for account credentials where
    /// verification fails.
    #[test]
    fn test_soundness_account() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![
                AtomicStatement::AttributeNotInSet {
                    statement: AttributeNotInSetStatement {
                        attribute_tag: 1u8.into(),
                        set: [
                            Web3IdAttribute::String(AttributeKind("ff".into())),
                            Web3IdAttribute::String(AttributeKind("aa".into())),
                            Web3IdAttribute::String(AttributeKind("zz".into())),
                        ]
                        .into_iter()
                        .collect(),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
            ],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialProof::Account { proofs, .. } = &mut proof.verifiable_credential[0] else {
            panic!("should be account proof");
        };
        proofs[1].0 = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 3.into(),
                lower: Web3IdAttribute::Numeric(200),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let public = vec![acc_cred_fixture.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Test verify fails if the credentials and credential inputs have
    /// mismatching types.
    #[test]
    fn test_soundness_mismatching_credential_types() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [(3.into(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: 3.into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            }],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // use mismatching type of credential inptus
        let web3_cred_fixture = web3_credentials_fixture(
            [(3.to_string(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let public = vec![web3_cred_fixture.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Test verify fails if the credentials and credential inputs have
    /// mismatching lengths.
    #[test]
    fn test_soundness_mismatching_credential_length() {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::Sha256(Sha256Challenge::new(rng.gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [(3.into(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: 3.into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            }],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InconsistentPublicData);
    }

    // todo ar test new stuff

    /// Test that constructing proofs for a account credential
    /// request works with a `Context` in the sense that the proof verifies.
    ///
    /// JSON serialization of requests and presentations is also tested.
    #[test]
    fn test_with_context_challenge() {
        let mut rng = rand::thread_rng();
        // Randomly generated nonce. It is important that the nonce is freshly generated by the backend
        // for each request so that the presentation request anchor on-chain truely looks random.
        let nonce_context = GivenContext {
            label: "nonce".into(),
            context: Sha256Challenge::new(rng.gen()).into(),
        };
        // Human readable string giving more context to the request.
        let context_string_context = GivenContext {
            label: "context_string".into(),
            context: "My great ZK application.".into(),
        };
        // The topic of the wallet connection as defined by `walletConnect`.
        // The wallet or ID app use this value to check that the topic matches the current active connection.
        let connection_id_context = GivenContext {
            label: "connection_id".into(),
            context: "43eee2b1e5128c9a26c871b7aff2cfe448aee66c5a927d47116e8f0c30f452e1".into(),
        };
        // Human readable string giving more context to the request.
        let block_hash_context = GivenContext {
            label: "block_hash".into(),
            context: BlockHash::new(rng.gen()).into(),
        };
        // The website URL that the wallet is connected to or a TLS certificate/fingerprint of the connected website.
        let resource_id_context = GivenContext {
            label: "resource_id".into(),
            context: "https://my-great-website.com".into(),
        };
        let challenge = Challenge::V1(crate::web3id::Context {
            given: vec![nonce_context, context_string_context, connection_id_context],
            requested: vec![block_hash_context, resource_id_context],
        });

        let params = GlobalContext::generate("Test".into());
        let cred_id_exp = ArCurve::generate_scalar(&mut rng);
        let cred_id = CredentialRegistrationID::from_exponent(&params, cred_id_exp);
        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id,
            statement: vec![
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeNotInSet {
                    statement: AttributeNotInSetStatement {
                        attribute_tag: 1u8.into(),
                        set: [
                            Web3IdAttribute::String(AttributeKind("ff".into())),
                            Web3IdAttribute::String(AttributeKind("aa".into())),
                            Web3IdAttribute::String(AttributeKind("zz".into())),
                        ]
                        .into_iter()
                        .collect(),
                        _phantom: PhantomData,
                    },
                },
            ],
        }];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut values = BTreeMap::new();
        values.insert(3.into(), Web3IdAttribute::Numeric(137));
        values.insert(
            1.into(),
            Web3IdAttribute::String(AttributeKind("xkcd".into())),
        );
        let mut randomness = BTreeMap::new();
        for tag in values.keys() {
            randomness.insert(
                *tag,
                pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
            );
        }

        let secrets: CommitmentInputs<
            '_,
            IpPairing,
            ArCurve,
            Web3IdAttribute,
            ed25519_dalek::SigningKey,
        > = CommitmentInputs::Account {
            values: &values,
            randomness: &randomness,
            issuer: IpIdentity::from(17u32),
        };
        let commitment_inputs = [secrets];

        let proof = request
            .clone()
            .prove(
                &params,
                <[CommitmentInputs<
                    '_,
                    IpPairing,
                    ArCurve,
                    Web3IdAttribute,
                    _,
                >; 1] as IntoIterator>::into_iter(commitment_inputs),
            )
            .expect("Cannot prove");

        let commitments = {
            let key = params.on_chain_commitment_key;
            let mut comms = BTreeMap::new();
            for (tag, value) in randomness.iter() {
                let _ = comms.insert(
                    AttributeTag::from(*tag),
                    key.hide(
                        &pedersen_commitment::Value::<ArCurve>::new(
                            values.get(tag).unwrap().to_field_element(),
                        ),
                        value,
                    ),
                );
            }
            comms
        };

        let public = vec![CredentialsInputs::Account { commitments }];
        assert_eq!(
            proof
                .verify(&params, public.iter())
                .expect("Verification of mixed presentation failed."),
            request,
            "Proof verification failed."
        );

        let data = serde_json::to_string_pretty(&proof).unwrap();
        assert!(
            serde_json::from_str::<Presentation<IpPairing, ArCurve, Web3IdAttribute>>(&data)
                .is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data).unwrap(),
            request,
            "Cannot deserialize request correctly."
        );
    }

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_account() {
        // let challenge = Challenge::Sha256(Sha256Challenge::new(seed0().gen()));

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
                (
                    2.into(),
                    Web3IdAttribute::String(AttributeKind("aa".into())),
                ),
                (
                    5.into(),
                    Web3IdAttribute::String(AttributeKind("testvalue".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        // let credential_statements = vec![CredentialStatement::Account {
        //     network: Network::Testnet,
        //     cred_id: acc_cred_fixture.cred_id,
        //     statement: vec![
        //         AtomicStatement::AttributeInRange {
        //             statement: AttributeInRangeStatement {
        //                 attribute_tag: 3.into(),
        //                 lower: Web3IdAttribute::Numeric(80),
        //                 upper: Web3IdAttribute::Numeric(1237),
        //                 _phantom: PhantomData,
        //             },
        //         },
        //         AtomicStatement::AttributeInSet {
        //             statement: AttributeInSetStatement {
        //                 attribute_tag: 2.into(),
        //                 set: [
        //                     Web3IdAttribute::String(AttributeKind("ff".into())),
        //                     Web3IdAttribute::String(AttributeKind("aa".into())),
        //                     Web3IdAttribute::String(AttributeKind("zz".into())),
        //                 ]
        //                 .into_iter()
        //                 .collect(),
        //                 _phantom: PhantomData,
        //             },
        //         },
        //         AtomicStatement::AttributeNotInSet {
        //             statement: AttributeNotInSetStatement {
        //                 attribute_tag: 1.into(),
        //                 set: [
        //                     Web3IdAttribute::String(AttributeKind("ff".into())),
        //                     Web3IdAttribute::String(AttributeKind("aa".into())),
        //                     Web3IdAttribute::String(AttributeKind("zz".into())),
        //                 ]
        //                     .into_iter()
        //                     .collect(),
        //                 _phantom: PhantomData,
        //             },
        //         },
        //         AtomicStatement::RevealAttribute {
        //             statement: RevealAttributeStatement {
        //                 attribute_tag: 5.into(),
        //             },
        //         },
        //     ],
        // }];

        // let request = Request::<ArCurve, Web3IdAttribute> {
        //     challenge,
        //     credential_statements,
        // };
        //
        // let proof = request
        //     .clone()
        //     .prove(
        //         &global_context,
        //         [acc_cred_fixture.commitment_inputs()].into_iter(),
        //     )
        //     .expect("prove");
        //
        // let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        // println!("proof_json:\n{}", proof_json);

        let proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2025-10-26T07:20:55.639111Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2025-10-26T07:20:55.638868Z",
          "proofValue": [
            {
              "proof": "ad2921ae1d65542c4d8f491c779028e989876ce7c95b817122b1d85b16f593d818792c9261dd83b097cd433e57ca5e05a273ada11a24afa3bc3fb3ea387e3a7569a6e5b962604146442305d0b272317d4232b06c3c51ab0d6fe52c600fdd7f648cbf4ef3174ee92910a9849cd1c948ba4c91ea92abfaf7068e4a026ebc39207404270d8420ccef4d0f99ca4964681fa6831ae08ff49f1d36c42ef14589f742a2539076002194b8bce2a776a4b987f73713f69aa29cc294e3ecf68c474d7abc570e1b2d902396bdec86e8713d3b0280a15eb73eaeb94ccb2a01f92aa0b3eb97c060864e8cd95c364a02a375873b319c911099b8514e3b37cce88d0cc5632a847b5496ba301d5e00c2769846f97289a2fd501d860966bea3ab867720f98754d57e00000007a58c2c0282d8a91ca553617311c51ca929c7a8f4cac3788d2b9a0a6cc92c90f332d7f8cec6fec159164049d15c0ba7e590d7657976135cba7acc2174245233dd44ea341f691e928306d66b074e02adb860cc740489a1f849f198cdc41045b38688ad8de18b6cb8f7ff4b026e7ec7228dcefe257bdc5a1c317a28662dd25349ac6018ef9868cb1b4d23a2ce29a0ff7a0ca49caef2e6838c6d54fb786a65e67ea252b4e5fedf15d6085a8abf2f725409851bc1ee2883272de5bcff7793477d56f3813889c8d8ad2dd2f83c4862f3092464e6d9dcf8c87d312c83dac7314467d5dbb9575b39aa72dade9a4d59328b79100e8ce2436e98a1e319324f4dcebff6c68d25d5834fc63c071090459692f644cba70f28593a0eb65f7f71efbe3022c6b438a178a45a266adb8ce205675425af8ffafc23cc4c542c6599cabbb1aa8f048388da74e4bdfec09913e2691f72c8eb804589640ba1d1cba99f9a20106506f4236fc72a8dd233aabd5333e1bb68b98ed7a3466d1d090ed581b85e521813fa6324fdb89d0b16585861afb706695be090a9ee847ec3221ee40a2442e6e8f6a91a42920a72f03e168d823abcd5594d6b339c4e969143a7c720885552657c0275d1d919b4beb031a12c0a1b179efc7e6339d2f2671d6f03024cf392fdb0774b778a585a9602d8f66833a5d6e5347327ad3027b7c583b3af18bbe30a28a5927ee848be6673883182c9591574c92030439a83250ea62a9ef2264294200608d86f654a29f876cfa77c369c43f0d801262b7da3368eb452a867dbfdf0613ec4401f0ffdd3fcb6da4220b4c96b3e8838d0936e03426d844a585269b50433f9da9e3b512992a559f7c28dfe165c267ac99a1d99e048d0a136ca1ca0ecf7941e4403364144f0ed4ddaa2788f57e690c63eb3c651609ed59a42f1f79861581932df7e9fe02d4e20058ee4afefaf9476c0e64bace57500a185d1ea272150e44f89cee08aa5a50c9f428be8e5dba12e21e2563675f7cd5a21a1d2ac0dc9b3542ccc87bb355aab2b63",
              "type": "AttributeInRange"
            },
            {
              "proof": "b3f32d6d31476315f369557429adc7e2c6e4f52e148e8cd08d6240cff29eedaa35308c83dd06c3bccfd07aeec8c60dceb93697c3ca588f29bb1126a20e930c2634e96915c4eaa05586acf07e691bee08ccb8d003ab246e139c81c051836f157ab914b460f1de18361d32703e91bcc48a21e6198c60177e84ca2491673b667f25fdfbeb42f636335eabf3befa4c913790a30b5cee7a4442c7eae1fd029a7016624ab1dd421a9ca3f8ccac6d3816cda42b5b1dcc6e9ad0b0c55cb8f23d4004246317dcdc128226ba6e4c3876381d4a92927b91a34adf49c80b05781c4368d9a1bf72cd55f71352e42859638551dde2de772b02a64ed63aa1c6605d67e29e407a7c023b37380ec18747d1ecbd068275c51e422a6798443e577d3e0398b64c8a3897000000028f357fb97de1f64f81b8b70b7ce077d294d2a8dcd6c24ac1720b6b5943c2b72064045b8d5655ddceadda4c2235be921e915061e61b8ac78f84dfbd9de4991436659e444a8931d3bf4e04fb306cff517dac1dd1c403931b72695ef7c853856d73b4452d9b85bd851a73426e966638e6d67fb5efb49a0e795a8c9c8f9c0ac36f341f991ca85f3d497bbf947867d5bf6b9db81f8b99c9631b0b6a02973ce1912d126477d32c381c4e6109c7f4fbe121b978c6fc6d7d03f5e5a4e93555be4fd92c7914baadc605adbe46b60cb1488dd8b3686860e75a291accd0ce941c9e8511ade24b9c3930a1d80993fa6081003038b01a2514cb6a0790c6af3e2432e54ce4bb20",
              "type": "AttributeInSet"
            },
            {
              "proof": "94d3ea2668881ae0d6e5d1e7fc463bad6e902e2a7cd8d9be4b11d48f8854b9652cf9b0181123d667c134e7d6fd8bac0fb413ef563ed3eff09f9a7e6f1cfb75e7d711caf19a70b4f0a4f6941daab261ba58796e74f6e29a87e991e4c7696ceb2484cd39aa81a4eb49f9be71caecba3e3a3b4a062a3eedc0b73405230e03150ab07f980f4840730f990e754b7dc78e9f1b8926cf57d6ef243966533d2b122670fa0cd8d94b49f149f8bd3a1a5f13fd31c68c3f584e6e4829c20bc95aaafc79e4fa3ba5ed019f3e72ff4bcb9ed680b73c94371749e45b4e74f8286fed5f52aa676b16c75c385da8a877494e1ed6019e2b1f827d3dfb0001396dee7764f640f0f6a610e50ada2a30ef5d8883a1f692d8c29cfef88d9164dd630e0757a9636ecefdaa00000002b839595e42d08fab8492ff918eaa954c6dcf515da600a629604041c1c02a7393423507158c9783b85585167f4c8e603bb9782a730d25940704ffb1707921031cab55329beb4cfe4da63d6eba70c76063e5c7176f274bdbf2054f0e9e9d978bb6a23e6bba5168513f0663d18227b3a0b948b40da12619050f06b8c015a820a3b5a240ceb50ef269ffca17c197cc461287a34950e33adc3993a4e38eb851fabddb85e3badba69962602f2c994a4bf8426e3e153c2e42b4a68d5e6388673c3e6f3c42a1d499cc42408f56671666f32d3bd5d764422e041027562549e8f41c6e913326a72534109ebdb87ef445677fa5a27114b511a0d131ad9eac163ebdc1c00104",
              "type": "AttributeNotInSet"
            },
            {
              "attribute": "testvalue",
              "proof": "fceb0900994b980e3bfab3733499731791634cd9a9bc2485cc027d88bc50a093637712584ac90ad0529d095de23705cdc0cffda27051f23bfb6ddaa8648b344d",
              "type": "RevealAttribute"
            }
          ],
          "type": "ConcordiumZKProofV3"
        },
        "statement": [
          {
            "attributeTag": "dob",
            "lower": 80,
            "type": "AttributeInRange",
            "upper": 1237
          },
          {
            "attributeTag": "sex",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeInSet"
          },
          {
            "attributeTag": "lastName",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeNotInSet"
          },
          {
            "attributeTag": "nationality",
            "type": "RevealAttribute"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredential"
      ]
    }
  ]
}
"#;
        let proof: Presentation<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![acc_cred_fixture.credential_inputs];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_web3() {
        // let challenge = Challenge::Sha256(Sha256Challenge::new(seed0().gen()));

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred = web3_credentials_fixture(
            [
                (3.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    1.to_string(),
                    Web3IdAttribute::String(AttributeKind("xkcd".into())),
                ),
                (
                    2.to_string(),
                    Web3IdAttribute::String(AttributeKind("aa".into())),
                ),
                (
                    5.to_string(),
                    Web3IdAttribute::String(AttributeKind("testvalue".into())),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        // let credential_statements = vec![CredentialStatement::Web3Id {
        //     ty: [
        //         "VerifiableCredential".into(),
        //         "ConcordiumVerifiableCredential".into(),
        //         "TestCredential".into(),
        //     ]
        //     .into_iter()
        //     .collect(),
        //     network: Network::Testnet,
        //     contract: web3_cred.contract,
        //     credential: web3_cred.cred_id,
        //     statement: vec![
        //                 AtomicStatement::AttributeInRange {
        //                     statement: AttributeInRangeStatement {
        //                         attribute_tag: 3.to_string(),
        //                         lower: Web3IdAttribute::Numeric(80),
        //                         upper: Web3IdAttribute::Numeric(1237),
        //                         _phantom: PhantomData,
        //                     },
        //                 },
        //                 AtomicStatement::AttributeInSet {
        //                     statement: AttributeInSetStatement {
        //                         attribute_tag: 2.to_string(),
        //                         set: [
        //                             Web3IdAttribute::String(AttributeKind("ff".into())),
        //                             Web3IdAttribute::String(AttributeKind("aa".into())),
        //                             Web3IdAttribute::String(AttributeKind("zz".into())),
        //                         ]
        //                         .into_iter()
        //                         .collect(),
        //                         _phantom: PhantomData,
        //                     },
        //                 },
        //                 AtomicStatement::AttributeNotInSet {
        //                     statement: AttributeNotInSetStatement {
        //                         attribute_tag: 1.to_string(),
        //                         set: [
        //                             Web3IdAttribute::String(AttributeKind("ff".into())),
        //                             Web3IdAttribute::String(AttributeKind("aa".into())),
        //                             Web3IdAttribute::String(AttributeKind("zz".into())),
        //                         ]
        //                             .into_iter()
        //                             .collect(),
        //                         _phantom: PhantomData,
        //                     },
        //                 },
        //                 AtomicStatement::RevealAttribute {
        //                     statement: RevealAttributeStatement {
        //                         attribute_tag: 5.to_string(),
        //                     },
        //                 },
        //
        //     ],
        // }];
        //
        // let request = Request::<ArCurve, Web3IdAttribute> {
        //     challenge,
        //     credential_statements,
        // };
        //
        // let proof = request
        //     .clone()
        //     .prove(&global_context, [web3_cred.commitment_inputs()].into_iter())
        //     .expect("prove");
        //
        // let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        // println!("proof_json:\n{}", proof_json);

        let proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2025-10-26T07:28:08.545556Z",
    "proofValue": [
      "8dbdfb933b46a7661258cdd172547f16d17e2fdf335ddb55d91e1b9cf1dd9227a7e200207b53e494bf39ee821bc76b6c62d863a1103a0d577220dca418834100"
    ],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:pkc:ee1aa49a4459dfe813a3cf6eb882041230c7b2558469de81f87c9bf23bf10a03",
        "proof": {
          "commitments": {
            "commitments": {
              "1": "9443780e625e360547c5a6a948de645e92b84d91425f4d9c0455bcf6040ef06a741b6977da833a1552e081fb9c4c9318",
              "2": "83a4e3bc337339a16a97dfa4bfb426f7e660c61168f3ed922dcf26d7711e083faa841d7e70d44a5f090a9a6a67eff5ad",
              "3": "a26ce49a7a289e68eaa43a0c4c33b2055be159f044eabf7d0282d1d9f6a0109956d7fb7b6d08c9f0f2ac6a42d2c68a47",
              "5": "8ae7a7fc631dc8566d0db1ce0258ae9b025ac5535bc7206db92775459ba291789ae6c40687763918c6c297b636b3991c"
            },
            "signature": "afeabe7b0948eaa432e7b664790338431399299f284c51bfb910706511c077e7bb6a19e4a18a537f3f930b89ba1cb7fd46413107fbb24633b127a2858729fe02"
          },
          "created": "2025-10-26T07:28:08.545294Z",
          "proofValue": [
            {
              "proof": "b88f478605769d1548cd2f2793cb28d32a8551cd0f5c182c655af40d1c9b59bd28ade9776b754249ae8f6c8aed632e8698b0a5c804d746ea6037eec874fd1154193c178c7ccee512bf14e9cc314950457320c7bcee75752990f2bc66b684e75fb1c80e7cd89e01c9242efcde33c53bb6a2c8d7334175b5cbcb069c47636000b351ad942f5e90a697976a7908583994ab98b595a4ab388c3b02447a9ea1df40fbf48621a73ef112e040925774a24aa1d888459649ac6ce9e6bacda26dc4a5a64025d740ccc27bc460ea8de1820cceb035e868c7414fe3c4bf27f5af5e5284bfa61d47841aec9d28373f5f6ce6f3c81910ee3a987433e901f77c23a65fb5332f9b394562e04c260f829b267f71116ad28f8c6e5a3ffc302137475c58266626928e00000007885033420a7f64541eb4dc8d89aa32daa1f245c1b6aa8c643d313cceed84b029142a5ab21a5007799d9152cc6cce7f5a80c4c2b32c55c0bf57c71fa87b2473c1d0f96d7f7942bfc0784ccc1bc0447a7aa96953366ded0f014314db95fd68ebd7a511c9c488f8e29c29c5147404c1be6f69d3b233d64586b3d46fde08d88920e09ab3e88f187e6a5b51f9e4d4956179c7ab38236b3d59648be8c44d06e006ea05290f8b5f9ebbf537f127637e4bab81d044511233c4398834019b68d529808cdca44a919b78ccc29bec5a6a06004a99727b11d19df7105988448ff7c96aef84b2aa4a1b033f563ef99da03ec7a11d51508dc8d869d1c070af1b365dd6fec9c2bd0c3d7bfb8e24044a27fb6df4a9cc3f35ff4280bfe5df1c9d7d1d698f2459ed90b696f2d7af8f2ef247bbb410ecad10c7fd8be6e5b5e0350f7341ab783fc706ee3c93cda8f5ba83456d8bfc6feb3eeda2b042361e9a223e41e69d2ab2988b491b5e2527f78e19c843b27e70157318db0659a1fceb913173432f89833cd6051f02b533a08fee16185a9f4d0b83ed49bd9340eba77fb4d9646762d4c0ae96ef41bdcfd4e1b05bbf943f47190ff55e9d355f862fd4dfb0448960623bfc0c8550adf6093787b5ebf41456224240c4cc51ab65e3566df9d65e3ec6e665daa1855c0d91b70e8f23ff3c5b74142dad5137b88e91cc0f8f94ae82a746b709ff00352abbceb304788a00774e1a5029b5ae88c4f1b5849e30999a85d4820ec5bb5bb5ea46bc2b263d9e4d73c28425fdc289494f17dc9ba046ad14d8fe698a888253386858daabd0c4820cc39b7865063bb71979a048b374f2744ed863f479805bd66d44720b139a84fa7dee3808f44a242867dd320b8aa4248f900e9a83ccc4ce2e4608085ee57650451259f62234d6947c331fe480e43ca438ee6dd47bc446ec5ec19ff1fd5ddce700f7da870aa0f8bb12b7a6dc1780f73a312e1142888138d7f18a0461de1287763fc8be3fa3d43d8a6d3d6050efb0049e43dfdb1c7a90ed716656a8dbf1",
              "type": "AttributeInRange"
            },
            {
              "proof": "ab55aaaf3ab5a759d8c71d13e7898310b3784fc4c6c8ada9ec909eccd38b9d40b73043428b4ae65be93c0442c3e3ba0ba0d68e0ab83af8ce6e5c2ea172ee0bd80d67f1620b92e86dacffd5b898130897d65a9a9355ce2b9ea51e668bec09945eb62d5cc55b18bad8ca41bf27e6173b23115d7ede12ddf3ce08ec19bb203216924cda455aba8b8a9c3c3a42d15b79daf4b57c9023549e8fe2269d0703c013164d27354506bfaf1da4000a50dded7e98a27259bc3f38526f20d2e182fd40da91ca3f4a2c2e715fcd911e091056d896246a8ceb3ff9649ffad269e9402e5005f3725e84739f2f3c0ce432e3a46e5129472b11aed524e08b81190a52994e75fc58191fd63592c02ca020815b6f2bd33b25366bce92c99a68f1abbc2c16d51140a8c700000002b0c94b4d02db076510bdaeb2aea3e09a0337d12137528a66e01e83781f6b35d2280e50bf07c10afcfecc3b9d50d78c9d8185c6dcd6db2eb3dfc700e3cb41c64f000f1e8e61afe55b0e875d8177c61c1a54790816d27ffb2e66ee04411a9cd9b7983b8e6725b5b175ba515705feb34911276763a96fade764d08097f9ba1cd2b98c188a2e39ba7074b32a4e3769e056d3846fbb3a62c306621945698bb4b7035e58539e99a2800a5a0a83d6fbff7a1694a2e8b67e3de34a3c1bc7000187b45c7563e5909ee8b29607c81890fc24fae6bc9bf5f0b01e41144c00b6fd99d023b7d618bd8bb7aa3a4259fe6f8679c5682d402db30a9572febc8c9bee97aa7ff57335",
              "type": "AttributeInSet"
            },
            {
              "proof": "ad019a1114ca11054347f80e5a0cb0433761a285456e5412a0a8a636681a0084b507a9e47ec7f45a94562d323085f1fc97349b1aaf71bff9f6463d7dbde0ee1a22d67ad94cd833fbed098db3ad73626a229c2a1fc91bd3a49e965021a68f16cca11835c2e3b6dc6632c3b0db3c154f277ae56803cbbacce5acd16eedec189b2ffa9e824f8062489059c642cb594010f6a7c42f756bf75fa40d47bb62654087e692089789c2d17bb6acf084ab46794819939554a0cd50f2d433483eaadcb1bbd14cd7eec6b29f86c6bcc704ea110d20b26cf9c44d89c974da31d5fafff9e46407016437111abf301253e9ed3a585740a5419db13baadaec7718223395865c8fb518cba9eb52509ab099476b3945eeb5cc5bb77adb6ff375760ffdaedc01afae8a00000002b26f1d85c9a5d6da3e05bcf2a8e81ea4623bd7f1d70e8d36241ae706713ee48245048c90864a22c62d3a0921eda2b70084e2f61260773e2e6cbab5022c868f1a228b652e1e19ad11e42e260e05f08b708423dcd0035bbeeb491a51d9a5bebb50849db1248de073213212e4ebfa7c2270f7c1452b3f8aae39d805e1bdac47039dbac66a734b117ea794dba4f51ec161898116e7a41cd043b4cd04d4f1f500fda04b12820346972653002bb1141bfcd1f4b62820e6cb17c324d1b9509feccd099a5ea3463a889e4c2eb865306c11937ee12c6d5c519e90587052e042ab20b549a6379654d209ae2f61ba657b5b94eb1cf90dfe7e661c770983e1f02741bdff7b25",
              "type": "AttributeNotInSet"
            },
            {
              "attribute": "testvalue",
              "proof": "4ea7503e43982ac82dc8d7ed87308572b63aef46167d8566a7e8efcdd572e4b22799c2303e27e3f1a83ee0f9d9df708af9a9029c41e285d2589256f2f55446ce",
              "type": "RevealAttribute"
            }
          ],
          "type": "ConcordiumZKProofV3"
        },
        "statement": [
          {
            "attributeTag": "3",
            "lower": 80,
            "type": "AttributeInRange",
            "upper": 1237
          },
          {
            "attributeTag": "2",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeInSet"
          },
          {
            "attributeTag": "1",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeNotInSet"
          },
          {
            "attributeTag": "5",
            "type": "RevealAttribute"
          }
        ]
      },
      "issuer": "did:ccd:testnet:sci:1337:42/issuer",
      "type": [
        "ConcordiumVerifiableCredential",
        "TestCredential",
        "VerifiableCredential"
      ]
    }
  ]
}
"#;
        let proof: Presentation<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![web3_cred.credential_inputs];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }
}
