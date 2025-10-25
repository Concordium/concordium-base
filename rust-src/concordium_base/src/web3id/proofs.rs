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
        AttributeNotInSetStatement,
    };
    use crate::id::types::{AttributeTag, IpIdentity};
    use crate::web3id::did::Network;
    use crate::web3id::{
        CredentialHolderId, GivenContext, OwnedCommitmentInputs, Sha256Challenge, Web3IdAttribute,
    };
    use concordium_contracts_common::{ContractAddress, Timestamp};
    use rand::{Rng, SeedableRng};
    use std::marker::PhantomData;

    struct AccountCredentialsFixture {
        commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
        credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        cred_id: CredentialRegistrationID,
    }

    impl AccountCredentialsFixture {
        fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
        }
    }

    fn account_credentials_fixture(
        attrs: BTreeMap<AttributeTag, Web3IdAttribute>,
        global_context: &GlobalContext<ArCurve>,
    ) -> AccountCredentialsFixture {
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
        let signer = ed25519_dalek::SigningKey::generate(&mut seed0());
        let cred_id = CredentialHolderId::new(signer.verifying_key());

        let issuer = ed25519_dalek::SigningKey::generate(&mut seed0());
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
            &issuer,
            contract,
        )
        .unwrap();

        let commitment_inputs = OwnedCommitmentInputs::Web3Issuer {
            signer,
            values: attrs,
            randomness: attr_rand,
            signature: signed_cmms.signature,
        };

        let credential_inputs = CredentialsInputs::Web3 {
            issuer_pk: issuer.verifying_key().into(),
        };

        Web3CredentialsFixture {
            commitment_inputs,
            credential_inputs,
            cred_id,
            contract,
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
    /// a statements is invalid.
    #[test]
    fn test_soundness_web3() {
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
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(&global_context, [web3_cred.commitment_inputs()].into_iter())
            .expect("prove");

        // change statement to be invalid
        let CredentialProof::Web3Id { proofs, .. } = &mut proof.verifiable_credential[0] else {
            panic!("should be account proof");
        };
        proofs[1].0 = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.to_string(),
                lower: Web3IdAttribute::Numeric(200),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let public = vec![web3_cred.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
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
    fn test_soundness_mismatching_credential_typesp() {
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

    // todo ar test web3 soundness, signature + linking proof

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
            [(3.into(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        // let credential_statements = vec![CredentialStatement::Account {
        //     network: Network::Testnet,
        //     cred_id: acc_cred_fixture.cred_id,
        //     statement: vec![AtomicStatement::AttributeInRange {
        //         statement: AttributeInRangeStatement {
        //             attribute_tag: 3.into(),
        //             lower: Web3IdAttribute::Numeric(80),
        //             upper: Web3IdAttribute::Numeric(1237),
        //             _phantom: PhantomData,
        //         },
        //     }],
        // }];
        //
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
    "created": "2025-10-25T07:34:54.280481Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2025-10-25T07:34:54.280317Z",
          "proofValue": [
            {
              "proof": "ae278735684b0c19c140933e04f0e02494110f5a08b1caf04c7c49ab8817aabe7f162b2f7c4c9563159e770b3341bc10814fd7d72f4eb37821e0587e69f09f9710ea82d1bf56603b24f8650116eda95383f8f9c6a17d7c29c611fe8ba6da43eeaaaf5c91bed3ed11bac729220d142f7723188127b9c557a32329bdbdf3e8552c412076e758d6ff2371702ba5d8bda6a1a33238957633b91fe94b1ed52aa5e587f1a9d5581d1034fd504ff94067ab3b3dba286aa27407417f92e8d23b2f6adc55102c48a898a63975c29edb6a2bddb932cd4011c1d261f56f4e7c38ffa40da6d54774fa3768d24e43f5c062f7948eb2063353785dc2d8bd2bd48db1fb9f741aad095bd03ff739f421cedf743c7d8c370e9c506ca2315706853cf27a3e85791eaf00000007849a40131bb85963bde1d778a520028f6760d6c747716b02015c53286760856ad420a209a31174c4a794edd28d4a9efd9960c265363329b177985e27421d52b5f57141f11e65ac70984d7fd5212ed2bb8ddcd2bd92dc23f27a06b0dc3178cd01a32db39d0fac09781e5bf8b53d9a1346f68e02c3c4f5c181c7abf25f5f97d533f6c1f735982af9ffc2f4b430692aabe3892ccfe4b6b676d4d7ad0e85bd63ab1f5ca38a05fe7d9eb726f6b841ebde9bea683b32d8aee57ca16eacf7310da5a784a53bbb174e4d01ac17a47a77b8c5b945908d72c327be21c4c40ec1f5501739531ad26485d56adb139fbf6ba346cfd985b41880d6d6999f3b1fda204bae03f64b8347060533652daa5464e32acb5bfce4f94275af7ec352a936e44a85cb014ed2a4764c10ae9d31baebb73db94f9adf23f599f34953c434c7af5a8cc055bef0200009991f3a70c763a893efcd18b329a8a0b6b9f3b5f196cfa529a3edddd471e3eb894dabf34085c1adb92e2f14a9114bdd8416a51294b83c525a8666ef8d5348b58afc2f88242b672b487fb03d1cde6755971c974b62d8ca45e3321a86b7b5c6867d6531de64ad4e2c2eba4525acd18cb19eb1bd97f4198923f146f5fdebb22a27e26874f648c3b6afc69203aad675d37b31c736bf3dc443e1077b43f334c2dcb5a2863d4c53f8fba95f3bef90f2044f4db677b1ed621944d0b387ce5801a38d539a06df930374b25c2ede7b65129960886898a368729852539970b3ec7352dce984484fa34ec3f3b08d64b149ac4f8d6d06cf101af12745c4549af0c39c827593681a5c31a3d43c1e410a0635468728f137762bbc3cac97984e6a6a68633d4737413e79a904dd38347f94cbb3c1d1f7a8edb4c2a9a9e5d70a0ad13ebcf826f42bda51ed3e8cfcd21ef1ec53db3a5a2dc86bf2cf77fed6cadde66df0765f664b55a4a397d851a79a80974152991d822218d9a3154b4fe995fd935809a53c42cc5e355e265c0e40c12a12c0ac0c6edbfda5b9177ed095b6f33464e4199a2470af",
              "type": "AttributeInRange"
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
            [(17.to_string(), Web3IdAttribute::Numeric(137))]
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
        //     statement: vec![AtomicStatement::AttributeInRange {
        //         statement: AttributeInRangeStatement {
        //             attribute_tag: "17".into(),
        //             lower: Web3IdAttribute::Numeric(80),
        //             upper: Web3IdAttribute::Numeric(1237),
        //             _phantom: PhantomData,
        //         },
        //     }],
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
    "created": "2025-10-25T07:40:54.678361Z",
    "proofValue": [
      "2f0a65e05478c9cd27c2dbffb8b336936b4d619a41d2dd0a777124825b1384738e4c588285ba7b33b40f0195d0f721176df4b80f3ab799708132a4d7d048c501"
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
              "17": "a26ce49a7a289e68eaa43a0c4c33b2055be159f044eabf7d0282d1d9f6a0109956d7fb7b6d08c9f0f2ac6a42d2c68a47"
            },
            "signature": "ad43311219bedc399454e54cc2c39e445fe69191163dcb15392d38eede9ef42f188575644d2cf634f819ecf2d152084935b7b960fef7cfad8de3e5a209b6970b"
          },
          "created": "2025-10-25T07:40:54.678228Z",
          "proofValue": [
            {
              "proof": "b3d8c309698ca4ca49133b058c5e108cebe97c400073d3a037e644981584d9b174cc2f992d5dc050d536ac71e20ce1398e7a8529b30f252fe0463cc46531cedcadf0a4436fafa41f18305dc124bfcac7b5b6252ebe3c948ec965870f1fc0d3e5a3cdfd4e8a6c3cac7894361fb06d05b3525a3aa96423c0b5ff107412ad53f5838aeeb992bfa46e5d5e564cf8ee3a35b890cce92fdb7631ae6adf0ab6df26efd6894570fc575a30f4d0112464b26b563321ae64f9f5055dd92e3076d20871c6f257745d9feb223f25872c990627bae6224d6427be6e57e6872d0cf9910c410803518acd3345cb30ae3835067110dd085880f241f39872f5b479c89823c0d4487f56a91d5116f38d4bcfc840023c25f73dbca1f10d2d0e0967b1795b245fe6e35b00000007910aaa4fc2f2496f7ebcec8c0e74e58888660a92a77fda1897310b8624edd773b84cfb43b4df50ecf308b38a09d61fe7aa5cfb791047ff6e913ed4b95f12cbb4a29853020ae381e59f7febd654a8d48b168781d9898f7b4179e757fcbe7089b68785970923045ca9ff89df45d88ab2cc3517d90f268b00c2b9815f3dc01acb164b0835e1ca878a373769d9c05d243fbcb8e88238e8672b4784f6a4247de9e9dfa3abef46312a78fcd19b093e7820115c3116dabb19a203ef0a8057c9daa94a4b90ab74d4b7629615eb92124b09b2560db4014f7c4ae2f308f4d10b85f6feefa41bd0eed8ea60d70d296211c461b9fceda803e494319b69e4433bf610c1d190561e72b595d7918d7c03a41f4ea6391a611610fe7a788f9726c18c3e49f16e4fb6802ba5164c2ac927d1ed67e3d6c50db4ddf8e73c5496830cecf9d647b6436e272fe559d79892961610d0830befc49fa9b11176ce37057e2a490d96bbc242ef65cf9c22c2d25aaba0356926119eef7b0005660a0248f5a954b3a3b6f942df520d94c84ae59b76aca3e264ccb565a1426e71aa18816fc7cdcdee5c75560c1640ac926890f8739ec11895e29996befe38a38519264a65f4b1fb72e8a785278e7b638000f693feb2a5726ae86c9c7211b63cf570c6a3b3b037011d264c9729b0f094b976e92619615febb741969840f326c6fa021ddf602be20c1d9abc772c0cebf9b1542c6c327145a348ec0d87d77003c3b9b405be1b786eb2e66bfd58c2063a3ab1144dbee7cfce83a648a63a64baf8be10553e54aa538bca2793006914bdb55f89dbd3634d6a383942483c61001edc1ba1da554b68e537321caeaee59b6919cdef0bca9b0b0b37d256587302bf8ee6588082c7b2eb4a337912c0c2c7f2935b848586e5fe58581c2e18f5d01c4faf85e3ff5945f65203a08c8c85303ab0671e8b51fb4450ecd7de5c4d7b4864fcf53570708849097ad214179988d7f9b855ef413dd4c0c5b9037bc12b4e8382fbf4d4bd1820e40f8a0e60b16d9d70d8d20bdf72",
              "type": "AttributeInRange"
            }
          ],
          "type": "ConcordiumZKProofV3"
        },
        "statement": [
          {
            "attributeTag": "17",
            "lower": 80,
            "type": "AttributeInRange",
            "upper": 1237
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
