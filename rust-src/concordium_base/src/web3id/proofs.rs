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
    use rand::Rng;
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
        let mut rng = rand::thread_rng();

        let cred_id_exp = ArCurve::generate_scalar(&mut rng);
        let cred_id = CredentialRegistrationID::from_exponent(&global_context, cred_id_exp);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut rng);
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

    fn web3_credentials_fixture(
        attrs: BTreeMap<String, Web3IdAttribute>,
        global_context: &GlobalContext<ArCurve>,
    ) -> Web3CredentialsFixture {
        let mut rng = rand::thread_rng();

        let signer = ed25519_dalek::SigningKey::generate(&mut rng);
        let cred_id = CredentialHolderId::new(signer.verifying_key());

        let issuer = ed25519_dalek::SigningKey::generate(&mut rng);
        let contract = ContractAddress::new(1337, 42);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut rng);
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
            [
                (3.into(), Web3IdAttribute::Numeric(137)),

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

        // use mismatching type of credential inptus
        let web3_cred_fixture = web3_credentials_fixture(
            [
                (3.to_string(), Web3IdAttribute::Numeric(137)),

            ]
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
}
