use crate::random_oracle::{TranscriptProtocol, TranscriptProtocolV1};
use crate::{
    curve_arithmetic::Curve,
    id::types::{Attribute, GlobalContext},
};
use itertools::Itertools;
use std::collections::BTreeMap;

use crate::curve_arithmetic::Pairing;
use crate::id::id_proof_types::{
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement, ProofVersion,
};
use crate::id::identity_attributes_credentials;
use crate::id::identity_attributes_credentials::IdentityAttributeHandling;
use crate::id::types::{
    HasAttributeRandomness, HasAttributeValues, IdentityAttribute,
    IdentityAttributesCredentialsInfo, IdentityAttributesCredentialsValues, IpContextOnly,
};
use crate::pedersen_commitment::Commitment;
use crate::web3id::v1::{
    AccountBasedCredentialV1, AccountBasedSubjectClaims, AccountCredentialProofPrivateInputs,
    AccountCredentialProofs, AccountCredentialSubject, AccountCredentialVerificationMaterial,
    AtomicProofV1, AtomicStatementV1, ConcordiumLinkingProofVersion, ConcordiumZKProof,
    ConcordiumZKProofVersion, ContextInformation, CredentialMetadataV1,
    CredentialProofPrivateInputs, CredentialV1, CredentialVerificationMaterial,
    IdentityBasedCredentialV1, IdentityBasedSubjectClaims, IdentityCredentialEphemeralId,
    IdentityCredentialEphemeralIdDataRef, IdentityCredentialProofPrivateInputs,
    IdentityCredentialProofs, IdentityCredentialSubject, IdentityCredentialVerificationMaterial,
    LinkingProofV1, PresentationV1, ProveError, RequestV1, SubjectClaims, VerifyError,
};
use rand::{CryptoRng, Rng};

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    PresentationV1<P, C, AttributeType>
{
    /// Get an iterator over the metadata for each of the verifiable credentials
    /// in the order they appear in the presentation. This contains data that need to be
    /// verified externally and also data that is needed to look up [`CredentialVerificationMaterial`].
    /// Hence, proper handling of the metadata is required for verifying the presentation. An implementation of handling
    /// the metadata may be found in the [Rust SDK `web3id` module](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/web3id/index.html)
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = CredentialMetadataV1> + '_ {
        self.verifiable_credentials.iter().map(|cp| cp.metadata())
    }

    /// Verify a presentation and the contained credentials in the context of the provided verification material.
    /// In case of success, returns the [`RequestV1`] which contains the claims the presentation
    /// verifies.
    ///
    /// Notice: This only verifies the cryptographic consistency of the data.
    /// It does not check metadata, such as expiry. This should be checked
    /// separately by the verifier. See [`CredentialMetadataV1`].
    pub fn verify<'a>(
        &self,
        global_context: &GlobalContext<C>,
        verification_material: impl ExactSizeIterator<Item = &'a CredentialVerificationMaterial<P, C>>,
    ) -> Result<RequestV1<C, AttributeType>, VerifyError> {
        let mut transcript = TranscriptProtocolV1::with_domain("ConcordiumVerifiableCredentialV1");
        append_context(&mut transcript, &self.presentation_context);
        transcript.append_message("GlobalContext", &global_context);

        let mut request = RequestV1 {
            context: self.presentation_context.clone(),
            subject_claims: Vec::new(),
        };

        if verification_material.len() != self.verifiable_credentials.len() {
            return Err(VerifyError::VerificationMaterialMismatch);
        }

        for (i, (verification_material, credential)) in verification_material
            .zip(&self.verifiable_credentials)
            .enumerate()
        {
            // The proof for each credential is independent, so make a copy of the transcript so far
            let mut transcript = transcript.split();

            transcript.append_message("ProofVersion", &credential.proof_version());
            transcript.append_message("CreationTime", &credential.created());

            let claims = credential.claims();

            request.subject_claims.push(claims);

            if !credential.verify(global_context, &mut transcript, verification_material) {
                return Err(VerifyError::InvalidCredential(i));
            }
        }

        Ok(request)
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialV1<P, C, AttributeType>
{
    /// Verify a single credential. This only checks the cryptographic parts and
    /// ignores the metadata such as issuance date.
    fn verify(
        &self,
        global: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        verification_material: &CredentialVerificationMaterial<P, C>,
    ) -> bool {
        match self {
            CredentialV1::Account(cred_proof) => {
                cred_proof.verify(global, transcript, verification_material)
            }
            CredentialV1::Identity(cred_proof) => {
                cred_proof.verify(global, transcript, verification_material)
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountBasedCredentialV1<C, AttributeType> {
    /// Proof described in "15.4.1 Account Based Presentations" (blue paper v2.2.0)
    fn verify<P: Pairing<ScalarField = C::Scalar>>(
        &self,
        global_context: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        verification_material: &CredentialVerificationMaterial<P, C>,
    ) -> bool {
        let CredentialVerificationMaterial::Account(AccountCredentialVerificationMaterial {
            issuer,
            attribute_commitments: commitments,
        }) = verification_material
        else {
            // mismatch in types
            return false;
        };

        if self.issuer != *issuer {
            return false;
        }

        transcript.append_label("ConcordiumAccountBasedCredential");
        transcript.append_message("Issuer", &self.issuer);
        transcript.append_message("Statements", &self.subject.statements);
        transcript.append_message("Network", &self.subject.network);
        transcript.append_message("AccountCredId", &self.subject.cred_id);

        verify_statements(
            &self.subject.statements,
            &self.proof.proof_value.statement_proofs,
            commitments,
            &BTreeMap::default(),
            global_context,
            transcript,
        )
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    IdentityBasedCredentialV1<P, C, AttributeType>
{
    /// Proof described in "15.4.2 Identity Based Credential" (blue paper v2.2.0)
    fn verify(
        &self,
        global_context: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        verification_material: &CredentialVerificationMaterial<P, C>,
    ) -> bool {
        let CredentialVerificationMaterial::Identity(IdentityCredentialVerificationMaterial {
            ip_info,
            ars_infos,
        }) = verification_material
        else {
            // mismatch in types
            return false;
        };

        transcript.append_label("ConcordiumIdBasedCredential");
        transcript.append_message("Issuer", &self.issuer);
        transcript.append_message("Statements", &self.subject.statements);
        transcript.append_message("Network", &self.subject.network);

        let Ok(cred_id_data) = self.subject.cred_id.try_to_data() else {
            return false;
        };

        let id_attr_cred_info = IdentityAttributesCredentialsInfo {
            values: IdentityAttributesCredentialsValues {
                ip_identity: self.issuer,
                threshold: cred_id_data.threshold,
                ar_data: cred_id_data.ar_data,
                attributes: self.proof.proof_value.identity_attributes.clone(),
                validity: self.validity.clone(),
            },
            proofs: self.proof.proof_value.identity_attributes_proofs.clone(),
        };

        if identity_attributes_credentials::verify_identity_attributes(
            global_context,
            IpContextOnly {
                ip_info,
                ars_infos: &ars_infos.anonymity_revokers,
            },
            &id_attr_cred_info,
            transcript,
        )
        .is_err()
        {
            return false;
        }

        // Append values that are not part of subject claims
        transcript.append_message("ValidFrom", &id_attr_cred_info.values.validity.created_at);
        transcript.append_message("ValidTo", &id_attr_cred_info.values.validity.valid_to);
        transcript.append_message("EncryptedIdentityCredentialId", &self.subject.cred_id);

        let cmm_attributes: BTreeMap<_, _> = self
            .proof
            .proof_value
            .identity_attributes
            .iter()
            .filter_map(|(tag, attr)| match attr {
                IdentityAttribute::Committed(cmm) => Some((*tag, *cmm)),
                _ => None,
            })
            .collect();

        let revealed_attributes: BTreeMap<_, _> = self
            .proof
            .proof_value
            .identity_attributes
            .iter()
            .filter_map(|(tag, attr)| match attr {
                IdentityAttribute::Revealed(attr) => Some((*tag, attr)),
                _ => None,
            })
            .collect();

        verify_statements(
            &self.subject.statements,
            &self.proof.proof_value.statement_proofs,
            &cmm_attributes,
            &revealed_attributes,
            global_context,
            transcript,
        )
    }
}

fn verify_statements<
    'a,
    C: Curve,
    AttributeType: Attribute<C::Scalar> + 'a,
    TagType: Ord + crate::common::Serialize + 'a,
>(
    statements: &[AtomicStatementV1<C, TagType, AttributeType>],
    proofs: &[AtomicProofV1<C>],
    cmm_attributes: &BTreeMap<TagType, Commitment<C>>,
    revealed_attributes: &BTreeMap<TagType, &AttributeType>,
    global_context: &GlobalContext<C>,
    transcript: &mut impl TranscriptProtocol,
) -> bool {
    // Notice that we already added the number of statements to the transcript
    // by adding statements to the transcript. This acts as a variable length
    // prefix of the loop over statements.

    statements.iter().zip_longest(proofs).all(|elm| {
        elm.both().map_or(false, |(statement, proof)| {
            statement.verify(
                ProofVersion::Version2,
                global_context,
                transcript,
                cmm_attributes,
                revealed_attributes,
                proof,
            )
        })
    })
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountBasedSubjectClaims<C, AttributeType> {
    /// Proof described in "15.4.1 Account Based Presentations" (blue paper v2.2.0)
    fn prove<P: Pairing<ScalarField = C::Scalar>>(
        self,
        global_context: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
        private_input: CredentialProofPrivateInputs<P, C, AttributeType>,
    ) -> Result<AccountBasedCredentialV1<C, AttributeType>, ProveError> {
        let CredentialProofPrivateInputs::Account(AccountCredentialProofPrivateInputs {
            attribute_values: values,
            attribute_randomness: randomness,
            issuer,
        }) = private_input
        else {
            return Err(ProveError::PrivateInputsMismatch);
        };

        transcript.append_label("ConcordiumAccountBasedCredential");
        transcript.append_message("Issuer", &issuer);
        transcript.append_message("Statements", &self.statements);
        transcript.append_message("Network", &self.network);
        transcript.append_message("AccountCredId", &self.cred_id);

        let statement_proofs = prove_statements(
            &self.statements,
            values,
            randomness,
            &BTreeMap::default(),
            global_context,
            transcript,
            csprng,
        )?;

        Ok(AccountBasedCredentialV1 {
            proof: ConcordiumZKProof {
                created_at: now,
                proof_value: AccountCredentialProofs { statement_proofs },
                proof_version: ConcordiumZKProofVersion::ConcordiumZKProofV4,
            },
            subject: AccountCredentialSubject {
                cred_id: self.cred_id,
                statements: self.statements,
                network: self.network,
            },
            issuer,
        })
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> IdentityBasedSubjectClaims<C, AttributeType> {
    /// Proof described in "15.4.2 Identity Based Credential" (blue paper v2.2.0)
    fn prove<P: Pairing<ScalarField = C::Scalar>>(
        self,
        global_context: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
        private_input: CredentialProofPrivateInputs<P, C, AttributeType>,
    ) -> Result<IdentityBasedCredentialV1<P, C, AttributeType>, ProveError> {
        let CredentialProofPrivateInputs::Identity(IdentityCredentialProofPrivateInputs {
            ip_context,
            id_object,
            id_object_use_data,
        }) = private_input
        else {
            return Err(ProveError::PrivateInputsMismatch);
        };

        transcript.append_label("ConcordiumIdBasedCredential");
        transcript.append_message("Issuer", &self.issuer);
        transcript.append_message("Statements", &self.statements);
        transcript.append_message("Network", &self.network);

        let attributes_handling: BTreeMap<_, _> = self
            .statements
            .iter()
            .map(|stmt| match stmt {
                AtomicStatementV1::AttributeValue(statement) => {
                    (statement.attribute_tag, IdentityAttributeHandling::Reveal)
                }
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                    attribute_tag,
                    ..
                })
                | AtomicStatementV1::AttributeInSet(AttributeInSetStatement {
                    attribute_tag,
                    ..
                })
                | AtomicStatementV1::AttributeNotInSet(AttributeNotInSetStatement {
                    attribute_tag,
                    ..
                }) => (*attribute_tag, IdentityAttributeHandling::Commit),
            })
            .collect();

        let (id_attr_cred_info, id_attr_cmm_rand) =
            identity_attributes_credentials::prove_identity_attributes(
                global_context,
                ip_context,
                id_object,
                id_object_use_data,
                &attributes_handling,
                csprng,
                transcript,
            )
            .map_err(|err| ProveError::IdentityAttributeCredentials(err.to_string()))?;

        let cred_id =
            IdentityCredentialEphemeralId::from_data(IdentityCredentialEphemeralIdDataRef {
                ar_data: &id_attr_cred_info.values.ar_data,
                threshold: id_attr_cred_info.values.threshold,
            });

        // Append values that are not part of subject claims
        transcript.append_message("ValidFrom", &id_attr_cred_info.values.validity.created_at);
        transcript.append_message("ValidTo", &id_attr_cred_info.values.validity.valid_to);
        transcript.append_message("EncryptedIdentityCredentialId", &cred_id);

        let revealed_attributes: BTreeMap<_, _> = id_attr_cred_info
            .values
            .attributes
            .iter()
            .filter_map(|(tag, attr)| match attr {
                IdentityAttribute::Revealed(attr) => Some((*tag, attr)),
                _ => None,
            })
            .collect();

        let statement_proofs = prove_statements(
            &self.statements,
            &id_object.get_attribute_list().alist,
            &id_attr_cmm_rand.attributes_rand,
            &revealed_attributes,
            global_context,
            transcript,
            csprng,
        )?;

        let proof = IdentityCredentialProofs {
            identity_attributes_proofs: id_attr_cred_info.proofs,
            identity_attributes: id_attr_cred_info.values.attributes,
            statement_proofs,
        };

        Ok(IdentityBasedCredentialV1 {
            proof: ConcordiumZKProof {
                created_at: now,
                proof_value: proof,
                proof_version: ConcordiumZKProofVersion::ConcordiumZKProofV4,
            },
            subject: IdentityCredentialSubject {
                cred_id,
                statements: self.statements,
                network: self.network,
            },
            issuer: id_attr_cred_info.values.ip_identity,
            validity: id_attr_cred_info.values.validity,
        })
    }
}

fn prove_statements<
    'a,
    C: Curve,
    AttributeType: Attribute<C::Scalar> + 'a,
    TagType: Ord + crate::common::Serialize + 'a,
>(
    statements: &[AtomicStatementV1<C, TagType, AttributeType>],
    attribute_values: &impl HasAttributeValues<C::Scalar, TagType, AttributeType>,
    attribute_randomness: &impl HasAttributeRandomness<C, TagType>,
    revealed_attributes: &BTreeMap<TagType, &AttributeType>,
    global_context: &GlobalContext<C>,
    transcript: &mut impl TranscriptProtocol,
    csprng: &mut (impl Rng + CryptoRng),
) -> Result<Vec<AtomicProofV1<C>>, ProveError> {
    // Notice that we already added the number of statements to the transcript
    // by adding statements to the transcript. This acts as a variable length
    // prefix of the loop over statements.

    statements
        .iter()
        .map(|statement| {
            statement
                .prove(
                    ProofVersion::Version2,
                    global_context,
                    transcript,
                    csprng,
                    attribute_values,
                    attribute_randomness,
                    revealed_attributes,
                )
                .ok_or(ProveError::AtomicStatementProof)
        })
        .collect()
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> SubjectClaims<C, AttributeType> {
    fn prove<P: Pairing<ScalarField = C::Scalar>>(
        self,
        global_context: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
        private_input: CredentialProofPrivateInputs<P, C, AttributeType>,
    ) -> Result<CredentialV1<P, C, AttributeType>, ProveError> {
        match self {
            SubjectClaims::Account(cred_stmt) => cred_stmt
                .prove(global_context, transcript, csprng, now, private_input)
                .map(CredentialV1::Account),
            SubjectClaims::Identity(cred_stmt) => cred_stmt
                .prove(global_context, transcript, csprng, now, private_input)
                .map(CredentialV1::Identity),
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> RequestV1<C, AttributeType> {
    /// Prove the claims in the given [`RequestV1`] using the provided cryptographic
    /// parameters and secrets and return a [`PresentationV1`] embedding the claims and proofs.
    pub fn prove<'a, P: Pairing<ScalarField = C::Scalar>>(
        self,
        params: &GlobalContext<C>,
        private_inputs: impl ExactSizeIterator<
            Item = CredentialProofPrivateInputs<'a, P, C, AttributeType>,
        >,
    ) -> Result<PresentationV1<P, C, AttributeType>, ProveError>
    where
        AttributeType: 'a,
    {
        self.prove_with_rng(
            params,
            private_inputs,
            &mut rand::thread_rng(),
            chrono::Utc::now(),
        )
    }

    /// Prove the claims in the given [`RequestV1`] using the provided cryptographic
    /// parameters and secrets and return a [`PresentationV1`] embedding the claims and proofs.
    /// The source of randomness and "now" are given
    /// as arguments.
    pub fn prove_with_rng<'a, P: Pairing<ScalarField = C::Scalar>>(
        self,
        global_context: &GlobalContext<C>,
        private_inputs: impl ExactSizeIterator<
            Item = CredentialProofPrivateInputs<'a, P, C, AttributeType>,
        >,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PresentationV1<P, C, AttributeType>, ProveError>
    where
        AttributeType: 'a,
    {
        let mut verifiable_credentials = Vec::with_capacity(private_inputs.len());
        let mut transcript = TranscriptProtocolV1::with_domain("ConcordiumVerifiableCredentialV1");
        append_context(&mut transcript, &self.context);
        transcript.append_message("GlobalContext", &global_context);

        if self.subject_claims.len() != private_inputs.len() {
            return Err(ProveError::PrivateInputsMismatch);
        }
        for (subject_claims, private_inputs) in self.subject_claims.into_iter().zip(private_inputs)
        {
            // The proof for each credential is independent, so make a copy of the transcript so far
            let mut transcript = transcript.split();

            transcript.append_message(
                "ProofVersion",
                &ConcordiumZKProofVersion::ConcordiumZKProofV4,
            );
            transcript.append_message("CreationTime", &now);

            let credential = subject_claims.prove(
                global_context,
                &mut transcript,
                csprng,
                now,
                private_inputs,
            )?;
            verifiable_credentials.push(credential);
        }

        let linking_proof = LinkingProofV1 {
            created_at: now,
            proof_value: [],
            proof_type: ConcordiumLinkingProofVersion::ConcordiumWeakLinkingProofV1,
        };

        Ok(PresentationV1 {
            presentation_context: self.context,
            linking_proof,
            verifiable_credentials,
        })
    }
}

fn append_context(digest: &mut impl TranscriptProtocol, context: &ContextInformation) {
    digest.append_label("ConcordiumContextInformationV1");
    digest.append_message("given", &context.given);
    digest.append_message("requested", &context.requested);
}

impl<
        C: Curve,
        TagType: crate::common::Serialize + Ord,
        AttributeType: Attribute<C::Scalar> + Ord,
    > AtomicStatementV1<C, TagType, AttributeType>
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove(
        &self,
        version: ProofVersion,
        global: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        csprng: &mut impl rand::Rng,
        attribute_values: &impl HasAttributeValues<C::Scalar, TagType, AttributeType>,
        attribute_randomness: &impl HasAttributeRandomness<C, TagType>,
        revealed_attributes: &BTreeMap<TagType, &AttributeType>,
    ) -> Option<AtomicProofV1<C>> {
        match self {
            AtomicStatementV1::AttributeValue(statement) => {
                // If the attribute value has been revealed as part of the identity attributes
                // proof, we essentially need no proof for the statement.
                if let Some(_revealed_attribute) = revealed_attributes.get(&statement.attribute_tag)
                {
                    statement.prove_for_already_revealed(transcript);
                    Some(AtomicProofV1::AttributeValueAlreadyRevealed)
                } else {
                    let proof = statement.prove(
                        version,
                        global,
                        transcript,
                        csprng,
                        attribute_randomness,
                    )?;
                    let proof = AtomicProofV1::AttributeValue(proof);
                    Some(proof)
                }
            }
            AtomicStatementV1::AttributeInSet(statement) => {
                let proof = statement.prove(
                    version,
                    global,
                    transcript,
                    csprng,
                    attribute_values,
                    attribute_randomness,
                )?;
                let proof = AtomicProofV1::AttributeInSet(proof);
                Some(proof)
            }
            AtomicStatementV1::AttributeNotInSet(statement) => {
                let proof = statement.prove(
                    version,
                    global,
                    transcript,
                    csprng,
                    attribute_values,
                    attribute_randomness,
                )?;
                let proof = AtomicProofV1::AttributeNotInSet(proof);
                Some(proof)
            }
            AtomicStatementV1::AttributeInRange(statement) => {
                let proof = statement.prove(
                    version,
                    global,
                    transcript,
                    csprng,
                    attribute_values,
                    attribute_randomness,
                )?;
                let proof = AtomicProofV1::AttributeInRange(proof);
                Some(proof)
            }
        }
    }
}

impl<
        C: Curve,
        TagType: std::cmp::Ord + crate::common::Serialize,
        AttributeType: Attribute<C::Scalar>,
    > AtomicStatementV1<C, TagType, AttributeType>
{
    pub(crate) fn verify(
        &self,
        version: ProofVersion,
        global: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        cmm_attributes: &BTreeMap<TagType, Commitment<C>>,
        revealed_attributes: &BTreeMap<TagType, &AttributeType>,
        proof: &AtomicProofV1<C>,
    ) -> bool {
        match (self, proof) {
            (
                AtomicStatementV1::AttributeValue(statement),
                AtomicProofV1::AttributeValue(proof),
            ) => statement.verify(version, global, transcript, cmm_attributes, proof),
            (
                AtomicStatementV1::AttributeValue(statement),
                AtomicProofV1::AttributeValueAlreadyRevealed,
            ) => statement.verify_for_already_revealed(transcript, revealed_attributes),
            (
                AtomicStatementV1::AttributeInRange(statement),
                AtomicProofV1::AttributeInRange(proof),
            ) => statement.verify(version, global, transcript, cmm_attributes, proof),
            (
                AtomicStatementV1::AttributeInSet(statement),
                AtomicProofV1::AttributeInSet(proof),
            ) => statement.verify(version, global, transcript, cmm_attributes, proof),
            (
                AtomicStatementV1::AttributeNotInSet(statement),
                AtomicProofV1::AttributeNotInSet(proof),
            ) => statement.verify(version, global, transcript, cmm_attributes, proof),
            _ => false,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::id::constants::{ArCurve, AttributeKind};
    use crate::id::id_proof_types::{AttributeInRangeStatement, AttributeValueStatement};
    use crate::id::types::{AttributeTag, IpIdentity};
    use crate::web3id::did::Network;
    use crate::web3id::v1::{fixtures, ContextProperty};
    use crate::web3id::Web3IdAttribute;
    use std::marker::PhantomData;

    fn challenge_fixture() -> ContextInformation {
        ContextInformation {
            given: vec![ContextProperty {
                label: "prop1".to_string(),
                context: "val1".to_string(),
            }],
            requested: vec![ContextProperty {
                label: "prop2".to_string(),
                context: "val2".to_string(),
            }],
        }
    }

    /// Test that constructing proofs for a mixed (both identity and account credentials
    /// involved) request works in the sense that the proof verifies.
    #[test]
    fn test_completeness_identity_and_account() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements1, attributes1) = fixtures::statements_and_attributes();
        let (statements2, attributes2) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes1, &global_context);

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes2, &global_context);

        let subject_claims = vec![
            SubjectClaims::Identity(IdentityBasedSubjectClaims {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements: statements1,
            }),
            SubjectClaims::Account(AccountBasedSubjectClaims {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
                statements: statements2,
            }),
        ];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [
                    id_cred_fixture.private_inputs(),
                    acc_cred_fixture.private_inputs(),
                ]
                .into_iter(),
            )
            .expect("Cannot prove");

        let public = vec![
            id_cred_fixture.verification_material,
            acc_cred_fixture.verification_material,
        ];
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
    fn test_completeness_account() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![acc_cred_fixture.verification_material];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for account credentials. Tests empty set of statements.
    #[test]
    fn test_completeness_account_empty() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture =
            fixtures::account_credentials_fixture(BTreeMap::default(), &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements: vec![],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![acc_cred_fixture.verification_material];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for account credentials where
    /// verification fails because a statement is not what has been proven.
    #[test]
    fn test_soundness_account_statements_invalid() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialV1::Account(AccountBasedCredentialV1 { subject, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        subject.statements[2] = AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
            attribute_tag: 3.into(),
            lower: Web3IdAttribute::Numeric(200),
            upper: Web3IdAttribute::Numeric(1237),
            _phantom: PhantomData,
        });

        let public = vec![acc_cred_fixture.verification_material];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because statements are false. Tests revealed attribute.
    #[test]
    fn test_soundness_account_statements_invalid_revealed() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (mut statements, attributes) = fixtures::statements_and_attributes();

        statements[4] = AtomicStatementV1::AttributeValue(AttributeValueStatement {
            attribute_tag: 5.into(),
            attribute_value: Web3IdAttribute::String(
                AttributeKind::try_new("testvalue2".into()).unwrap(),
            ),
            _phantom: Default::default(),
        });

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![acc_cred_fixture.verification_material];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for account credentials where
    /// verification fails because issuer is not correct
    #[test]
    fn test_soundness_account_issuer() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change claimed issuer
        let CredentialV1::Account(cred) = &mut proof.verifiable_credentials[0] else {
            panic!("should be account proof");
        };
        cred.issuer = IpIdentity(10);

        let public = vec![acc_cred_fixture.verification_material];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for account credentials where
    /// verification fails because a statements not proven is added.
    #[test]
    fn test_soundness_account_statements_added() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialV1::Account(AccountBasedCredentialV1 { subject, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        subject.statements.push(AtomicStatementV1::AttributeInRange(
            AttributeInRangeStatement {
                attribute_tag: AttributeTag(4).to_string().parse().unwrap(),
                lower: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-27T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                upper: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-29T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                _phantom: PhantomData,
            },
        ));

        let public = vec![acc_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test verify fails if the credentials and credential inputs have
    /// mismatching types.
    #[test]
    fn test_soundness_account_mismatching_credential_types() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // use mismatching type of credential inputs
        let web3_cred_fixture = fixtures::identity_credentials_fixture(
            [(3.into(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let public = vec![web3_cred_fixture.verification_material];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test verify fails if the credentials and credential inputs have
    /// mismatching lengths.
    #[test]
    fn test_soundness_mismatching_credential_length() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            issuer: acc_cred_fixture.issuer,
            cred_id: acc_cred_fixture.cred_id,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::VerificationMaterialMismatch);
    }

    /// Test prove and verify presentation for identity credentials.
    #[test]
    fn test_completeness_identity() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![id_cred_fixture.verification_material];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for identity credentials. Tests empty set of statements.
    #[test]
    fn test_completeness_identity_empty() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let id_cred_fixture =
            fixtures::identity_credentials_fixture(BTreeMap::default(), &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements: vec![],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![id_cred_fixture.verification_material];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because statements are false.
    #[test]
    fn test_soundness_identity_statements_invalid() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialV1::Identity(IdentityBasedCredentialV1 { subject, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        subject.statements[2] = AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
            attribute_tag: 3.into(),
            lower: Web3IdAttribute::Numeric(200),
            upper: Web3IdAttribute::Numeric(1237),
            _phantom: PhantomData,
        });

        let public = vec![id_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because statements are false. Tests revealed attribute.
    #[test]
    fn test_soundness_identity_statements_invalid_revealed() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (mut statements, attributes) = fixtures::statements_and_attributes();

        statements[4] = AtomicStatementV1::AttributeValue(AttributeValueStatement {
            attribute_tag: 5.into(),
            attribute_value: Web3IdAttribute::String(
                AttributeKind::try_new("testvalue2".into()).unwrap(),
            ),
            _phantom: Default::default(),
        });

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![id_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because there are additional statements added compared to what is proven.
    #[test]
    fn test_soundness_identity_statements_added() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // add additional statement
        let CredentialV1::Identity(IdentityBasedCredentialV1 { subject, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        subject.statements.push(AtomicStatementV1::AttributeInRange(
            AttributeInRangeStatement {
                attribute_tag: AttributeTag(4).to_string().parse().unwrap(),
                lower: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-27T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                upper: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-29T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                _phantom: PhantomData,
            },
        ));

        let public = vec![id_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because verification of attribute credentials fails.
    #[test]
    fn test_soundness_identity_attribute_credentials() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change attribute credentials proof to be invalid
        let CredentialV1::Identity(IdentityBasedCredentialV1 { proof: proofs, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        let mut ar_keys = proofs
            .proof_value
            .identity_attributes_proofs
            .proof_id_cred_pub
            .keys();
        let ar1 = *ar_keys.next().unwrap();
        let ar2 = *ar_keys.next().unwrap();
        let tmp = proofs
            .proof_value
            .identity_attributes_proofs
            .proof_id_cred_pub[&ar1]
            .clone();
        *proofs
            .proof_value
            .identity_attributes_proofs
            .proof_id_cred_pub
            .get_mut(&ar1)
            .unwrap() = proofs
            .proof_value
            .identity_attributes_proofs
            .proof_id_cred_pub[&ar2]
            .clone();
        *proofs
            .proof_value
            .identity_attributes_proofs
            .proof_id_cred_pub
            .get_mut(&ar2)
            .unwrap() = tmp;

        let public = vec![id_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because verification of attribute credentials fails.
    #[test]
    fn test_soundness_identity_invalid_cred_id() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let subject_claims = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements,
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
            subject_claims,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // change ephemeral credential id to be invalid
        let CredentialV1::Identity(IdentityBasedCredentialV1 { subject, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        subject.cred_id.0 = vec![0, 1, 2];

        let public = vec![id_cred_fixture.verification_material];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }
}
