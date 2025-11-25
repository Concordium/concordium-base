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

    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
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

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_account() {
        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = fixtures::account_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    2.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    5.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
                ),
                (
                    6.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("bb".into()).unwrap()),
                ),
                (
                    AttributeTag(4).to_string().parse().unwrap(),
                    Web3IdAttribute::try_from(
                        chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
                            .unwrap()
                            .to_utc(),
                    )
                    .unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let proof_json = r#"
{
  "type": [
    "VerifiablePresentation",
    "ConcordiumVerifiablePresentationV1"
  ],
  "presentationContext": {
    "type": "ConcordiumContextInformationV1",
    "given": [
      {
        "label": "prop1",
        "context": "val1"
      }
    ],
    "requested": [
      {
        "label": "prop2",
        "context": "val2"
      }
    ]
  },
  "verifiableCredential": [
    {
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredentialV1",
        "ConcordiumAccountBasedCredential"
      ],
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "statement": [
          {
            "type": "AttributeInRange",
            "attributeTag": "dob",
            "lower": 80,
            "upper": 1237
          },
          {
            "type": "AttributeInSet",
            "attributeTag": "sex",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeNotInSet",
            "attributeTag": "lastName",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeInRange",
            "attributeTag": "countryOfResidence",
            "lower": {
              "type": "date-time",
              "timestamp": "2023-08-27T23:12:15Z"
            },
            "upper": {
              "type": "date-time",
              "timestamp": "2023-08-29T23:12:15Z"
            }
          },
          {
            "type": "AttributeValue",
            "attributeTag": "nationality",
            "attributeValue": "testvalue"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": "000000000000000502b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da88db85b1fecf20f66e9a4cca89ca261430d9a775de164636011003d72d1d522dae8488fb5ff2b348e8f4f4f68d7bc33e38a29abf47db4d15f9d1b703efff0ed234a668d779cad8e592041828446206bb98c48e23e06684405903c6cd14e06f4c4389c1954fd8c8be55052680025ff77e060416cea8d8a9cd512da8d6a4d3651092557b7ec885d994d32e775174bebb4f61630fdd1192dfa1cd0fe0b76cbdbc167571a3b82445887427d46f406f2e8139e93bd8950368cb74d9219fcf3cc195b7400000007a6bbc0b7dedae5d3c9b4096410d050e926f6aaa65b63d6e903bdf533762b3f0eab62286575e4261a5adcaf800aef0a3394b567034287af3f6fa990315e29ab084ccefeca9ef5a185a64170b169fd3c90d3f70ce1f0df4b1f2a8a88efefcf2ac9831d560dd6c8328b470d21163a8fc3174a2456e76bb0672b85fd8d14ee08b257e6b54df0c9bd2142ce9a176af53c3b6794aeacbdb1b40f22c4ae645b10b218a5cc6d50dbf7b374e706de7b6ec9faf72d89e6e91b3383b1ab3b6d2d5be95af2d192eddb29452b78545944d23b578dc4a364cd626e57fffc2e4e284e67c4c58d4a58029ad2fe82a74c4f79ef643e3d417493b5a25ffc04b8968cf6ad43a6ff2e0bdad32cd83fc26f958177add5a5dc61dfda8e3c95f17ebef3d0d364c2ba4f55eeb7e5f7beff294a7df714d83a5cbbf665b711877e4497941d5eb99b4ee4ddbcb0b22d04df8a2290d1c29a4d2b559f28308ff961fad1c524478e5fce35f2b05b64e3d36ddf55af7b269436ae1e06cb2b106af4d3465e171f8b2f8d5c7de50cb9068b186360d490384d75fedb0bdc6e7349ff43f86b6ac6a3578281aca11c1c15ee191da64f61e9a28cad750167ad86b781b7d204a1f241d65006c6ba2de1bbbe35d00d55893780c487e5e772c5a12f20b61ec355d75fedb5969096200f7d1afc5b805db4b2b001629af1cb3f6aaa3abef758c282261264b36525e7d16a76ecc09070e9a0ec300b679bd773137b81335fb792609ae55831fb97c96449e29a438ec9f60e9c6ffdebe8f3b168e33b51e3cec726067ddd143537f21713968f8dbb04c796b66f80e11f416c7db00b43d7272f824ea5e5059579e746c032310cbe801ecb5f04b23346926141ee8b79e2e4d522bd93d263844569fdb5a5f29e522c31868408a82b29d6b0392c1ff173431155190c630145f1c9ad989060c456e7979b32b46ea6e831a80f9d4bdd4b3bb5dfa32cac82415a5258a1d3528eddf116378d51c449b7071b1902c289f468d5212aabb6fea40a3d4e9cddd9444e00b1b36369bb6c03b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b1ae7e6d38e19aa6374b3db2d0ed6918fac19a79981df368bb842f5b3e88ed9f88af521c771e336233d35dab81a3ef02b12475047f017ddc597aa597f49dadc9cbb0c72cb50b08c7e3a155f35b7879d64ea48923d6a550399e33a167dc783c7f6ced1b69d4180cca76304febb32c320703294b174da590c3607aa1651f0a88573997ddc59deb816d401a5130517c7a81f1e92cd4e5511bbdc15dd8762a9d285616c3a0b58c0ed867cc74128f52006aeb802f1a07237c66d8c4feef00fd2b1ae400000002a83a469f8f002dc2bf11e8c1b65e2a17b1f398c6806744425e444bffeafc34128320d8a061e226b6d7541ee0e0466327b14b41d7d8142aa18f5b3e734ca8b07cbe0d024a0f648e4db512ee56f4e7ef71d08b1fe3985db75d0beb6e1cc9b8c428971e9c0858baed4e935768dd2201aa82cfbf1692770dc92c7558f23fd46f5d050cd11a1cb476380011fca121f1ce23b9b43e16948af3b3fe4c8a15d4ff935476b23a67f14b0d2ee19a9c48ab89228be2772d63a50fe87fb9ce56dbf43f261b8a0de90b8f7cf375db6016b9b3fa0af14594312df176ea4070eae321a8b22f573c7183f0d3655b15dda99339fd9caa66e9134861e6504c7cc8188c19d1756383ec048b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaa506a369ea1e6bf58a89075f51344b7db1e4899a12383642a04091aaaef9fcf49281d22d23faca75c7de65be46fb3ae787822af473431d3b611a1aa63051cf37c2a5cae78b26e6e66e8994d62a5b1098bf61306a3418422199a614e4b09269953ec7d6cd85b83e0d4bb6d5370506f505e0e255e3fc86321938647e5638d47a3f711431d0e050a141c2d7a9ff7473515d24fcf7d49df7c62c7a311de1ba74e1eb017f29dec74a0c4b6c1033754c4cec0c45c85e99c62e654d0b6ed8087e811b560000000286384013b18b78f466a96c266b36cd1b3ae84b6746e1cddb521d5248c62eac29c1f7faddfe5094ce8fd5b457d65f0fc18c018bcac96884e2907c390ee2ecbe057336d4c1bd0c6edeba8340910f5ed88b1169283ff98cfecb016af2476595f835806f969e3a7b594d41af1abf47619d929ca35323890888d58febdb488ce9a2a170dcdc0222a6b33d1ce367702a5e6f6e84bb20150993878b7e5023bf51c427b7bf8cfb7b504e5e0258b25c7fe094a79dd4051c2807f480a36bf6d38795526a4f02ee00fa5456eac9e78022d1593bba9d6f4b09c064558cc5d433b81346c7b4f60c731be525a641825de736e0ea4776de5cbbe0c4d8c5b9c080b8160a39f868e702b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c862afeedd50d8b65c822e69a213b0fc8f2e4188289ebbc5828ff043f0365453989208210c97536a7e9ee865af8872688935b3a9616c8802e3482a4074d0b759e11d052195453ef95945cd0557916d80a9eda70f61ffc653ce99d66caf1cdf7f0688f3bd5adc04f23552b0ef780e6c804f2738b60c3e812cc36c9c02484a47b831c0ff050e1513f54ba97372b1b8b48a278a56d5088ef09d2f24a6c9b95697c1406e4718f3bc71070191eaff6f89ce06c9aa5fedaeb0dabbbd4da46eb22a74ae200000007a5df6c977b2cceed7dc03296768edbe510f0674341d6732cd366a56b13469408ca9a94c1bd50f77074e351ebd8ec6a9485fa5193e1d6574ed673a8ea871fcf9621b0a67f370f56f882c062360c0f4038c1afb1d25dfb554f03b7757a71e61f21ab3baa7c7ac3d30ef2d5328fff37fb6658052001b90bf00000d1b553d8fe988342bee11e6cd1423131c019a9766272069248846381908bbefcf3129f8dbc3cf848ce7fa2e8e7d90c51e03634cf23574ecf51b9efb3b5c244bbbaf8f136c2e917874397a528529aa95cd3076f0ad4fe1751d25e5351dc4fbe28efabae297827a47f902d822b561304db940dfec34db5778e00039f96cb100e76c29cd3b71733f139054e8a39df0d5644285ac93486a2374ecea315f961f59a9c9f6d18fce437e286e11cc988e03ba537773e37fee3bd4a222bcc4361743621916bfd8e982b5957ce2f1dedc3e5fdedea8ae8574ef10e2ab24f53383813f54832fc7b3e79bc7a82c46b4b66ff5aa24086a59041ca4d9db7bff59c37820129d9f3df31007c17d1e48e63b20c1b9ca5106b3baac41a29318810fa8fed1e954c2cd4793db870fed9b17350aeea535ed51ff96fff8c1d7b67518a913efebe3dc3eaac543787be142064eb2fa0559b9f4e570d297ecf1d09bb704595217a5643016e52df4e1c20c0be398ef9832c8343626967d7f81eadd5d81d27a208ed586ef24d69ce7101e4a8384fc5a3cd25716c550c73a4b079d297b507a4ca1d6099346c31b4ade498589f40a04d072e6e9a664e07c9165eb8bb2d1f7568c00c09e4421cf5da5a466684df2e3987f692dff494949916f3bde458fd16f3ef4ddf09563b93b239ea442430d449c27a21215b5dba2930237640088c5d176cb3e5941d5f0a56982b2b05f35503cfc007b730475f28f4241ac28c5f955723f9d92124ab4aab89d198444db0de63fc100df9dab06a3e0591a5096877b581e7304278af7fe8778c13df4f0bc72e0801e663f075db89c119b8639b836a3d6026ec7610ed05fc405228c03e2bec4d60d61b00fee62d95135d4f7f9b06628d14597d9045d70e3d27d9ab7847b71e968b3639f70b5faf58f07543f340c7b5a6a12542209795ae19544a3e32bd966df630815b60",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": "",
    "type": "ConcordiumWeakLinkingProofV1"
  }
}
"#;
        let proof: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![acc_cred_fixture.verification_material];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_identity() {
        let global_context = GlobalContext::generate("Test".into());

        let id_cred_fixture = fixtures::identity_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    2.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    5.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
                ),
                (
                    6.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("bb".into()).unwrap()),
                ),
                (
                    AttributeTag(4).to_string().parse().unwrap(),
                    Web3IdAttribute::try_from(
                        chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
                            .unwrap()
                            .to_utc(),
                    )
                    .unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let proof_json = r#"
{
  "type": [
    "VerifiablePresentation",
    "ConcordiumVerifiablePresentationV1"
  ],
  "presentationContext": {
    "type": "ConcordiumContextInformationV1",
    "given": [
      {
        "label": "prop1",
        "context": "val1"
      }
    ],
    "requested": [
      {
        "label": "prop2",
        "context": "val2"
      }
    ]
  },
  "verifiableCredential": [
    {
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredentialV1",
        "ConcordiumIdBasedCredential"
      ],
      "credentialSubject": {
        "id": "did:ccd:testnet:encidcred:04000500000001a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412f959d6060a0b98ae6c2d1f08ab3e173f02ceb959c69c30eb55017c74af4179470adb3b3b7b5e382bc8fd3dc173d7bc6b400000002acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c280e2dc5cac96c5e428adcc4cd9de19b7704df058a5c938c894bf03a94298fc5f741930c575f8f0dd1af64052dcaf4f00000000038b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae057787793917a120aaf73f3caeec5adfc74d43f7ab4d920d89940a8e1cf5e73df89ff49cf95ac38dbc127587259fcdd8baec00000004b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c962776f4a4698f6e30c4ed4d4aca5583296fd05ca86234abe88d347b506073c32d8b87b88f03e9e888aa8a6d76050b2200000005b0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc10410930a5f6bc26b8b3b65c82748119af60f17f1e114c62afa62f7783b20a455cd4747d6cda058f381e40185bb9e6618f4e4",
        "statement": [
          {
            "type": "AttributeInRange",
            "attributeTag": "dob",
            "lower": 80,
            "upper": 1237
          },
          {
            "type": "AttributeInSet",
            "attributeTag": "sex",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeNotInSet",
            "attributeTag": "lastName",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeInRange",
            "attributeTag": "countryOfResidence",
            "lower": {
              "type": "date-time",
              "timestamp": "2023-08-27T23:12:15Z"
            },
            "upper": {
              "type": "date-time",
              "timestamp": "2023-08-29T23:12:15Z"
            }
          },
          {
            "type": "AttributeValue",
            "attributeTag": "nationality",
            "attributeValue": "testvalue"
          }
        ]
      },
      "validFrom": "2020-05-01T00:00:00Z",
      "validUntil": "2022-05-31T23:59:59Z",
      "issuer": "did:ccd:testnet:idp:0",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc9dda27a50094cba9bfcf801e64dbe683c0b71926a7185436e942f8c8077566b3000000050000000115726915418468b26d6e74190b76915057b8a4241cce9c45ce7fb9eebadb10380d3c58996247f9589b75d980c22cb52bba4474635acdd36ca9608b03a4fa17071d2475f082a64d60185b4e66be4c25d82abc0da2539127a03835c23c92cbae27000000023c9d71ca25a598cb0ea22848c766906ff6ae52cd30b32e0aea57905edf89c7a06c424eb85df08da398507bf2a2d60873a927d42479a08e902c247555b5a54c266c4447fa40a7a8c1f693e71a628fe46d844ce6a79b9a76ddf5a3c682db641dd900000003687dde67f4bf5a0a89cf32468d344b296f8f243d6fa5946f96c04c2e9aa506b14330a6083226b65b55c3cea3985ab39b60b8d0db1bd812fb2ada6e14288da2fd07db10ace62993c934944bd63b11a0b1c098059905a6777970d04365c085d1da0000000409dcbd1240c0fc6eaa35254ccc5cb724442bbf38c7c1d37912b1fcccad403f2e2a68dc38582ba48dadae94def9b6bcca09cc8a76d1fe7d6a76e6891dfba34ba55e5cd0bb1bc71976f9f85768b82bdfe47664c6e2f6e87c4bc836c898b4fcfe780000000538f72551c6300c32bd3401901113c1a0de21b6c411f7b23dcb0978021c06043e27a762ac3f79325a7da5c92520bf30930a15b4f8e1f8e0345a8920944def95ab2244e704856d61cc42dc2b7765939b408f73150f0bba0069d43a388dc4b9af4c5adb834750b09315c12cc625f1813f9417f72f6d367f47585584c45d6471aa6d0000000c000438badd11174560b10965889ef2a5e06c7e10a049b1ca950b5641a7a6fa0d2c2dee4aa278a8d7dcba3625824033c4bae0c8336a73afe374f1366b8acec0b22602560a5a195d54241d9307176e66834046001a5d73649e7fc557829d89d897855701010102338aa101037d164c46e745fe608dd7bedb3dcc66eb8b6f1fdd0b6843e7260c3200198b0abade3d91b3a0dd7e23cad15f1e671037ef0a600b882f6b832defe318db20dcf6376d42d73fc9db0bfd4fc2c63110951792167ddddc89500980551f9bb70049f2851c9793009b5eb009d32a102358596a79fa951176c475e1cce3ab454c4064269569c392c56309f2ca90b77af6254209dab87841ed35042a44270ae946cf00496a71478e437a843beb8e522295c9b3479b4a28b77dd624268693eb9538d2ae5105514841b593230dfb8c64936082a79c76e0df7392049895001ccc0f81739d002e3175e30fe6f0eb0ef6ebcba037b75dcace321379a487be6db7ea03de3fa5a057cd6a8a6c24a45847ad6941fc7e3c347a39260427c7f413b95821064aff6e1a01023cbcc2d00f1f28d79687747b0e4fb70b22319e39fefb76a90ef22e021f96ff55000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4b092dd34e11fd7dd65823bd9a28f6169fba00b9b82cb9a8e149f43421c17a98aa5d382d05056a988c0956d330ff55f9caf87e8f23f45b9c3fd46fd17de35b9288ed1fde6fa48135fd76e331da22d2ebeaaa90098c9fb5744358a77cbf3a3043f51203db2a0423969266759114978722c077c55d02bffa1f76c8fcb85395cab013c3ba44446b18d561753335da9236fac7cb618432492eb7d992d699cc240456120da4c2712b9a44b640af2033485fd918ae817e81cf0e26057c66371f1b2b7b0000000079580daa7ed6bfd9662c47231c3094a8f96c2c25e5c0eba5336343eca68747f7e9918ac172c2211a43438fd47b136bd628ff969687ca71147490780b44914c168c007ed619431b041287d549fb96d51e6b41e7c28eadcfe553d53b870acac4594a6010d523918c8862810fc6c8cde78e3e5965735c1d00f0ef9b5cc4902ae52ec62010d0f98b9d07c78a3ae3eb1676f56b07a0ab8716ebea736ceffd92045eed660158cc24864a23b5b3e0cac55c68051dffaefcdaca795ff97e093d901173faeadc00b2053ae59cbb36864862c30bbcfa5032e1516590e380c2b5073cd1bc3e76ae8f8dc4edc892ebbe15805271f98c0ac22ef9e0daecde89e16bbf0f5e0206c32a54ed875a3de1e86d560f615c8c6cca5fe74d2c096003486caddbd6185b859b2502a5d05bd9ac863faa0a2ca54eabe1fab68df7086d78a486f688d4419bac0ca6b29288d9ee95df17e27d269bcff0fa521802f55a178e6189c4fc4e0c9aacc7641935f9750f7af0aac001a0efb0e2436afe8d40637b5f1b40858878bfa5ae8a017b3217a716ebdf27a1723a93865fe088c834cff4c2e27ebcac37e3d23b7bfc4a96f4d0d3e1ebf1f13ad4a81f7c73482802590d0c0dea55147cc163fbd143db10aeb8505a2d9ee098a6c47bc41fe032d729becf1b7131249773a9efd811e9caebd1d72658785b32470eab5708287532a4a4a4a91073b5b77e693c393ede85f4d23c77d4e7accf7460976f7ed911d9090748eb9498c76bb8ba173367a5963a938d8c2173d20db10bcc7c452f1f19f93b31a02b6f24794413dc183ea2bf157388d22397beb12e6e4a626ab32e6740a0c3d9bcb49579c27a479d5cf6f2d98b1227c690d734161166bbf9caff311f2c504a4dda5e53b70b8738b18dfa4fbb5ecd0b074885db065516a7a19b78c63dc1f5a72a8b843b5ea3c1b49feaccfa55216a81dd028a44797f262a0b42d1e617490f16f575f44991cd02f1a679d6695a0137b02423d96ee162d768f0ef1c74980e5728bfcda5fa69d451e3a64dea119b16aab039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1e8106424aff358bd337af5576ce1a48243e21c3b73051a87b7a914ef68645f82f5c2b1a8af8def5d639feea0fa02f625f9397619ff9538ec5ca1238e7f26451a7036e9319fbe3baadcefe0f09d32a37cbc7644b92ab9e984304fe7ee22886d8e7331b923ccea38b31cd4c5b6e21ea7b13f93a74d2e4e5c5abe8f48efdc901055541e152730c07ed5c80c97a3538602df6b37cbc864618781c1728ca3d13af97b33e922b8722a17d7b3397dbd604ea26446aee03488924d55a8dca65731db96bbd00000002a753709610f96d22afb715d26c8586d8971f9201ba327d6eb4a0ff5ee0943f81f7eef7901d85fdd59b18d825b64accae87447036ee703852251d2b9d0d9add516ea1c1ac8f68168e881c4a6ebfb1f9c1c7e7098b7aabf9e0a2efa2423186f7f4898dfca0ef6f07fdbd180a2a164d21b18b0424d7f7e9c93d326e3ab308062bf644184b0e76e3782b27de5b4b971b127a904946ecd4b94a21158d8ffc0f040b6dde6f044dc084ce27a016a1677099f3b335237a19623edc4940193bf706197b2832e1f8a77215de4dc73fab8cf1e1e090f57e5db737174759e3434b4da5feeefa41be4bf511821326cb664dcb6705c926e135c0de63e86b3c0fb1db02a47ecda00487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeea30b4541acc1c039323dfeb5a8bb81396cee8e41a591c6c559f24181b3f1d9a1cf386dbbc74e601480099930464fff2f820ffefe9c1754ea7220ab4fb95a73bd217f7440d26d803077031d039a09f366221c1d60f761f70bcfe592e099e41b4a5bd088cd1ece3af477e1d13f03c1459ad22b42f3479f12d7229de52d7f4ef95c689a33ade597a8902964e244e6cca0d1f94de905f9fccf95b774ed2b8c2a36f061f3a8da53b11d71d9855c79face7dac770caf93e5e9d7fbd6b2907f994bf8e6000000028c27c3a9d06054e718d61e0c97597c3e2aa2fa7b372b61e37fd02004a58cd9a9db0e4aa75995de479dc528369aae7850971c7a68b793ac91d3f8e31fe12200a63cd651d0fef437981c041f1417c0a7b35ffc2725f19ea6f47b2db483ad3c28b1ac997b445bb2fb55c276fb800e331cd8a406efc9074101a3b477df4d1fa187a27a07e58e3d0a5fff80d9c33f5b0d9f0685a41e8378e99fe37e7376290d971afcd3548fd6e7ab783c338558a58c7f4b17b3f2f19892b8fab86f297ad4fc25ba8107bdfd243161d90f6439adafe37e70edf6d318489571acc3761f12ca134dd42713dcd3d4e4bf11bdbabb6771a1d11f406969ed4f1b3dea7d32c292ffa07a302a02b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f470898974118b864ba4ea9442144f894abfdc952071f586c663ee9c7daaa100295213bf22a96b9c2562d7f4bdbc878e59a5dff96d1793ff7a7819b528ee718513bcd5d6f44cb1ff1433d4a6a72d95a3e9c2f9bdf179fc0d999a689ba5f10717dd812bef9cab61b118dfc80d1f16fed604130e256bc3cbbd4a3f9e7aa656e685d9f801845f043178b7aad99f9214e790c31939f6b85e3d876351377a3d57b3c85d84876a93fd039a4ff13d73c3564d8cd9c4310b4e7bbc27f907b10b6f95c09c853e6edbb84300000007ac2df00a78778a0e2e4ab221df2686305b7c4f369c9393d83d2398442fd650d3d49a9171e64b20c4b341e8c5f0153bab845202926b803c5eef4d10937696d1f2917a5c1ddfa86860b780c7e9cdca49bc0c07973d1a2a77fa6688176e3c88c933afc37a04d49778bb6c3eac0ef42a67cde86dbee2825f12f848ed2383af2da472dde4fc29b9ed9267480363f587f5babcb86c0965845495f3b5cda6f3cd5d5784a3123b89a74b7732b51dfbbfb28cd9ea0f635c4920711cc8bc9512154ef679ddac1730212ea8cc4718c1085583c5c40b964f1aa0689595a8b6d1869f23a8d857c68251863f5c3e57c62f73d40090b437a337db8b01b5b258f5217fb81b634edea1f942224a7d6bb9124272a99f038980976a8df52094c62fe7dc6a07cbe2e67aa413ddead30ad92e54c0cdc1b915d2bedfef9660fa69b513736ca221fa4bd6ce054c90ebd9ddae7cce9f0c02630cfe7f88f8fec518d60cd79fd9f9acd653b8cb8707dc463eb942faf56308d8afd89a5d1f690a43203cb72049183431d0e291888a344544ea7d38ae1db3ee49d6d9790e1baa80abbe54db280593b9a7f632a0bd9298cc93f298b8b0a7b91eaddc1856e2ad00c721bb2099d944fa0a847513fa51bfca7822fb8163794fa28e8bc9712dc2f2cd5b6f53c66dd8a536f869447dbf39b4accb28dcec7de58ad83819bcc4ab0b966b165bb8e0bfcb30a6280e588cac873e9b3919a8bb8c3418f4cecfc2e14e60b47259143898aeb7380ef76d93c8e5102ffdedb793e49f23cba70e9ec04475394fffea2d0c6273730a101314589fc9c7ab713604443a0e8c7816d10d6581fa30fdb1552c61025ae3e85d46e7dd38e90d1a6d8d4921c806d9dfc84a7a0497335c8b9e4be2db89512fd2ca332ebb66ec302da2ab68f2a40cf3b957720348b7ac5414b9c7c3bf05c88fe606a31b69b5d6e606a0d8dce4c0952d047fec38e28ef722bfae923ca9104f1742f1df96ef9650543e19d25a3b6e8f93e0ac26841120c46cd416e9fa4a111b1ad3b8a171033d26a901",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": "",
    "type": "ConcordiumWeakLinkingProofV1"
  }
}
"#;
        let proof: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![id_cred_fixture.verification_material];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }
}
