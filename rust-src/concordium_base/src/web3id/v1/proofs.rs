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
            let mut transcript = transcript.clone();

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
        let transcript = TranscriptProtocolV1::with_domain("ConcordiumVerifiableCredentialV1");
        self.prove_with_transcript(global_context, private_inputs, csprng, now, transcript)
    }

    pub fn prove_with_transcript<'a, P: Pairing<ScalarField = C::Scalar>>(
        self,
        global_context: &GlobalContext<C>,
        private_inputs: impl ExactSizeIterator<
            Item = CredentialProofPrivateInputs<'a, P, C, AttributeType>,
        >,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
        mut transcript: impl TranscriptProtocol + Clone,
    ) -> Result<PresentationV1<P, C, AttributeType>, ProveError>
    where
        AttributeType: 'a,
    {
        let mut verifiable_credentials = Vec::with_capacity(private_inputs.len());
        append_context(&mut transcript, &self.context);
        transcript.append_message("GlobalContext", &global_context);

        if self.subject_claims.len() != private_inputs.len() {
            return Err(ProveError::PrivateInputsMismatch);
        }
        for (subject_claims, private_inputs) in self.subject_claims.into_iter().zip(private_inputs)
        {
            // The proof for each credential is independent, so make a copy of the transcript so far
            let mut transcript = transcript.clone();

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
    use crate::random_oracle::TranscriptProtocolTracer;
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

    /// Test generate and verify presentation containing multiple credentials.
    #[test]
    fn test_completeness_multiple_credentials() {
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
        "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc022d40f10bd9f0db027ee76e5d78722b22605a1f420c0d8923f384fd2e9df4d500000005000000014996e6a8d95d738baf684228c059ffda43b6a801240c467ff648b24c1e32a8fa25e6348ea46cfe7a6134f6754367715ab1fa97f963720164fd4af47882ea5f5c68917936ca63783c8e7252b3add6d60427580f639caec877eaf62af847e260b0000000022edfd6a9b5f6cb325c2ddafc2f37328768062360b94ff89b795eefc2bdd8b8c7566f982f3189e2158c9932e6c2236beae9c4a1767de64235066fc668c43590a466a5e08b9552ff74c7850795edfb41de40a8183b3ae27e25e14a851192492649000000035477e4693d1f65ba2c6d911de408be4b4164ae853b9d944859a7125c7f80c8b6737b58adf891170ac056de0907671899121fede2fd7cbcd6c266fef9d011baf65e6529fb326268ad4394ac4bdcd594901d2d649c9633ed273d47472550a6ed1d00000004636f324e0c8d9958f960f621ba0bdb0a12c2fdac465fab6f3d6b0219edf20bda34bcc475e9e940e5f2c166aab81bb46a24fe84a7c150f60f19b25a9aa26b02960fb8204657da982ecc80099255157f127037fc1d01bae5e751dfd1b568d5d3b2000000055252326e4bd286ff449e1e4191ad5bfd3834498357850252b2efdf71e5a195801b0b139f690a241db78ffae798e90adf5468ed485dd47c396dafdbf95846ab3f1dfc26f4044279839a74ef3d99d3e683ddfd948707a841052beed7fa59d3cfe10a85e4f590f94aeec5694aa34ce7809e6409635c3dcc06c48e2b6eb7c88e805b0000000c0044de5e492f26cdc8d9dd7353c8f4561776db5cf1e9e56765f8a27325bea23c7c6e93ee0e96b86044e30a334d6a3574f1eb257fbc13e38045de829d08e668e1760233b357f18e2fb13b681affb3100a76389289b0a672fb4c018b496086e907a8d9010101024a3c3d379c549361b01f1da35dc354171e8b08e37cde8b26708a7d0a74a1c475001607576a587bc3724829d37a211c4e7ac685f5d2ff8d183878c47761fa207a2772c92a29d9723c60fcf02a5f3ee44f16c8d719ef0ff7306017e8abcca0ac43da002c1306c3df6c321d1827b482e5bdd43d9ae0ebda13ee87f8ffce45b9280974d30da67ed93028333a98441ec283b84ef993ba16ee3f63abeb6913cb84c6087e520031d913edbe710a6ef608a7496ddb24b62af6dc53b0c400515094a102dc34ba7e5101b14654477c70600fc619c536a55689a34483d87a607c616b8e4a7f588b1c0020de9f2cbea7cb077e1dc06c4f2f3286792ff9ab865d04a264699b063387d3565a810470a1a3f0b94ed0a313bf2558035cb562112fe9d4ce3db05035da60dfb401023ecf78fe04bea07742a2b68c1dfc848ced58d50cc72e3aa9417456c137f07042000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4975a76ced40574074001091721440b1d62252454c2b26494f5014ef4b5f0adaab23eea032dabcf7fc274915ed26a38ea985468e8f27f81f378870fdf0c9fa880b75d301d54dead22ebe69d98305b8bcb1825f77084a3fe794ef69ae07ca2f40c327c3b8055a8dc2823524df825d4748e84c743856120bf5bc77826884412154e26cf2b601c2b869084806c5e670919b8cb8d6ea8f7a8fd14096f7dc9765bcd0d5a04e5770764de9318b0f4f5fd1343b30f0954656423cbb994da605956acc5e30000000792698ceb941b32e6ff12451a75d1eb465ca0710879a4d67ecf75ff5e614605b7284f07109a658007dd94b499322649a68af4e7b7ad848fbc3e2dfe248fe846d0836279a0a8045909516fa2de9ce9d456e68278372af302a891a3c138596bb369abb626f0e5ccd6ceb9d6f7f0bd979a37afdeff02c294ad7db9ad1335f0d532027bf7fc78c7fe3d1025bbd9b754e8ce068ef1e251727d48cb25040091f05b327ac2ec733c1cb349f6aa20c00f644a3f9c84df72112b4f4b247126df77eb27933db078a098bc904d01ce5de1be0fdb9d8796b3d427c7a89d7ace44209339c5577416dff5094858771314c6dcb8562f7d17a30c84630530510bff914ff0398b4616171386c23145d4cff3e4a0f698715bd68dbe2233b851ee49c17c0b7dc9b6f5f4ae461de98c4d582c8be6f490e75a0c2b1a61dfca366e86ca6ed131b93d43c93292f6182cf3d86e98d0baf613630e7a34a54dcba10f680b641579909c138223182443f71f110d7eb97d0bc99c795d95f28611ddf484208c3aa9763b517024d32faaea07a4343e4fa9b72ffb951fddd5e811def887a8d92e89c574d7820ed46df10da13e63ec1223d2bf1ee4b8f6cd353eae032fd8b3f6f886d5feb3032ac2c6cef1f03513e04646ffdbd0be6597f674bfcbce9f16127b43aa49f4e6853c56e2cd96c75aab089f07d04515e52a097c1b08c75ddb30315af1d65aebd00585c3818e7587baa5b11b80a0fd5fd2e0b7b473c9ad112a3168aadaf83ba4d94ad7e6b47c639684d634fe5ae59fc1f9e6741e924bdc8ed49c2a72bf1e7869fff80d17a7a0adacbf2123fbed51683d0897fd76310f3896381f47c675764b6475a027f92a0b89d863218dce9b3ac48524b3d1def4f0877aeab34415a27e33d305e9ae39dc8c918125498ab16932378e9f739bd2e0c4866265ff9f98c7b562000c762254336c3ac576cdfd96936c3f32ded9523594401d0ad2f2232a01b9c8443395180f1ec80a119e63e0bf631cb93a9db4ee6a2a29e06f520835f7af238e1c8cd873bef1e4039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1e86c2ef60ae3a42de23a15550c75b135a7be766fc38a2554377afc4892fef23e54ad59b72bfa590493d3a0e6d0c3692f9b12c28a4c2fcbfc8331381867935bdbdbe83220fe2330b5024ffdaeb37eb9a4f8dc8505ff846ce16a24ad0f36b8145591838c8cd056b4fa56d76e3f0d3c04cd58a13fc953ac12f292817ad4c1b46d62e372b5a5f8c7f3a4dcb29beb03b75d7b9d0a4a463e37f00da224c7fde6d34c3d53f34ac41a47b698e9b381d0debc448c465c594d9cf9c42e8cbce7e0e03091000000000028f08b690d86821cdcd517648214e22b5b0b73e2c7f82a3ccae933d61bc0e28fc69b047aba5cc6b8e9e6f4578e02924db920fdd2cbc3f1171c98169f4fd5676b77f210f9ae5e949afab54b2e52137538906ea05c5fc5e0ca989eb081a3ba9285ea611a9d69bbefb08d3142a7523a3ca91961b4f6deaa87286a4fe776607572b5db7e6ea488c5b9007731663b4537b584983937bfa8ec12bc8f6b1ec8185cb2863f7dc15f82f50978301f7441901d2921799af71fbf5f3a83162ddaed844b5647970b4bf4cb7d8bae88457f65c2e5f09b71b6585303e4783642c20949423fba406002407e6a58cd57836650e76df878926d0b6315f4c4329385566667701fe7f820487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeb5ed24f1e21e96aa8f81d1b57f7963fdb0d617a6c302365781dcbe1628103ba3e9fb7c05ec5064aa5f518a2dd54deb3bb6547660749326b8e7c23931f938d1f94b2b199330c7cf4e21caaf3586b5ce3f56d5a1a06a78729f9e8b7838eef1f95828f2e1f46ccd7642fae51f13d2b0d6c55b328e0d6bae6355d412db989f82a3fa47b167da18c385588da0d8b2715d09c06cb2e03a1bccf8e112893d054c79b8d850d3c90fc8866865a2f85a8b3f64d9dfad1381b1bc0653335ac741925dccaac600000002895dca7ed412bae0cb70d758773dcfbb2254c95be80f230ceb3a73883bd6b6220cff45b7e9d058da58071acb8a32767b99a869379b6095f4e2b7ddecbd8a4d17a094f9681a4345c35c87dd86cba4074e56dae9e1ddadb7edfa248058f12f8f0c965d922130d696027a12fdfd06b1c39c7fba1875b39f751be361ccf330dfcdfa68623eb78747bc06f9ac45b812d5d313abfbfabdb4411220d1e78b5384749bb890b3f220139e0200315d516b3fb2e156b2a5c1c2a081a3e67eb6e8fc97be9bb4439a9eaadaab8e29db023baa98322d0d0e7f06efd708b5c7f8846e799e8607a20242d81c399a6571f8ea9c203a534ebfc6bf416540b8ad6a2c82e66dd9d2c0c502b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411aaae9e0b0179b2e09afee8e5d56ea05b85694d71186f6d6dba1465c19cfc41f55751c1c7e3e071f0a97733f2ad4a8d7eb5038bb97411c01f77d451d483611c939f1910f388110198c69a2efdce02ad2334a1c39958bd66abb940ef1f42143a65010e383128f291e962c579ec7cb9f24f373554e84ce1a21f459d5ea4ab1a41ec733322f9b95611de75450bf415e60dc15f8d33fdb61f14d9c73c92cd6ace0943403768e8947e8122b2cbbc663a5373940daf22b914730c980c66e87e444db56f000000078c1751517b7f76514a5ea7af097099c03cc64d9416494d5a9f448c2615903650ab7c8c2358619073d84f04034ba7f768b62b4825d8a12f4c0378b2b271eb05f8b3cff514ebdae3b6de637539305437c2bc0bc6c2649961a1d22295035d07f460863a3d0467f01e79c4199bf3dd73a57a58315be6b4e465e43fe66e82dc933ee622598672fbd0c5bae12d8e187c7a6dc8a2c4b3dc57040a759e23594760d76c8d6655c0860e4a1187e89d7451b1507bc5e0ff3eeb28577af943a44afb61d96eca898cb8417551edffc189fe2d24e83f554206c397b80153044e45be32aef5b46deff4625d1d316338bf3521ee32ef50388a067b5c0972ca68797b98b337c09589c307d5adfac00a524ccca6d8d5450a0eea765673fbea3956aa0edf0dc0a2c7318dd61540865a408715c148e406489f7e56d953af3df90585b2dd12e99a4a6878009001b62f9fa0a023041fd77f41be2da2ed746a07bb3fa3864ab5e76be4f98d480fd97280735eb9f44c6bb0b1b02e2ee8c9d1c71c68de3325e6d14f44ef98b68b50ddef96b312c9a17296ecf837591659252f25670d9744c7334abca978eab4d7c40276b876ca682c2c06ba2809082d842c021fadb934bff19025c4dc1d80f6a9fac3cf59a7209c1d73113b87b8d34a8d618a5534db6fbc4492cfb6439a2c088cbbd44febb15f56e1d119bbf1e2bd108325711d56938eeffce12ecc900059822448666fd380701afb94887ff3a73d5ab6e3a9614ec319bb579d02de414db8a02d54f80928255dafc2b7833159aab87daffd5e143e7e939ec2c05496573f7de1aa46492cc29053e0ab0d7a2b524b3cade5e2ee0fbb0aa8f0b340cf139321230da9d50df0e36794ff03927ebdfaeb5b4c88612f9a7cb6660d8a088433ec92cd24ad06e4bb75885b0b7103d524f4f6b080be40484b9138278d95feb40af1c52cbb29f7623675d081c0930866586fee0476a9f21bffe406e3265413f792e0d464e9476becd32bb6af4856aaf4dfdbd6f1a2fea4cbe6df332e324f091fa74e7d9cdf01",
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

    /// Test prove and verify presentation for identity credentials.
    #[test]
    fn test_transcript_trace_identity() {
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

        let transcript = TranscriptProtocolTracer::new(TranscriptProtocolV1::with_domain(
            "ConcordiumVerifiableCredentialV1",
        ));

        let proof = request
            .clone()
            .prove_with_transcript(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
                &mut rand::thread_rng(),
                chrono::Utc::now(),
                transcript,
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
}
