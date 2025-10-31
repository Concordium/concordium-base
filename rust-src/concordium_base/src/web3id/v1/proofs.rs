use crate::random_oracle::StructuredDigest;
use crate::{
    curve_arithmetic::Curve,
    id::types::{Attribute, GlobalContext},
    random_oracle::RandomOracle,
};

use crate::web3id::{
    CommitmentInputs, CredentialsInputs, LinkingProof, PresentationVerificationError, ProofError,
    WeakLinkingProof, Web3IdBasedCredential, Web3IdSigner, LINKING_DOMAIN_STRING,
};
use ed25519_dalek::Verifier;

use crate::curve_arithmetic::Pairing;
use crate::web3id::v1::{
    ContextChallenge, CredentialV1, CredentialStatementV1, PresentationV1, CredentialMetadataV1,
    RequestV1,
};
use rand::{CryptoRng, Rng};

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    PresentationV1<P, C, AttributeType>
{
    /// Get an iterator over the metadata for each of the verifiable credentials
    /// in the order they appear in the presentation.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item =CredentialMetadataV1> + '_ {
        self.verifiable_credentials.iter().map(|cp| cp.metadata())
    }

    /// Verify a presentation in the context of the provided public data and
    /// cryptographic parameters.
    ///
    /// In case of success returns the [`RequestV1`] for which the presentation
    /// verifies.
    ///
    /// **NB:** This only verifies the cryptographic consistentcy of the data.
    /// It does not check metadata, such as expiry. This should be checked
    /// separately by the verifier.
    pub fn verify<'a>(
        &self,
        params: &GlobalContext<C>,
        public: impl ExactSizeIterator<Item = &'a CredentialsInputs<P, C>>,
    ) -> Result<RequestV1<C, AttributeType>, PresentationVerificationError> {
        let mut transcript = RandomOracle::domain("ConcordiumVerifiablePresentationV1");
        append_context(&mut transcript, &self.presentation_context);
        transcript.append_message(b"ctx", &params);

        let mut request = RequestV1 {
            challenge: self.presentation_context.clone(),
            credential_statements: Vec::new(),
        };

        // Compute the data that the linking proof signed.
        let to_sign =
            linking_proof_message_to_sign(&self.presentation_context, &self.verifiable_credentials);

        let mut linking_proof_iter = self.linking_proof.proof_value.iter();

        if public.len() != self.verifiable_credentials.len() {
            return Err(PresentationVerificationError::InconsistentPublicData);
        }

        for (cred_public, cred_proof) in public.zip(&self.verifiable_credentials) {
            request.credential_statements.push(cred_proof.statement());
            if let CredentialV1::Web3Id(Web3IdBasedCredential { holder: owner, .. }) =
                &cred_proof
            {
                let Some(sig) = linking_proof_iter.next() else {
                    return Err(PresentationVerificationError::MissingLinkingProof);
                };
                if owner.public_key.verify(&to_sign, &sig.signature).is_err() {
                    return Err(PresentationVerificationError::InvalidLinkinProof);
                }
            }
            if !cred_proof.verify(params, &mut transcript, cred_public) {
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

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialV1<P, C, AttributeType>
{
    /// Verify a single credential. This only checks the cryptographic parts and
    /// ignores the metadata such as issuance date.
    fn verify(
        &self,
        global: &GlobalContext<C>,
        transcript: &mut RandomOracle,
        public: &CredentialsInputs<P, C>,
    ) -> bool {
        match self {
            CredentialV1::Account(cred_proof) => cred_proof.verify(global, transcript, public),
            CredentialV1::Web3Id(cred_proof) => cred_proof.verify(global, transcript, public),
            CredentialV1::Identity(cred_proof) => {
                cred_proof.verify(global, transcript, public)
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialStatementV1<C, AttributeType> {
    fn prove<P: Pairing<ScalarField = C::Scalar>, Signer: Web3IdSigner>(
        self,
        global: &GlobalContext<C>,
        ro: &mut RandomOracle,
        csprng: &mut impl rand::Rng,
        now: chrono::DateTime<chrono::Utc>,
        input: CommitmentInputs<P, C, AttributeType, Signer>,
    ) -> Result<CredentialV1<P, C, AttributeType>, ProofError> {
        match self {
            CredentialStatementV1::Account(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialV1::Account),
            CredentialStatementV1::Web3Id(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialV1::Web3Id),
            CredentialStatementV1::Identity(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialV1::Identity),
        }
    }
}

fn linking_proof_message_to_sign<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    challenge: &ContextChallenge,
    proofs: &[CredentialV1<P, C, AttributeType>],
) -> Vec<u8> {
    use crate::common::Serial;
    use sha2::Digest;
    // hash the context and proof.
    let mut out = sha2::Sha512::new();
    challenge.serial(&mut out);
    proofs.serial(&mut out);
    let mut msg = LINKING_DOMAIN_STRING.to_vec();
    msg.extend_from_slice(&out.finalize());
    msg
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> RequestV1<C, AttributeType> {
    /// Construct a proof for the [`RequestV1`] using the provided cryptographic
    /// parameters and secrets.
    pub fn prove<'a, P: Pairing<ScalarField = C::Scalar>, Signer: 'a + Web3IdSigner>(
        self,
        params: &GlobalContext<C>,
        attrs: impl ExactSizeIterator<Item = CommitmentInputs<'a, P, C, AttributeType, Signer>>,
    ) -> Result<PresentationV1<P, C, AttributeType>, ProofError>
    where
        AttributeType: 'a,
    {
        self.prove_with_rng(params, attrs, &mut rand::thread_rng(), chrono::Utc::now())
    }

    /// Construct a proof for the [`RequestV1`] using the provided cryptographic
    /// parameters and secrets. The source of randomness and "now" are given
    /// as arguments.
    pub fn prove_with_rng<'a, P: Pairing<ScalarField = C::Scalar>, Signer: 'a + Web3IdSigner>(
        self,
        params: &GlobalContext<C>,
        attrs: impl ExactSizeIterator<Item = CommitmentInputs<'a, P, C, AttributeType, Signer>>,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PresentationV1<P, C, AttributeType>, ProofError>
    where
        AttributeType: 'a,
    {
        let mut proofs = Vec::with_capacity(attrs.len());
        let mut transcript = RandomOracle::domain("ConcordiumVerifiablePresentationV1");
        append_context(&mut transcript, &self.challenge);
        transcript.append_message(b"ctx", &params);
        if self.credential_statements.len() != attrs.len() {
            return Err(ProofError::CommitmentsStatementsMismatch);
        }
        let mut signers = Vec::new();
        for (cred_statement, attributes) in self.credential_statements.into_iter().zip(attrs) {
            if let CommitmentInputs::Web3Issuer { signer, .. } = attributes {
                signers.push(signer);
            }
            let proof = cred_statement.prove(params, &mut transcript, csprng, now, attributes)?;
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
            created: now,
            proof_value,
        };
        Ok(PresentationV1 {
            presentation_context: self.challenge,
            linking_proof,
            verifiable_credentials: proofs,
        })
    }
}

fn append_context(digest: &mut impl StructuredDigest, context: &ContextChallenge) {
    digest.add_bytes("ConcordiumContextInformationV1");
    digest.append_message("given", &context.given);
    digest.append_message("requested", &context.requested);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::id::constants::{ArCurve, IpPairing};
    use crate::id::id_proof_types::{AtomicStatement, AttributeInRangeStatement};
    use crate::web3id::did::Network;
    use crate::web3id::v1::ContextProperty;
    use crate::web3id::{
        fixtures, AccountBasedCredential, AccountCredentialStatement, IdentityBasedCredential,
        IdentityCredentialStatement, Web3IdAttribute, Web3IdCredentialStatement,
    };
    use std::marker::PhantomData;

    fn challenge_fixture() -> ContextChallenge {
        ContextChallenge {
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

    /// Test that constructing proofs for web3 only credentials works in the
    /// sense that the proof verifies.
    #[test]
    fn test_completeness_web3() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![web3_cred_fixture.credential_inputs];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Test that constructing proofs for web3 only credentials works in the
    /// sense that the proof verifies. Tests empty set of statements.
    #[test]
    fn test_completeness_web3_empty() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred_fixture =
            fixtures::web3_credentials_fixture(BTreeMap::default(), &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements: vec![],
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![web3_cred_fixture.credential_inputs];
        assert_eq!(
            proof
                .verify(&global_context, public.iter())
                .expect("verify"),
            request,
            "verify request"
        );
    }

    /// Prove and verify where verification fails because
    /// signature on commitments in invalid.
    #[test]
    fn test_soundness_web3_commitments_signature() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // change commitments signature to be invalid
        let CredentialV1::Web3Id(Web3IdBasedCredential { commitments, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be web3 proof");
        };
        commitments.signature = web3_cred_fixture.issuer_key.sign(&[0, 1, 2]);
        fix_weak_link_proof(
            &mut proof,
            &challenge,
            web3_cred_fixture.commitment_inputs(),
        );

        let public = vec![web3_cred_fixture.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    fn fix_weak_link_proof(
        proof: &mut PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
        challenge: &ContextChallenge,
        cmm_input: CommitmentInputs<IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
    ) {
        let CommitmentInputs::Web3Issuer { signer, .. } = cmm_input else {
            panic!("should be web3 inputs");
        };
        let to_sign = linking_proof_message_to_sign(challenge, &proof.verifiable_credentials);
        let signature = signer.sign(&to_sign);
        proof.linking_proof.proof_value[0] = WeakLinkingProof { signature };
    }

    /// Prove and verify where verification fails because
    /// a statements is invalid.
    #[test]
    fn test_soundness_web3_statements() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialV1::Web3Id(Web3IdBasedCredential { proofs, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be web3 proof");
        };
        proofs[2].0 = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 3.to_string(),
                lower: Web3IdAttribute::Numeric(200),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };
        fix_weak_link_proof(
            &mut proof,
            &challenge,
            web3_cred_fixture.commitment_inputs(),
        );

        let public = vec![web3_cred_fixture.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Prove and verify where verification fails because
    /// linking proof is missing or invalid or too many.
    #[test]
    fn test_soundness_web3_linking_proof() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge: challenge.clone(),
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![web3_cred_fixture.credential_inputs];
        let CommitmentInputs::Web3Issuer { signer, .. } =
            CommitmentInputs::from(&web3_cred_fixture.commitment_inputs)
        else {
            panic!("should be web3 inputs");
        };

        // add additional linking proof
        let signature = signer.sign(&[0, 1, 2]);
        proof
            .linking_proof
            .proof_value
            .push(WeakLinkingProof { signature });

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::ExcessiveLinkingProof);

        // remove linking proofs
        proof.linking_proof.proof_value.clear();

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::MissingLinkingProof);

        // add invalid linking proof
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
    #[test]
    fn test_completeness_web3_and_account() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements1, attributes1) = fixtures::statements_and_attributes();
        let (statements2, attributes2) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes1, &global_context);

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes2, &global_context);

        let credential_statements = vec![
            CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements: statements1,
            }),
            CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements: statements2,
            }),
        ];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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
    }

    /// Test prove and verify presentation for account credentials.
    #[test]
    fn test_completeness_account() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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

    /// Test prove and verify presentation for account credentials. Tests empty set of statements.
    #[test]
    fn test_completeness_account_empty() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture =
            fixtures::account_credentials_fixture(BTreeMap::default(), &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements: vec![],
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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
        let CredentialV1::Account(AccountBasedCredential { proofs, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        proofs[2].0 = AtomicStatement::AttributeInRange {
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
    fn test_soundness_account_mismatching_credential_types() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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

        // use mismatching type of credential inputs
        let web3_cred_fixture = fixtures::web3_credentials_fixture(
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
    /// mismatching types.
    #[test]
    fn test_soundness_web3_mismatching_credential_types() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let web3_cred_fixture = fixtures::web3_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
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
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // use mismatching type of credential inputs
        let acc_cred_fixture = fixtures::account_credentials_fixture(
            [(3.into(), Web3IdAttribute::Numeric(137))]
                .into_iter()
                .collect(),
            &global_context,
        );

        let public = vec![acc_cred_fixture.credential_inputs];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Test verify fails if the credentials and credential inputs have
    /// mismatching lengths.
    #[test]
    fn test_soundness_mismatching_credential_length() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
                network: Network::Testnet,
                cred_id: acc_cred_fixture.cred_id,
                statements,
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
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

        let public = vec![];

        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InconsistentPublicData);
    }

    /// Test prove and verify presentation for identity credentials.
    #[test]
    fn test_completeness_identity() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatement {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements,
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![id_cred_fixture.credential_inputs];
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

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatement {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements: vec![],
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let public = vec![id_cred_fixture.credential_inputs];
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
    fn test_soundness_identity_statements() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatement {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements,
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // change statement to be invalid
        let CredentialV1::Identity(IdentityBasedCredential { proofs, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        proofs.statement_proofs[2].0 = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 3.into(),
                lower: Web3IdAttribute::Numeric(200),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let public = vec![id_cred_fixture.credential_inputs];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    /// Test prove and verify presentation for identity credentials where
    /// verification fails because verification of attribute credentials fails.
    #[test]
    fn test_soundness_identity_attribute_credentials() {
        let challenge = challenge_fixture();

        let global_context = GlobalContext::generate("Test".into());

        let (statements, attributes) = fixtures::statements_and_attributes();

        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatement {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements,
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let mut proof = request
            .clone()
            .prove(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        // change attribute credentials proof to be invalid
        let CredentialV1::Identity(IdentityBasedCredential { proofs, .. }) =
            &mut proof.verifiable_credentials[0]
        else {
            panic!("should be account proof");
        };
        let mut ar_keys = proofs.identity_attributes_proofs.proof_id_cred_pub.keys();
        let ar1 = *ar_keys.next().unwrap();
        let ar2 = *ar_keys.next().unwrap();
        let tmp = proofs.identity_attributes_proofs.proof_id_cred_pub[&ar1].clone();
        *proofs
            .identity_attributes_proofs
            .proof_id_cred_pub
            .get_mut(&ar1)
            .unwrap() = proofs.identity_attributes_proofs.proof_id_cred_pub[&ar2].clone();
        *proofs
            .identity_attributes_proofs
            .proof_id_cred_pub
            .get_mut(&ar2)
            .unwrap() = tmp;

        let public = vec![id_cred_fixture.credential_inputs];
        let err = proof
            .verify(&global_context, public.iter())
            .expect_err("verify");
        assert_eq!(err, PresentationVerificationError::InvalidCredential);
    }

    // todo ar add stability tests
}
