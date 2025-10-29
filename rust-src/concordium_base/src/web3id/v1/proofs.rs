use crate::random_oracle::StructuredDigest;
use crate::{
    curve_arithmetic::Curve,
    id::types::{Attribute, GlobalContext},
    random_oracle::RandomOracle,
};

use crate::web3id::{
    CommitmentInputs, CredentialsInputs, LinkingProof, PresentationVerificationError, ProofError,
    WeakLinkingProof, Web3IdCredentialProof, Web3IdSigner, LINKING_DOMAIN_STRING,
};
use ed25519_dalek::Verifier;

use crate::curve_arithmetic::Pairing;
use crate::web3id::v1::{
    ContextChallenge, CredentialProofV1, CredentialStatementV1, PresentationV1, ProofMetadataV1,
    RequestV1,
};
use rand::{CryptoRng, Rng};

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    PresentationV1<P, C, AttributeType>
{
    /// Get an iterator over the metadata for each of the verifiable credentials
    /// in the order they appear in the presentation.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = ProofMetadataV1> + '_ {
        self.verifiable_credential.iter().map(|cp| cp.metadata())
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
            linking_proof_message_to_sign(&self.presentation_context, &self.verifiable_credential);

        let mut linking_proof_iter = self.linking_proof.proof_value.iter();

        if public.len() != self.verifiable_credential.len() {
            return Err(PresentationVerificationError::InconsistentPublicData);
        }

        for (cred_public, cred_proof) in public.zip(&self.verifiable_credential) {
            request.credential_statements.push(cred_proof.statement());
            if let CredentialProofV1::Web3Id(Web3IdCredentialProof { holder: owner, .. }) =
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
    CredentialProofV1<P, C, AttributeType>
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
            CredentialProofV1::Account(cred_proof) => cred_proof.verify(global, transcript, public),
            CredentialProofV1::Web3Id(cred_proof) => cred_proof.verify(global, transcript, public),
            CredentialProofV1::Identity(cred_proof) => {
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
    ) -> Result<CredentialProofV1<P, C, AttributeType>, ProofError> {
        match self {
            CredentialStatementV1::Account(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialProofV1::Account),
            CredentialStatementV1::Web3Id(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialProofV1::Web3Id),
            CredentialStatementV1::Identity(cred_stmt) => cred_stmt
                .prove(global, ro, csprng, now, input)
                .map(CredentialProofV1::Identity),
        }
    }
}

fn linking_proof_message_to_sign<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    challenge: &ContextChallenge,
    proofs: &[CredentialProofV1<P, C, AttributeType>],
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
            verifiable_credential: proofs,
        })
    }
}

fn append_context(digest: &mut impl StructuredDigest, context: &ContextChallenge) {
    digest.add_bytes("ConcordiumContextInformationV1");
    digest.append_message("given", &context.given);
    digest.append_message("requested", &context.requested);
}
