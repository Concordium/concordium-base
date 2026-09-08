//! A dedicated API for *proofs of ID credential*: a zero-knowledge proof, derived from an ID
//! credential, that attests only that the holder owns a valid credential. No attribute values,
//! ranges or set memberships are proven or revealed.
//!
//! The entrypoints are [`IdCredentialProofRequest::prove`] for constructing a proof and
//! [`IdCredentialProof::verify`] for verifying one.
//!
//! This is deliberately a separate API from the general verifiable presentation API in the
//! [parent module](super), so that the construction can be changed in the future without
//! disturbing the statement and presentation types. A proof serializes as an ordinary
//! [`PresentationV1`], so existing verifiers of presentations can verify it as well.
//!
//! # What is proven
//!
//! For an [identity credential](IdCredentialSubject::Identity) the proof is a presentation with
//! an empty statement list. That is already a proof of ownership: verifying it checks the proof
//! of knowledge of the identity provider's signature on the identity object together with the
//! privacy guardian encryptions of `IdCredPub`.
//!
//! For an [account credential](IdCredentialSubject::Account) an empty statement list would prove
//! nothing at all, since there is no signature knowledge to check — only the claimed issuer is
//! compared. Instead the proof asserts knowledge of the opening of *every* attribute commitment
//! of the credential, via one [`AttributeOpeningKnownStatement`] per committed attribute. As for
//! every other account based statement proof, soundness rests on the commitment openings being
//! secret.

use crate::base::CredentialRegistrationID;
use crate::common;
use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::id_proof_types::ProofVersion;
use crate::id::types::{
    Attribute, GlobalContext, HasAttributeRandomness, HasAttributeValues, IpIdentity,
};
use crate::pedersen_commitment::{Commitment, CommitmentKey};
use crate::random_oracle::TranscriptProtocol;
use crate::sigma_protocols::aggregate_dlog::{AggregateDlog, Response as AggregateDlogResponse};
use crate::sigma_protocols::common::{prove as sigma_prove, verify as sigma_verify, SigmaProof};
use crate::web3id::did;
use crate::web3id::did::Network;
use crate::web3id::v1::{
    take_field_de, AccountBasedSubjectClaims, AccountCredentialVerificationMaterial,
    AtomicStatementV1, ContextInformation, CredentialMetadataV1, CredentialProofPrivateInputs,
    CredentialVerificationMaterial, IdentityBasedSubjectClaims, PresentationV1, ProveError,
    RequestV1, SubjectClaims, VerifyError,
};
use anyhow::{bail, ensure};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::de::{DeserializeOwned, Error as _};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// For the case where the verifier wants the user to prove knowledge of the opening of the
/// commitment to an attribute, without revealing anything about the attribute value.
#[derive(Debug, PartialEq, Eq, Clone, common::Serialize, serde::Serialize, serde::Deserialize)]
pub struct AttributeOpeningKnownStatement<TagType: common::Serialize> {
    /// The attribute whose commitment opening the verifier wants the user to prove knowledge of.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: TagType,
}

/// Proof of an [`AttributeOpeningKnownStatement`], i.e. of knowledge of the value and the
/// randomness inside the on-chain commitment to the attribute.
#[derive(Debug, Clone, Eq, PartialEq, common::Serialize, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct AttributeOpeningKnownProof<C: Curve> {
    /// Proof of knowledge of the two exponents `(value, randomness)` of the commitment.
    pub proof: SigmaProof<AggregateDlogResponse<C>>,
}

/// Add the public data of the opening proof to the transcript. Must be called identically by the
/// prover and the verifier, before the sigma protocol runs.
fn append_opening_public_data<C: Curve>(
    transcript: &mut impl TranscriptProtocol,
    key: &CommitmentKey<C>,
    commitment: &Commitment<C>,
) {
    transcript.append_label(b"AttributeOpeningKnownProof");
    transcript.append_message(b"keys", key);
    transcript.append_message(b"C", commitment);
}

/// The sigma protocol proving knowledge of `(value, randomness)` such that
/// `commitment = g^value * h^randomness`, where `g` and `h` are the commitment key generators.
fn opening_protocol<C: Curve>(
    key: &CommitmentKey<C>,
    commitment: &Commitment<C>,
) -> AggregateDlog<C> {
    AggregateDlog {
        public: commitment.0,
        coeff: vec![key.g, key.h],
    }
}

impl<TagType: common::Serialize + Ord> AttributeOpeningKnownStatement<TagType> {
    /// Prove the statement. The `version` is accepted for uniformity with the other atomic
    /// statements, but this proof does not depend on it.
    pub(crate) fn prove<C: Curve, AttributeType: Attribute<C::Scalar>>(
        &self,
        _version: ProofVersion,
        global: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        csprng: &mut impl rand::Rng,
        attribute_values: &impl HasAttributeValues<C::Scalar, TagType, AttributeType>,
        attribute_randomness: &impl HasAttributeRandomness<C, TagType>,
    ) -> Option<AttributeOpeningKnownProof<C>> {
        let value = attribute_values.get_attribute_value(&self.attribute_tag)?;
        let randomness = attribute_randomness
            .get_attribute_commitment_randomness(&self.attribute_tag)
            .ok()?;

        let key = &global.on_chain_commitment_key;
        let value_scalar = value.to_field_element();
        let commitment = key.hide_worker(&value_scalar, &randomness);

        append_opening_public_data(transcript, key, &commitment);

        let prover = opening_protocol(key, &commitment);
        let secret = vec![Rc::new(value_scalar), Rc::new(*randomness)];
        let proof = sigma_prove(transcript, &prover, secret, csprng)?;
        Some(AttributeOpeningKnownProof { proof })
    }

    /// Verify a proof of the statement. The `version` is accepted for uniformity with the other
    /// atomic statements, but this proof does not depend on it.
    pub(crate) fn verify<C: Curve>(
        &self,
        _version: ProofVersion,
        global: &GlobalContext<C>,
        transcript: &mut impl TranscriptProtocol,
        cmm_attributes: &BTreeMap<TagType, Commitment<C>>,
        proof: &AttributeOpeningKnownProof<C>,
    ) -> bool {
        let Some(commitment) = cmm_attributes.get(&self.attribute_tag) else {
            return false;
        };

        let key = &global.on_chain_commitment_key;
        append_opening_public_data(transcript, key, commitment);

        let verifier = opening_protocol(key, commitment);
        sigma_verify(transcript, &verifier, &proof.proof)
    }
}

/// The credential that an [`IdCredentialProof`] is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdCredentialSubject {
    /// An identity credential issued by an identity provider, i.e. the identity object held by
    /// the credential holder.
    Identity {
        /// Network to which the identity credential was issued.
        network: Network,
        /// Identity provider that issued the identity credential.
        issuer: IpIdentity,
    },
    /// An on-chain account credential deployed from an identity credential.
    Account {
        /// Network on which the account credential exists.
        network: Network,
        /// Identity provider that issued the identity credential the account was deployed from.
        issuer: IpIdentity,
        /// Registration id of the account credential.
        cred_id: CredentialRegistrationID,
    },
}

const CONCORDIUM_ID_CREDENTIAL_PROOF_REQUEST_TYPE: &str = "ConcordiumIdCredentialProofRequestV1";
const CONCORDIUM_ID_CREDENTIAL_SUBJECT_TYPE: &str = "ConcordiumIdCredentialSubjectV1";
const CONCORDIUM_IDENTITY_BASED_ID_CREDENTIAL_SUBJECT_TYPE: &str =
    "ConcordiumIdBasedIdCredentialSubject";
const CONCORDIUM_ACCOUNT_BASED_ID_CREDENTIAL_SUBJECT_TYPE: &str =
    "ConcordiumAccountBasedIdCredentialSubject";

impl serde::Serialize for IdCredentialSubject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Identity { network, issuer } => {
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_ID_CREDENTIAL_SUBJECT_TYPE,
                        CONCORDIUM_IDENTITY_BASED_ID_CREDENTIAL_SUBJECT_TYPE,
                    ],
                )?;
                map.serialize_entry("issuer", &did::Method::new_idp(*network, *issuer))?;
            }
            Self::Account {
                network,
                issuer,
                cred_id,
            } => {
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_ID_CREDENTIAL_SUBJECT_TYPE,
                        CONCORDIUM_ACCOUNT_BASED_ID_CREDENTIAL_SUBJECT_TYPE,
                    ],
                )?;
                map.serialize_entry(
                    "id",
                    &did::Method::new_account_credential(*network, *cred_id),
                )?;
                map.serialize_entry("issuer", &did::Method::new_idp(*network, *issuer))?;
            }
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for IdCredentialSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let types: BTreeSet<String> = take_field_de(&mut value, "type")?;

            let issuer: did::Method = take_field_de(&mut value, "issuer")?;
            let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                bail!("expected issuer did, was {}", issuer);
            };

            if types
                .iter()
                .any(|ty| ty == CONCORDIUM_IDENTITY_BASED_ID_CREDENTIAL_SUBJECT_TYPE)
            {
                Ok(Self::Identity {
                    network: issuer.network,
                    issuer: idp_identity,
                })
            } else if types
                .iter()
                .any(|ty| ty == CONCORDIUM_ACCOUNT_BASED_ID_CREDENTIAL_SUBJECT_TYPE)
            {
                let id: did::Method = take_field_de(&mut value, "id")?;
                let did::IdentifierType::Credential { cred_id } = id.ty else {
                    bail!("expected account credential did, was {}", id);
                };
                ensure!(
                    issuer.network == id.network,
                    "issuer and account registration id network not identical"
                );
                Ok(Self::Account {
                    network: id.network,
                    issuer: idp_identity,
                    cred_id,
                })
            } else {
                bail!(
                    "unknown ID credential subject types: {}",
                    types.iter().format(",")
                )
            }
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

impl serde::Serialize for IdCredentialProofRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", CONCORDIUM_ID_CREDENTIAL_PROOF_REQUEST_TYPE)?;
        map.serialize_entry("context", &self.context)?;
        map.serialize_entry("subject", &self.subject)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for IdCredentialProofRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let ty: String = take_field_de(&mut value, "type")?;
            ensure!(
                ty == CONCORDIUM_ID_CREDENTIAL_PROOF_REQUEST_TYPE,
                "expected type {}",
                CONCORDIUM_ID_CREDENTIAL_PROOF_REQUEST_TYPE
            );
            Ok(Self {
                context: take_field_de(&mut value, "context")?,
                subject: take_field_de(&mut value, "subject")?,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

impl IdCredentialSubject {
    /// The network of the credential.
    pub fn network(&self) -> Network {
        match self {
            Self::Identity { network, .. } | Self::Account { network, .. } => *network,
        }
    }

    /// The identity provider that issued the credential.
    pub fn issuer(&self) -> IpIdentity {
        match self {
            Self::Identity { issuer, .. } | Self::Account { issuer, .. } => *issuer,
        }
    }
}

/// A request for a proof that the holder owns a valid ID credential.
///
/// Prove it with [`IdCredentialProofRequest::prove`], supplying the credential secrets as
/// [`CredentialProofPrivateInputs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdCredentialProofRequest {
    /// Context that the proof is bound to. Must contain enough verifier-chosen entropy that a
    /// proof cannot be replayed; see [`ContextInformation`].
    pub context: ContextInformation,
    /// The credential that the proof must be derived from.
    pub subject: IdCredentialSubject,
}

impl IdCredentialProofRequest {
    /// Prove that the holder owns the requested ID credential.
    ///
    /// Fails with [`ProveError::PrivateInputsMismatch`] if the private inputs are for a
    /// different kind of credential, or a different issuer, than the request asks for.
    pub fn prove<
        'a,
        P: Pairing<ScalarField = C::Scalar>,
        C: Curve,
        AttributeType: Attribute<C::Scalar> + 'a,
    >(
        self,
        global_context: &GlobalContext<C>,
        private_inputs: CredentialProofPrivateInputs<'a, P, C, AttributeType>,
    ) -> Result<IdCredentialProof<P, C, AttributeType>, ProveError> {
        self.prove_with_rng(
            global_context,
            private_inputs,
            &mut rand::thread_rng(),
            chrono::Utc::now(),
        )
    }

    /// Prove that the holder owns the requested ID credential, with the source of randomness and
    /// "now" given as arguments.
    pub fn prove_with_rng<
        'a,
        P: Pairing<ScalarField = C::Scalar>,
        C: Curve,
        AttributeType: Attribute<C::Scalar> + 'a,
    >(
        self,
        global_context: &GlobalContext<C>,
        private_inputs: CredentialProofPrivateInputs<'a, P, C, AttributeType>,
        csprng: &mut (impl Rng + CryptoRng),
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<IdCredentialProof<P, C, AttributeType>, ProveError> {
        let subject_claims = match (&self.subject, &private_inputs) {
            (
                IdCredentialSubject::Identity { network, issuer },
                CredentialProofPrivateInputs::Identity(inputs),
            ) => {
                // The issuer of the produced credential is taken from the identity provider
                // context, so a mismatch here would silently prove a different claim than the
                // one requested.
                if inputs.ip_context.ip_info.ip_identity != *issuer {
                    return Err(ProveError::PrivateInputsMismatch);
                }
                SubjectClaims::Identity(IdentityBasedSubjectClaims {
                    network: *network,
                    issuer: *issuer,
                    statements: Vec::new(),
                })
            }
            (
                IdCredentialSubject::Account {
                    network,
                    issuer,
                    cred_id,
                },
                CredentialProofPrivateInputs::Account(inputs),
            ) => {
                if inputs.issuer != *issuer {
                    return Err(ProveError::PrivateInputsMismatch);
                }
                // Knowledge of the opening of every attribute commitment is what makes this a
                // proof of ownership. With no commitments there would be nothing to prove.
                if inputs.attribute_randomness.is_empty() {
                    return Err(ProveError::IdCredentialProof(
                        "the account credential has no attribute commitments",
                    ));
                }
                let statements = inputs
                    .attribute_randomness
                    .keys()
                    .map(|attribute_tag| {
                        AtomicStatementV1::AttributeOpeningKnown(AttributeOpeningKnownStatement {
                            attribute_tag: *attribute_tag,
                        })
                    })
                    .collect();
                SubjectClaims::Account(AccountBasedSubjectClaims {
                    network: *network,
                    issuer: *issuer,
                    cred_id: *cred_id,
                    statements,
                })
            }
            _ => return Err(ProveError::PrivateInputsMismatch),
        };

        let request = RequestV1 {
            context: self.context,
            subject_claims: vec![subject_claims],
        };
        let presentation =
            request.prove_with_rng(global_context, std::iter::once(private_inputs), csprng, now)?;
        Ok(IdCredentialProof(presentation))
    }
}

/// A proof that the holder owns a valid ID credential, and nothing more. It is the response to
/// proving an [`IdCredentialProofRequest`], and is verified with [`IdCredentialProof::verify`].
///
/// Serializes as the [`PresentationV1`] it wraps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdCredentialProof<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(PresentationV1<P, C, AttributeType>);

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    IdCredentialProof<P, C, AttributeType>
{
    /// Metadata of the credential the proof is derived from. This contains data that must be
    /// verified externally, such as the credential validity, as well as the data needed to look
    /// up the [`CredentialVerificationMaterial`].
    pub fn metadata(&self) -> CredentialMetadataV1 {
        // The shape invariant guarantees exactly one credential.
        self.0.verifiable_credentials[0].metadata()
    }

    /// View the proof as the verifiable presentation it is.
    pub fn as_presentation(&self) -> &PresentationV1<P, C, AttributeType> {
        &self.0
    }

    /// Deconstruct the proof into the verifiable presentation it is.
    pub fn into_presentation(self) -> PresentationV1<P, C, AttributeType> {
        self.0
    }

    /// Verify the proof in the context of the provided verification material. On success returns
    /// the [`IdCredentialProofRequest`] that the proof establishes.
    ///
    /// Notice: as for [`PresentationV1::verify`], this only verifies the cryptographic
    /// consistency of the data. Metadata such as credential expiry must be checked separately;
    /// see [`CredentialMetadataV1`].
    pub fn verify(
        &self,
        global_context: &GlobalContext<C>,
        verification_material: &CredentialVerificationMaterial<P, C>,
    ) -> Result<IdCredentialProofRequest, VerifyError> {
        let request = self
            .0
            .verify(global_context, std::iter::once(verification_material))?;

        // `PresentationV1::verify` established that the material matches the credential and that
        // the statements hold, so what is left is that the claims are the ones a proof of ID
        // credential makes.
        let [claims] = request.subject_claims.as_slice() else {
            return Err(VerifyError::NotAnIdCredentialProof(
                "expected exactly one credential",
            ));
        };

        let subject = match claims {
            SubjectClaims::Identity(claims) => {
                if !claims.statements.is_empty() {
                    return Err(VerifyError::NotAnIdCredentialProof(
                        "expected no statements on the identity credential",
                    ));
                }
                IdCredentialSubject::Identity {
                    network: claims.network,
                    issuer: claims.issuer,
                }
            }
            SubjectClaims::Account(claims) => {
                let CredentialVerificationMaterial::Account(
                    AccountCredentialVerificationMaterial {
                        attribute_commitments,
                        ..
                    },
                ) = verification_material
                else {
                    // Cannot happen: the verification above rejects a type mismatch.
                    return Err(VerifyError::NotAnIdCredentialProof(
                        "verification material does not match the credential",
                    ));
                };

                if attribute_commitments.is_empty() {
                    return Err(VerifyError::NotAnIdCredentialProof(
                        "the account credential has no attribute commitments",
                    ));
                }

                let mut proven = BTreeSet::new();
                for statement in &claims.statements {
                    let AtomicStatementV1::AttributeOpeningKnown(statement) = statement else {
                        return Err(VerifyError::NotAnIdCredentialProof(
                            "expected only commitment opening statements on the account \
                             credential",
                        ));
                    };
                    proven.insert(statement.attribute_tag);
                }

                // Every commitment must be opened. Accepting a subset would let a prover open a
                // single commitment and thereby claim ownership of the whole credential. The
                // length comparison additionally rejects a repeated attribute.
                if proven.len() != claims.statements.len()
                    || !attribute_commitments.keys().eq(proven.iter())
                {
                    return Err(VerifyError::NotAnIdCredentialProof(
                        "the proven commitment openings are not exactly the commitments of the \
                         credential",
                    ));
                }

                IdCredentialSubject::Account {
                    network: claims.network,
                    issuer: claims.issuer,
                    cred_id: claims.cred_id,
                }
            }
        };

        Ok(IdCredentialProofRequest {
            context: request.context,
            subject,
        })
    }
}

/// Check that a presentation has the shape of a proof of ID credential, as far as can be
/// determined without verification material. The remaining check, that the proven commitment
/// openings cover the credential exactly, needs the material and so happens in
/// [`IdCredentialProof::verify`].
fn check_shape<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    presentation: &PresentationV1<P, C, AttributeType>,
) -> anyhow::Result<()> {
    let [credential] = presentation.verifiable_credentials.as_slice() else {
        bail!("expected exactly one credential");
    };
    match credential.claims() {
        SubjectClaims::Identity(claims) => ensure!(
            claims.statements.is_empty(),
            "expected no statements on the identity credential"
        ),
        SubjectClaims::Account(claims) => {
            ensure!(
                !claims.statements.is_empty(),
                "expected at least one commitment opening statement on the account credential"
            );
            ensure!(
                claims
                    .statements
                    .iter()
                    .all(|s| matches!(s, AtomicStatementV1::AttributeOpeningKnown(_))),
                "expected only commitment opening statements on the account credential"
            );
        }
    }
    Ok(())
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    TryFrom<PresentationV1<P, C, AttributeType>> for IdCredentialProof<P, C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(presentation: PresentationV1<P, C, AttributeType>) -> Result<Self, Self::Error> {
        check_shape(&presentation)?;
        Ok(Self(presentation))
    }
}

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::Serialize,
    > serde::Serialize for IdCredentialProof<P, C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.0, serializer)
    }
}

impl<
        'de,
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + DeserializeOwned,
    > serde::Deserialize<'de> for IdCredentialProof<P, C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let presentation: PresentationV1<P, C, AttributeType> =
            serde::Deserialize::deserialize(deserializer)?;
        Self::try_from(presentation).map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::types::AttributeTag;
    use crate::web3id::v1::{fixtures, ContextProperty, CredentialV1};
    use crate::web3id::Web3IdAttribute;
    use std::str::FromStr;

    type TestProof = IdCredentialProof<IpPairing, ArCurve, Web3IdAttribute>;

    fn context_fixture() -> ContextInformation {
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

    fn attributes_fixture() -> BTreeMap<AttributeTag, Web3IdAttribute> {
        [
            (AttributeTag(1), Web3IdAttribute::Numeric(137)),
            (
                AttributeTag(2),
                Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
            ),
        ]
        .into_iter()
        .collect()
    }

    /// A proof of ID credential from an identity credential verifies, and establishes exactly
    /// the request it was asked for.
    #[test]
    fn test_completeness_identity() {
        let global_context = GlobalContext::generate("Test".into());
        let id_cred_fixture =
            fixtures::identity_credentials_fixture(attributes_fixture(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Identity {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
            },
        };

        let proof: TestProof = request
            .clone()
            .prove(&global_context, id_cred_fixture.private_inputs())
            .expect("prove");

        assert_eq!(
            proof
                .verify(&global_context, &id_cred_fixture.verification_material)
                .expect("verify"),
            request,
            "the verified request must be the one that was proven"
        );
    }

    /// A proof of ID credential from an account credential verifies, and establishes exactly the
    /// request it was asked for.
    #[test]
    fn test_completeness_account() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            },
        };

        let proof: TestProof = request
            .clone()
            .prove(&global_context, acc_cred_fixture.private_inputs())
            .expect("prove");

        // One opening statement per committed attribute, and nothing else.
        let SubjectClaims::Account(claims) = proof.0.verifiable_credentials[0].claims() else {
            panic!("expected an account credential");
        };
        assert_eq!(claims.statements.len(), attributes_fixture().len());

        assert_eq!(
            proof
                .verify(&global_context, &acc_cred_fixture.verification_material)
                .expect("verify"),
            request,
            "the verified request must be the one that was proven"
        );
    }

    /// The same proof also verifies through the general presentation API.
    #[test]
    fn test_completeness_verifies_as_presentation() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            },
        };
        let proof: TestProof = request
            .prove(&global_context, acc_cred_fixture.private_inputs())
            .expect("prove");

        let public = vec![acc_cred_fixture.verification_material];
        proof
            .as_presentation()
            .verify(&global_context, public.iter())
            .expect("the proof must verify as an ordinary presentation");
    }

    /// A prover that opens only *some* of the credential's commitments must be rejected, even
    /// though the presentation is cryptographically valid. Accepting a subset would let anyone
    /// who can open a single commitment claim ownership of the whole credential.
    #[test]
    fn test_soundness_account_partial_openings() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        // Prove an opening for only the first attribute, going around the new API.
        let statements = vec![AtomicStatementV1::AttributeOpeningKnown(
            AttributeOpeningKnownStatement {
                attribute_tag: AttributeTag(1),
            },
        )];
        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: context_fixture(),
            subject_claims: vec![SubjectClaims::Account(AccountBasedSubjectClaims {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
                statements,
            })],
        };
        let presentation = request
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // It is a valid presentation ...
        let public = vec![acc_cred_fixture.verification_material.clone()];
        presentation
            .verify(&global_context, public.iter())
            .expect("the partial presentation is cryptographically valid");

        // ... but not a valid proof of ID credential.
        let proof = TestProof::try_from(presentation).expect("shape check without material");
        let err = proof
            .verify(&global_context, &acc_cred_fixture.verification_material)
            .expect_err("partial openings must not be accepted");
        assert!(
            matches!(err, VerifyError::NotAnIdCredentialProof(_)),
            "unexpected error: {err}"
        );
    }

    /// Opening the same commitment twice must not stand in for covering two commitments.
    #[test]
    fn test_soundness_account_repeated_opening() {
        let global_context = GlobalContext::generate("Test".into());
        let attributes: BTreeMap<_, _> = [(AttributeTag(1), Web3IdAttribute::Numeric(137))]
            .into_iter()
            .collect();
        let acc_cred_fixture = fixtures::account_credentials_fixture(attributes, &global_context);

        let opening = AtomicStatementV1::AttributeOpeningKnown(AttributeOpeningKnownStatement {
            attribute_tag: AttributeTag(1),
        });
        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: context_fixture(),
            subject_claims: vec![SubjectClaims::Account(AccountBasedSubjectClaims {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
                statements: vec![opening.clone(), opening],
            })],
        };
        let presentation = request
            .prove(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        let proof = TestProof::try_from(presentation).expect("shape check without material");
        let err = proof
            .verify(&global_context, &acc_cred_fixture.verification_material)
            .expect_err("a repeated opening must not be accepted");
        assert!(
            matches!(err, VerifyError::NotAnIdCredentialProof(_)),
            "unexpected error: {err}"
        );
    }

    /// A tampered opening proof must not verify.
    #[test]
    fn test_soundness_account_tampered_proof() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            },
        };
        let mut proof: TestProof = request
            .prove(&global_context, acc_cred_fixture.private_inputs())
            .expect("prove");

        // Swap the two opening proofs, which are for different commitments.
        let CredentialV1::Account(credential) = &mut proof.0.verifiable_credentials[0] else {
            panic!("expected an account credential");
        };
        credential.proof.proof_value.statement_proofs.swap(0, 1);

        let err = proof
            .verify(&global_context, &acc_cred_fixture.verification_material)
            .expect_err("a tampered proof must not verify");
        assert_eq!(err, VerifyError::InvalidCredential(0));
    }

    /// An identity presentation that proves an attribute statement is not a proof of ID
    /// credential, even though it is a valid presentation.
    #[test]
    fn test_soundness_identity_extra_statement() {
        let global_context = GlobalContext::generate("Test".into());
        let (statements, attributes) = fixtures::statements_and_attributes();
        let id_cred_fixture = fixtures::identity_credentials_fixture(attributes, &global_context);

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: context_fixture(),
            subject_claims: vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
                statements,
            })],
        };
        let presentation = request
            .prove(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
            )
            .expect("prove");

        // The shape check rejects it without needing verification material.
        TestProof::try_from(presentation.clone())
            .expect_err("statements on an identity credential must be rejected");

        // And so does verification, for a proof that was not built through `try_from`.
        let err = IdCredentialProof(presentation)
            .verify(&global_context, &id_cred_fixture.verification_material)
            .expect_err("statements on an identity credential must be rejected");
        assert!(
            matches!(err, VerifyError::NotAnIdCredentialProof(_)),
            "unexpected error: {err}"
        );
    }

    /// An account credential with no attribute commitments cannot be proven, since there would be
    /// nothing to demonstrate knowledge of.
    #[test]
    fn test_soundness_account_no_commitments() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(BTreeMap::default(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            },
        };
        let err = request
            .prove::<IpPairing, ArCurve, Web3IdAttribute>(
                &global_context,
                acc_cred_fixture.private_inputs(),
            )
            .expect_err("a credential with no commitments must not be provable");
        assert!(
            matches!(err, ProveError::IdCredentialProof(_)),
            "unexpected error: {err}"
        );
    }

    /// Private inputs for a different kind of credential, or a different issuer, are rejected up
    /// front rather than producing a proof of a claim that was not requested.
    #[test]
    fn test_soundness_private_inputs_mismatch() {
        let global_context = GlobalContext::generate("Test".into());
        let id_cred_fixture =
            fixtures::identity_credentials_fixture(attributes_fixture(), &global_context);
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        // Identity request, account inputs.
        let wrong_kind = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Identity {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
            },
        };
        let err = wrong_kind
            .prove::<IpPairing, ArCurve, Web3IdAttribute>(
                &global_context,
                acc_cred_fixture.private_inputs(),
            )
            .expect_err("mismatching credential kinds must be rejected");
        assert!(
            matches!(err, ProveError::PrivateInputsMismatch),
            "unexpected error: {err}"
        );

        // Correct kind, but an issuer the private inputs are not for.
        let wrong_issuer = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: IpIdentity::from(acc_cred_fixture.issuer.0 + 1),
                cred_id: acc_cred_fixture.cred_id,
            },
        };
        let err = wrong_issuer
            .prove::<IpPairing, ArCurve, Web3IdAttribute>(
                &global_context,
                acc_cred_fixture.private_inputs(),
            )
            .expect_err("a mismatching issuer must be rejected");
        assert!(
            matches!(err, ProveError::PrivateInputsMismatch),
            "unexpected error: {err}"
        );
    }

    /// The JSON of a proof of ID credential is exactly the JSON of the presentation it wraps, and
    /// it round-trips.
    #[test]
    fn test_json_roundtrip() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

        let request = IdCredentialProofRequest {
            context: context_fixture(),
            subject: IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            },
        };
        let proof: TestProof = request
            .prove(&global_context, acc_cred_fixture.private_inputs())
            .expect("prove");

        let json = serde_json::to_value(&proof).expect("proof to JSON");
        assert_eq!(
            json,
            serde_json::to_value(proof.as_presentation()).expect("presentation to JSON"),
            "the wire format must be that of the presentation"
        );

        let roundtrip: TestProof = serde_json::from_value(json).expect("proof from JSON");
        assert_eq!(roundtrip, proof, "JSON roundtrip");
    }

    /// Deserialization rejects a presentation that is not shaped like a proof of ID credential.
    #[test]
    fn test_deserialize_rejects_multiple_credentials() {
        let global_context = GlobalContext::generate("Test".into());
        let first = fixtures::identity_credentials_fixture(attributes_fixture(), &global_context);
        let second = fixtures::identity_credentials_fixture(attributes_fixture(), &global_context);

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: context_fixture(),
            subject_claims: vec![
                SubjectClaims::Identity(IdentityBasedSubjectClaims {
                    network: Network::Testnet,
                    issuer: first.issuer,
                    statements: Vec::new(),
                }),
                SubjectClaims::Identity(IdentityBasedSubjectClaims {
                    network: Network::Testnet,
                    issuer: second.issuer,
                    statements: Vec::new(),
                }),
            ],
        };
        let presentation = request
            .prove(
                &global_context,
                [first.private_inputs(), second.private_inputs()].into_iter(),
            )
            .expect("prove");

        let json = serde_json::to_value(&presentation).expect("presentation to JSON");
        serde_json::from_value::<TestProof>(json)
            .expect_err("a presentation with two credentials is not a proof of ID credential");
    }

    /// Prove and verify the opening statement on its own, and check that a proof made with the
    /// wrong randomness does not verify.
    #[test]
    fn test_attribute_opening_known_statement() {
        use crate::curve_arithmetic::Value;
        use crate::random_oracle::RandomOracle;

        let global_context = GlobalContext::<ArCurve>::generate("Test".into());
        let key = &global_context.on_chain_commitment_key;

        let attribute = Web3IdAttribute::Numeric(137);
        let value = Value::<ArCurve>::new(attribute.to_field_element());
        let (commitment, randomness) = key.commit(&value, &mut rand::thread_rng());

        let statement = AttributeOpeningKnownStatement {
            attribute_tag: AttributeTag(1),
        };
        let values: BTreeMap<AttributeTag, Web3IdAttribute> =
            [(AttributeTag(1), attribute)].into_iter().collect();
        let randomness_map: BTreeMap<AttributeTag, _> =
            [(AttributeTag(1), randomness)].into_iter().collect();
        let commitments: BTreeMap<AttributeTag, _> =
            [(AttributeTag(1), commitment)].into_iter().collect();

        let mut transcript = RandomOracle::domain("Test");
        let proof = statement
            .prove(
                ProofVersion::Version2,
                &global_context,
                &mut transcript.split(),
                &mut rand::thread_rng(),
                &values,
                &randomness_map,
            )
            .expect("prove opening");
        assert!(
            statement.verify(
                ProofVersion::Version2,
                &global_context,
                &mut transcript,
                &commitments,
                &proof,
            ),
            "the opening proof must verify"
        );

        // A proof produced for a different commitment must not verify against this one.
        let (other_commitment, other_randomness) = key.commit(&value, &mut rand::thread_rng());
        let other_randomness_map: BTreeMap<AttributeTag, _> =
            [(AttributeTag(1), other_randomness)].into_iter().collect();
        let mut transcript = RandomOracle::domain("Test");
        let other_proof = statement
            .prove(
                ProofVersion::Version2,
                &global_context,
                &mut transcript.split(),
                &mut rand::thread_rng(),
                &values,
                &other_randomness_map,
            )
            .expect("prove opening");
        assert!(
            !statement.verify(
                ProofVersion::Version2,
                &global_context,
                &mut transcript,
                &commitments,
                &other_proof,
            ),
            "a proof for a different commitment must not verify"
        );
        assert_ne!(
            commitment, other_commitment,
            "the two commitments must differ"
        );
    }

    /// The request JSON uses the same DID conventions as the rest of the module, and round-trips.
    #[test]
    fn test_request_json() {
        let cred_id = CredentialRegistrationID::from_str(
            "856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        )
        .unwrap();

        for (subject, expected_subject) in [
            (
                IdCredentialSubject::Identity {
                    network: Network::Testnet,
                    issuer: IpIdentity::from(17u32),
                },
                serde_json::json!({
                    "type": [
                        "ConcordiumIdCredentialSubjectV1",
                        "ConcordiumIdBasedIdCredentialSubject"
                    ],
                    "issuer": "did:ccd:testnet:idp:17",
                }),
            ),
            (
                IdCredentialSubject::Account {
                    network: Network::Testnet,
                    issuer: IpIdentity::from(17u32),
                    cred_id,
                },
                serde_json::json!({
                    "type": [
                        "ConcordiumIdCredentialSubjectV1",
                        "ConcordiumAccountBasedIdCredentialSubject"
                    ],
                    "id": format!("did:ccd:testnet:cred:{cred_id}"),
                    "issuer": "did:ccd:testnet:idp:17",
                }),
            ),
        ] {
            let request = IdCredentialProofRequest {
                context: context_fixture(),
                subject,
            };
            let json = serde_json::to_value(&request).expect("request to JSON");
            assert_eq!(
                json,
                serde_json::json!({
                    "type": "ConcordiumIdCredentialProofRequestV1",
                    "context": serde_json::to_value(&request.context).unwrap(),
                    "subject": expected_subject,
                })
            );
            let roundtrip: IdCredentialProofRequest =
                serde_json::from_value(json).expect("request from JSON");
            assert_eq!(roundtrip, request, "request JSON roundtrip");
        }
    }

    /// Pin the wire format of an account based proof of ID credential: a proof produced by an
    /// earlier version of this code must still deserialize and verify. If this test fails, the
    /// proof format changed and previously issued proofs can no longer be verified.
    #[test]
    fn test_stability_account() {
        let global_context = GlobalContext::generate("Test".into());
        let acc_cred_fixture =
            fixtures::account_credentials_fixture(attributes_fixture(), &global_context);

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
            "type": "AttributeOpeningKnown",
            "attributeTag": "lastName"
          },
          {
            "type": "AttributeOpeningKnown",
            "attributeTag": "sex"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "proof": {
        "created": "2024-01-02T03:04:05Z",
        "proofValue": "0000000000000002055bb84a62c8af5066cabfc83e5c74bc84af4155f13cc877808205c05e807a65d30000000214c5ecb99e6064f484cb66ea573e3ee62faa4767c6a681676147c1b2bd69dcaf4869ad2a6e4304463bb3fe43988a4785749e1f24f4dfa66d518e1dc621d6c75805864a476b111a351b8331aacb1ddfecbe4f63359c83a7f72dc138024b6e727717000000025b6244a740421e689e42d5f62afa2740a9a6f947aec025cb150b365e15bf1dc2696df1a363a10f0949e21543754798ecc4d3766d03a799463e31df5fa49d83bf",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2024-01-02T03:04:05Z",
    "proofValue": "",
    "type": "ConcordiumWeakLinkingProofV1"
  }
}"#;

        let proof: TestProof =
            serde_json::from_str(proof_json).expect("the stable proof must deserialize");
        let request = proof
            .verify(&global_context, &acc_cred_fixture.verification_material)
            .expect("the stable proof must verify");

        assert_eq!(
            request.subject,
            IdCredentialSubject::Account {
                network: Network::Testnet,
                issuer: acc_cred_fixture.issuer,
                cred_id: acc_cred_fixture.cred_id,
            }
        );
    }
}
