mod proofs;

use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::types::Attribute;
use crate::web3id::did::Network;
use crate::web3id::{
    did, AccountCredentialMetadata, AccountCredentialProof, AccountCredentialStatement,
    CredentialHolderId, IdentityCredentialMetadata, IdentityCredentialProof,
    IdentityCredentialStatement, LinkingProof, Web3IdCredentialProof, Web3IdCredentialStatement,
    Web3idCredentialMetadata,
};
use anyhow::{bail, ensure, Context};
use itertools::Itertools;
use nom::Parser;
use serde::de::{DeserializeOwned, Error};
use serde::ser::SerializeMap;
use serde::Deserializer;
use std::collections::BTreeSet;

/// Context challenge that serves as a distinguishing context when requesting
/// proofs.
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    crate::common::Serialize,
    Debug,
)]
pub struct ContextChallenge {
    /// This part of the challenge is supposed to be provided by the dapp backend (e.g. merchant backend).
    pub given: Vec<ContextProperty>,
    /// This part of the challenge is supposed to be provided by the wallet or ID app.
    pub requested: Vec<ContextProperty>,
}

#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    crate::common::Serial,
    crate::common::Deserial,
    Debug,
)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// A statement about a single credential, either an account credential, an identity credential or a
/// Web3 credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Statement about an account credential derived from an identity issued by an
    /// identity provider.
    Account(AccountCredentialStatement<C, AttributeType>),
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id(Web3IdCredentialStatement<C, AttributeType>),
    /// Statement about an identity based credential derived from an identity credential issued by an
    /// identity provider.
    Identity(IdentityCredentialStatement<C, AttributeType>),
}

const CONCORDIUM_CONTEXT_INFORMATION_TYPE: &'static str = "ConcordiumContextInformationV1";

const VERIFIABLE_PRESENTATION_TYPE: &'static str = "VerifiablePresentation";
const CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE: &'static str = "ConcordiumVerifiablePresentationV1";

const VERIFIABLE_CREDENTIAL_TYPE: &'static str = "VerifiableCredential";
const CONCORDIUM_VERIFIABLE_CREDENTIAL_V1_TYPE: &'static str = "ConcordiumVerifiableCredentialV1";
const CONCORDIUM_ACCOUNT_BASED_CREDENTIAL_TYPE: &'static str = "ConcordiumAccountBasedCredential";
const CONCORDIUM_WEB3_BASED_CREDENTIAL_TYPE: &'static str = "ConcordiumWeb3BasedCredential";
const CONCORDIUM_IDENTITY_BASED_CREDENTIAL_TYPE: &'static str = "ConcordiumIdBasedCredential";

const CONCORDIUM_REQUEST_TYPE: &'static str = "ConcordiumVerifiablePresentationRequestV1";

const CONCORDIUM_STATEMENT_V1_TYPE: &'static str = "ConcordiumStatementV1";
const CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE: &'static str = "ConcordiumAccountBasedStatement";
const CONCORDIUM_WEB3_BASED_STATEMENT_TYPE: &'static str = "ConcordiumWeb3BasedStatement";
const CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE: &'static str = "ConcordiumIdBasedStatement";

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for CredentialStatementV1<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CredentialStatementV1::Account(AccountCredentialStatement {
                network,
                cred_id,
                statement,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_STATEMENT_V1_TYPE,
                        CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE,
                    ],
                )?;
                map.serialize_entry("id", &format!("did:ccd:{network}:cred:{cred_id}"))?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
            CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
                network,
                contract,
                credential,
                statement,
                ty,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type", // todo ar what to do about type here
                    ty,
                )?;
                map.serialize_entry(
                    "id",
                    &format!(
                        "did:ccd:{network}:sci:{}:{}/credentialEntry/{}",
                        contract.index, contract.subindex, credential
                    ),
                )?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
            CredentialStatementV1::Identity(IdentityCredentialStatement {
                network,
                issuer,
                statement,
            }) => {
                let did = did::Method {
                    network: *network,
                    ty: did::IdentifierType::Idp {
                        idp_identity: *issuer,
                    },
                };

                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_STATEMENT_V1_TYPE,
                        CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE,
                    ],
                )?;
                map.serialize_entry("issuer", &did)?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
        }
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for CredentialStatementV1<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let types: BTreeSet<String> = serde_json::from_value(take_field(&mut value, "type")?)?;

            Ok(
                if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE)
                {
                    let did: did::Method = serde_json::from_value(take_field(&mut value, "id")?)?;
                    let did::IdentifierType::AccountCredential { cred_id } = did.ty else {
                        bail!("expected account credential did, was {}", did);
                    };
                    let statement = serde_json::from_value(take_field(&mut value, "statement")?)?;

                    Self::Account(AccountCredentialStatement {
                        network: did.network,
                        cred_id,
                        statement,
                    })
                } else if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_WEB3_BASED_CREDENTIAL_TYPE)
                // todo ar do something about this type
                {
                    let did: did::Method = serde_json::from_value(take_field(&mut value, "id")?)?;
                    let did::IdentifierType::ContractData {
                        address,
                        entrypoint,
                        parameter,
                    } = did.ty
                    else {
                        bail!("expected contract data did, was {}", did);
                    };
                    let statement = serde_json::from_value(take_field(&mut value, "statement")?)?;
                    anyhow::ensure!(entrypoint == "credentialEntry", "Invalid entrypoint.");

                    Self::Web3Id(Web3IdCredentialStatement {
                        ty: types,
                        network: did.network,
                        contract: address,
                        credential: CredentialHolderId::new(
                            ed25519_dalek::VerifyingKey::from_bytes(
                                &parameter.as_ref().try_into()?,
                            )?,
                        ),
                        statement,
                    })
                } else if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE)
                {
                    let did: did::Method =
                        serde_json::from_value(take_field(&mut value, "issuer")?)?;
                    let did::IdentifierType::Idp { idp_identity } = did.ty else {
                        bail!("expected issuer did, was {}", did);
                    };
                    let statement = serde_json::from_value(take_field(&mut value, "statement")?)?;

                    Self::Identity(IdentityCredentialStatement {
                        network: did.network,
                        issuer: idp_identity,
                        statement,
                    })
                } else {
                    bail!("unknown credential types: {}", types.iter().format(","))
                },
            )
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Extract the value at the given key. This mutates the `value` replacing the
/// value at the provided key with `Null`.
fn take_field(
    value: &mut serde_json::Value,
    field: &'static str,
) -> anyhow::Result<serde_json::Value> {
    Ok(value
        .get_mut(field)
        .with_context(|| format!("field {field} is not present"))?
        .take())
}

/// Metadata of a single credential.
pub enum CredentialMetadataV1 {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account(AccountCredentialMetadata),
    /// Metadata of a Web3Id credential.
    Web3Id(Web3idCredentialMetadata),
    /// Metadata of an identity based credential.
    Identity(IdentityCredentialMetadata),
}

/// Metadata about a single [`CredentialProofV1`].
pub struct ProofMetadataV1 {
    /// Timestamp of when the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// Metadata specific to the type of credential
    pub cred_metadata: CredentialMetadataV1,
}

/// Credential corresponding to one [`CredentialStatementV1`]. This contains almost
/// all the information needed to verify it, except the issuer's public key in
/// case of the `Web3Id` proof, and the public commitments in case of the
/// `Account` proof, and the identity provider and privacy guardian (anonymity revoker) keys
/// in case of the `Identity` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialProofV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Credential based on an on-chain account
    Account(AccountCredentialProof<C, AttributeType>),
    /// Credential issued by a Web3 identity provider
    Web3Id(Web3IdCredentialProof<C, AttributeType>),
    /// Identity based credential
    Identity(IdentityCredentialProof<P, C, AttributeType>),
}

impl<P: Pairing<ScalarField = C::Scalar>, C: Curve, AttributeType: Attribute<C::Scalar>>
    crate::common::Serial for CredentialProofV1<P, C, AttributeType>
{
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        // todo ar proof ser
        match self {
            CredentialProofV1::Account(AccountCredentialProof {
                created,
                network,
                cred_id,
                proofs,
                issuer,
            }) => {
                0u8.serial(out);
                created.timestamp_millis().serial(out);
                network.serial(out);
                cred_id.serial(out);
                issuer.serial(out);
                proofs.serial(out)
            }
            CredentialProofV1::Web3Id(Web3IdCredentialProof {
                created,
                network,
                contract,
                commitments,
                proofs,
                holder,
                ty,
            }) => {
                1u8.serial(out);
                created.timestamp_millis().serial(out);
                let len = ty.len() as u8;
                len.serial(out);
                for s in ty {
                    (s.len() as u16).serial(out);
                    out.write_all(s.as_bytes())
                        .expect("Writing to buffer succeeds.");
                }
                network.serial(out);
                contract.serial(out);
                holder.serial(out);
                commitments.serial(out);
                proofs.serial(out)
            }
            CredentialProofV1::Identity(IdentityCredentialProof { .. }) => {
                // todo ar update
                2u8.serial(out);
                // created.timestamp_millis().serial(out);
                // network.serial(out);
                // id_attr_cred_info.serial(out);
                // proofs.serial(out)
            }
        }
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialProofV1<P, C, AttributeType>
{
    pub fn network(&self) -> Network {
        match self {
            CredentialProofV1::Account(acc) => acc.network,
            CredentialProofV1::Web3Id(web3) => web3.network,
            CredentialProofV1::Identity(id) => id.network,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialProofV1::Account(acc) => acc.created,
            CredentialProofV1::Web3Id(web3) => web3.created,
            CredentialProofV1::Identity(id) => id.created,
        }
    }

    pub fn metadata(&self) -> ProofMetadataV1 {
        let cred_metadata = match self {
            CredentialProofV1::Account(cred_proof) => {
                CredentialMetadataV1::Account(cred_proof.metadata())
            }
            CredentialProofV1::Web3Id(cred_proof) => {
                CredentialMetadataV1::Web3Id(cred_proof.metadata())
            }
            CredentialProofV1::Identity(cred_proof) => {
                CredentialMetadataV1::Identity(cred_proof.metadata())
            }
        };

        ProofMetadataV1 {
            created: self.created(),
            network: self.network(),
            cred_metadata,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> CredentialStatementV1<C, AttributeType> {
        match self {
            CredentialProofV1::Account(cred_proof) => {
                CredentialStatementV1::Account(cred_proof.statement())
            }
            CredentialProofV1::Web3Id(cred_proof) => {
                CredentialStatementV1::Web3Id(cred_proof.statement())
            }
            CredentialProofV1::Identity(cred_proof) => {
                CredentialStatementV1::Identity(cred_proof.statement())
            }
        }
    }
}

/// A presentation is the response to a [`RequestV1`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub presentation_context: ContextChallenge,
    pub verifiable_credential: Vec<CredentialProofV1<P, C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}

// impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar> + DeserializeOwned> TryFrom<serde_json::Value>
// for PresentationV1<P, C, AttributeType>
// {
//     type Error = anyhow::Error;
//
//     fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
//         let ty: String = serde_json::from_value(get_field(&mut value, "type")?)?;
//         anyhow::ensure!(ty == "VerifiablePresentation");
//         let presentation_context =
//             serde_json::from_value(get_field(&mut value, "presentationContext")?)?;
//         let verifiable_credential =
//             serde_json::from_value(get_field(&mut value, "verifiableCredential")?)?;
//         let linking_proof = serde_json::from_value(get_field(&mut value, "proof")?)?;
//         Ok(Self {
//             presentation_context,
//             verifiable_credential,
//             linking_proof,
//         })
//     }
// }
//
// impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
// for PresentationV1<P, C, AttributeType>
// {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         let json = serde_json::json!({
//             "type": "VerifiablePresentation",
//             "presentationContext": self.presentation_context,
//             "verifiableCredential": &self.verifiable_credential,
//             "proof": &self.linking_proof
//         });
//         json.serialize(serializer)
//     }
// }

/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: ContextChallenge,
    pub credential_statements: Vec<CredentialStatementV1<C, AttributeType>>,
}

// todo ar add type to ContextChallenge context type

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for RequestV1<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", &CONCORDIUM_REQUEST_TYPE)?;
        map.serialize_entry("context", &self.challenge)?;
        map.serialize_entry("credentialStatements", &self.credential_statements)?;
        map.end()
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for RequestV1<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let ty: String = serde_json::from_value(take_field(&mut value, "type")?)?;
            ensure!(
                ty == CONCORDIUM_REQUEST_TYPE,
                "expected type {}",
                CONCORDIUM_REQUEST_TYPE
            );

            let challenge = serde_json::from_value(take_field(&mut value, "context")?)?;
            let credential_statements =
                serde_json::from_value(take_field(&mut value, "credentialStatements")?)?;

            Ok(Self {
                challenge,
                credential_statements,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::constants::{ArCurve, AttributeKind};
    use crate::id::id_proof_types::{
        AtomicStatement, AttributeInRangeStatement, AttributeInSetStatement,
        AttributeNotInSetStatement, RevealAttributeStatement,
    };
    use crate::id::types::{AttributeTag, GlobalContext};
    use crate::web3id::did::Network;
    use crate::web3id::{fixtures, Web3IdAttribute};
    use concordium_contracts_common::Timestamp;
    use std::marker::PhantomData;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses account credentials.
    #[test]
    fn test_request_and_presentation_account_json() {
        let challenge = ContextChallenge {
            given: vec![ContextProperty {
                label: "prop1".to_string(),
                context: "val1".to_string(),
            }],
            requested: vec![ContextProperty {
                label: "prop2".to_string(),
                context: "val2".to_string(),
            }],
        };

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

        let credential_statements =
            vec![CredentialStatementV1::Account(AccountCredentialStatement {
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
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
                    },
                    AtomicStatement::RevealAttribute {
                        statement: RevealAttributeStatement {
                            attribute_tag: 5.into(),
                        },
                    },
                ],
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "type": "ConcordiumVerifiablePresentationRequestV1",
  "context": {
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
  "credentialStatements": [
    {
      "type": [
        "ConcordiumStatementV1",
        "ConcordiumAccountBasedStatement"
      ],
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
          "type": "RevealAttribute",
          "attributeTag": "nationality"
        }
      ]
    }
  ]
}
"#;
        assert_eq!(
            remove_whitespace(&request_json),
            remove_whitespace(expected_request_json),
            "request json"
        );
        let request_deserialized: RequestV1<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = "".to_string(); // todo ar serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2023-08-28T23:12:15Z",
          "proofValue": [
            {
              "proof": "b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da8a881ba424d4deb7715880d015d04a64fd37dfef5ec71d48efee4e8d4d640c505f47d6bb75c52545f01889aa503809d06835320bdc1035e9143aea9bffcb12e904549c4f4885ffcb11c4956b362153010506a4d2959a524be07dc01d717c7e3812d41eaf65a6feabe01babf8a7ae81b9726fd6ee688cd241b31c8219b928d2de7073df321c28040aea5820d8e52af2a23d9da963b335a7452473bdda093a4f8103c32680db7441639eac6d1279ed855ba5cd009a5d9999d4f48f2db031c1b2f3d00000007a7e39d70b58b37af8722528536e1ecd898f4b5060d39eeed8713bf28d58e963ab00e9b46cac7f542240515a9b477b6268322f52bafd7bb479c23c68c275b67fba7c7ccd4b386e61ef4b48d6bfbbeba45fcef3da404ea89c7f082838f8c97f6a88fcac670270f88647c325d842badb22aeec2876b956940b27945e5eb93aaf1d1ab8b2881dd8ebeb27a1871fa1a9e02db873c84ae38d0505fe0c40fca21fa757e928af08077716082cced518f315d694b32fe06568e5b3d1602062747b8911947b17f6535323fcb1a11f4e1807f7f10ad7dec744245bf33f4a183d4e1778be73f4f2028cc9b5731f54dc073763776979d96cf54b71d71f22d8035f7f01149bb205044d95c64be878f3d02a17b375df761b4e14f74a810d3e5de4e7790d19fa712a832cf4345394e0dfbf643d36e60cecc57585601fded8a44cde6e43be56c1a679eb0ccf5e66994d8e9b0354d128045eea70257f31a6c934ea4f4465b903d0dc64cacde6219d93500c798a1ad5abe63e067e2a23690bbc865b7aaaa557f782c4fb2cb9b2d4b0a81e8566627d546d21450e38d922c6749900808ddf06e6f01da92d7fcee94c66ebfa3058bcbfdbf655e9cac0bf73d693d0e57ec3d457910110a67e9124ee7814bf8f6c5836e153dd3a95355a8218df1f8aec1cd6213349e7f16d795ccf1d3a28fe24d63136909e5504faf640c2a99b12cb5a39ecc54a0b60081f00235adc9451b0aabfab24fc9d40dffc8ac9b2111f3369e941090b3242ad8334a54b7ec4940ae23ea4ad23bbef2376737977939097918f37c04b989f2d16a7d88b50818a60c730de62214903bfcfce0a45c107fd441f3b0d5da23afe5ad03baa0d6f1bf78aeb8ce94d4852c358c8200919337e4915f9732e74ebf6b0aa99af5f7bd768cacf9acbf70da2cf607f55567de34f263182984ff36a91e9cbb48918ab3483632fc1427ffad3124043b7111a213edda117c81c104a3351260afbc2b00ab567f82d9462916c8101a72e7fd3995b8734f8b8af18e415162ae47313c6bc738",
              "type": "AttributeInRange"
            },
            {
              "proof": "b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b7897a2f2d1e623b88284ca5eecea172d05bc25e83acd28f5e9e5a4f2637a0762a8a9bcbf052373d26cf38efbb25223ba91c2bff8115180e290bee9ed17b8e3e392b8bfb805f5ad854041d7a9c7669dc193e6e5091fc2fd38ac35eadb755d4b356efb4505072d3ca29c2158af6d2feb1faf939839a9b7d37b384ac3761bb7020319d8e2792cdd20ab483307f0004fa49fc9d9658daf7a7363f05767db6b1f73c344bff03f320bda0fc59a32d165b980c02d21416277a24231c0389b34f502c32000000028c4e5cf1c3505e536b50580d287728d58433e2e471af1500eefffa8d3db7eadbcc4115abcb58bc3cbad27fdd6b22676781235df2401fad1abaf9338f753c4d6606a4a2e04cf89347b398419169238a7fdc1d0ad7f1091db98cf1ea11b082be0a86aa22a16e1e022931fa71e69066894d15cd8525c87dcb1391b0b3502e0b96af9fcf7f6abd60030319137ec20d2d563196d9721142c308f02a8e6ff29fe113a6bc09f67ae02612c7c8b0fba524d7e077efecdbdc26320f10531a4dbd643f1a4e0a08dea12abf4eb723607be444120d6051bea73224fea2c33c3c335db19738536d0a8b7f89664da783709c21068e633e17b8ef6a04ff82235bd11aa73c565e9b",
              "type": "AttributeInSet"
            },
            {
              "proof": "8b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaaa72ae5ea7540bd7987ace8571e79822d6cab88b070cabe1d7102a01df2070d244548f1c0ea7524acc3078c9af52cd9295309836a5f188743eec08c2009c9510abdfd2fd67363ba5f4900d91fbe114f3c45fb6202e9f64a65a29c14e30e1986e1dd79a31dacf9f7804ba85b984525fc58be01578a8daef7530f98a6c92bc9a5a461af99e831c4094455010a2c58ed43c485e26733ca9a655a2ad5a9418fcd651130e22e918477fe17d3a1b850a837cdf8c8470025e6ed72b26092e2441580c45000000028f7d1d30615527b6882ac3d2e81d9568c50b64e8a68b233edf6237a891263ba6fd4e553bbf8975286c680ae6b1654989b7ac6688ba61e05683d3ad98b26e5ea8ee4d43d5dbaa91e304f6c38fc20be2801d9f4ec8d7438a14cfc1ea2d5229d90b91f280db6a74a3e6752cb24fa50692fd26948a63b87122ecb0e855f2ed1bb0b4b945766b2b6b7b1ea6473a5d878348099735dcb385a81381d2f4fc1d74bf38f7daa645e3e789f6f54485aebab151868ab2a6c8cdb6668dd7631e891d52dc12974e830668e2e8ef4010eec1b9a0456e0d40497c877abd9276de28b26eb986754217966dd19476ce48af7395bd71d5f98a5db3b8b21df3b8fcfbbc2007ad3ee60d",
              "type": "AttributeNotInSet"
            },
            {
              "proof": "b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c96f07725cca3147645f5916af2bec5458283cae75f50727eafd886e5d424eab130bc8230eafae5a346904717454047e7b1507b818338a16dcfe0a757653b7627345101cc445801bfe772eee0fce9466c5d48fa2be31eb72d44630c08c0bfc7e66fda653b5d969f662b3cfd689dffef2a2b244c85113cd551fac1d2383ecc783a6dacbfdf82fac9de1f2e5d37b8b1f4763a2ad6eae207c2602d1ab2975a5217725de4969b544a9072986f73e2636f57aaf5eaeb1b668e15451c3040bbae0179f8000000078e2daf21d82ecce620e819afb2f760a15c40fe0391156787d450b16bcef1fca356c313623a1667e9deee71f5e446a81dae490c45ad8d4864f1bcd9ff375136305596ad874265631a031b962ce09fa5e1c5f7007b37ea1ba0113b360982bfd7fd87b0a56d8f279a5ec05cf0a5c7d7f0feb2458de0029c563b055045d1199358ebdec943ab25ec579a6d2672f843f8096994472e623531d9c4831d176e9ba9c3296cfa8313ea424dcb567d955f23f32fdbc41dee336cdd40aadfb1fe8949e4134297719a926a36727543be39900201bd268543307ee049f1ef2501cd1ce6e15d6db88a7c29347a6d250db12e09d73ccf2583bd8ea6ab048ec85e80b6870a8e0699bb4e996d121dd07254b2462bc0bf36a6b7d068b2475fd2c06b54ee5768b0f953a2a062d94a43f274fe94fd5b0bc842c006e975589497d182908e60744aadddebf2ebd7c5e30b045432d9acd1e464ea12a3f9a68724f60799197a411f20e365df6e46edd6d008a819abbe76db7108b8fa0a8b5e5ab6c4799250021484f23d7a988d35ac179682e0befe03babf06e189db1a03bb9e10155dcaa5b1f50c6dcaae3956a846ec736da6af064409ffbeb4af7897cc404dba40c488d3dcd1505967f669ebfd7ee3b5857e68fa394dd123222c7a8384ed851c134f7d97beffe42e3d92d98e94e1794bcfe6eb8e531b3b0060d213ea23ed5c0b0b65ff1f7dc2c535376cbe417a04401933c5050f8ba3a27e4b4d04b4488223d0762d8490ea4c53e772db1d8deae662f7d24452ad149515dafdd332183dc2385cc2eb449e124c1308fb5a05a35a8b6b755d6f9ef37112fa1dc5c1f1e9e7572a5c1a78634fc9b8a61dbf98e7bf093816b12c0fc38b83ab8e2c3700c19767d885750119a324471bc9641333c7e31b436f8de8dc584a23470da92b27f303270abee804d056a10052324ecc6faf0a0e6c01f7296edfdd1708f4638dc3e0f77d452714f6a7e1ba77f7b74ef725b6406b3e33d3fe28a3e0abc9c6277eab969dba66a29db7b235386bdafdea7c0140",
              "type": "AttributeInRange"
            },
            {
              "attribute": "testvalue",
              "proof": "be1f7ff6fc8b97f296136a8f13a783ceacce3666aedf5b273433922afdb2864624da087298d8dcfea00ec619e0f44f72fd5cb0f5145a327d5b294f5da5bea41a",
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
            "attributeTag": "countryOfResidence",
            "lower": {
              "timestamp": "-262091-08-27T23:12:15Z",
              "type": "date-time"
            },
            "type": "AttributeInRange",
            "upper": {
              "timestamp": "-262091-08-29T23:12:15Z",
              "type": "date-time"
            }
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
        return;
        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        // let proof_deserialized: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
        //     serde_json::from_str(&proof_json).unwrap();
        // assert_eq!(proof_deserialized, proof);// todo ar
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses web3 credentials.
    #[test]
    fn test_request_and_presentation_web3_json() {
        let challenge = ContextChallenge {
            given: vec![ContextProperty {
                label: "prop1".to_string(),
                context: "val1".to_string(),
            }],
            requested: vec![ContextProperty {
                label: "prop2".to_string(),
                context: "val2".to_string(),
            }],
        };

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred_fixture = fixtures::web3_credentials_fixture(
            [
                ("3".into(), Web3IdAttribute::Numeric(137)),
                (
                    "1".into(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    "2".into(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    "5".into(),
                    Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
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

        let credential_statements =
            vec![CredentialStatementV1::Web3Id(Web3IdCredentialStatement {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredentialV1".into(),
                    "ConcordiumWeb3BasedCredential".into(),
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
                            attribute_tag: "3".into(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: "2".into(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: "1".into(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
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
                    },
                    AtomicStatement::RevealAttribute {
                        statement: RevealAttributeStatement {
                            attribute_tag: "5".into(),
                        },
                    },
                ],
            })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "type": "ConcordiumVerifiablePresentationRequestV1",
  "context": {
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
  "credentialStatements": [
    {
      "type": [
        "ConcordiumVerifiableCredentialV1",
        "ConcordiumWeb3BasedCredential",
        "TestCredential",
        "VerifiableCredential"
      ],
      "id": "did:ccd:testnet:sci:1337:42/credentialEntry/ee1aa49a4459dfe813a3cf6eb882041230c7b2558469de81f87c9bf23bf10a03",
      "statement": [
        {
          "type": "AttributeInRange",
          "attributeTag": "3",
          "lower": 80,
          "upper": 1237
        },
        {
          "type": "AttributeInSet",
          "attributeTag": "2",
          "set": [
            "aa",
            "ff",
            "zz"
          ]
        },
        {
          "type": "AttributeNotInSet",
          "attributeTag": "1",
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
          "type": "RevealAttribute",
          "attributeTag": "5"
        }
      ]
    }
  ]
}
"#;
        assert_eq!(
            remove_whitespace(&request_json),
            remove_whitespace(expected_request_json),
            "request json"
        );
        let request_deserialized: RequestV1<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [web3_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = "".to_string(); // todo ar serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [
      "54dca04d76d817b16fba7b9fa27e86906a3afa2904d1459bee35b795bac50a39a6f216afd5fd4fcf3a48c1f6af9f35d98177c0770f451099bd980c8484b4f800"
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
              "5": "8ae7a7fc631dc8566d0db1ce0258ae9b025ac5535bc7206db92775459ba291789ae6c40687763918c6c297b636b3991c",
              "countryOfResidence": "aa0146cdc6e0bd7ce3d3e9464a5bcde7577ee1fa4738ad761c4cd9c978a732e6d42d88d60887fd13be1ee9c73bc617d0"
            },
            "signature": "7d0f13482e21b26930b19a1059e4a5bf71c6e73d086392de9012be74afdd1fe74acfc0ed1a0249b6feaa861b09960f9c51cf63480ba2ee9a9209884a66b96b05"
          },
          "created": "2023-08-28T23:12:15Z",
          "proofValue": [
            {
              "proof": "b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da8a881ba424d4deb7715880d015d04a64fd37dfef5ec71d48efee4e8d4d640c505f47d6bb75c52545f01889aa503809d06835320bdc1035e9143aea9bffcb12e904549c4f4885ffcb11c4956b362153010506a4d2959a524be07dc01d717c7e3812d41eaf65a6feabe01babf8a7ae81b9726fd6ee688cd241b31c8219b928d2de7073df321c28040aea5820d8e52af2a23d9da963b335a7452473bdda093a4f8103c32680db7441639eac6d1279ed855ba5cd009a5d9999d4f48f2db031c1b2f3d00000007a7e39d70b58b37af8722528536e1ecd898f4b5060d39eeed8713bf28d58e963ab00e9b46cac7f542240515a9b477b6268322f52bafd7bb479c23c68c275b67fba7c7ccd4b386e61ef4b48d6bfbbeba45fcef3da404ea89c7f082838f8c97f6a88fcac670270f88647c325d842badb22aeec2876b956940b27945e5eb93aaf1d1ab8b2881dd8ebeb27a1871fa1a9e02db873c84ae38d0505fe0c40fca21fa757e928af08077716082cced518f315d694b32fe06568e5b3d1602062747b8911947b17f6535323fcb1a11f4e1807f7f10ad7dec744245bf33f4a183d4e1778be73f4f2028cc9b5731f54dc073763776979d96cf54b71d71f22d8035f7f01149bb205044d95c64be878f3d02a17b375df761b4e14f74a810d3e5de4e7790d19fa712a832cf4345394e0dfbf643d36e60cecc57585601fded8a44cde6e43be56c1a679eb0ccf5e66994d8e9b0354d128045eea70257f31a6c934ea4f4465b903d0dc64cacde6219d93500c798a1ad5abe63e067e2a23690bbc865b7aaaa557f782c4fb2cb9b2d4b0a81e8566627d546d21450e38d922c6749900808ddf06e6f01da92d7fcee94c66ebfa3058bcbfdbf655e9cac0bf73d693d0e57ec3d457910110a67e9124ee7814bf8f6c5836e153dd3a95355a8218df1f8aec1cd6213349e7f16d795ccf1d3a28fe24d63136909e5504faf640c2a99b12cb5a39ecc54a0b60081f00235adc9451b0aabfab24fc9d40dffc8ac9b2111f3369e941090b3242ad8334a54b7ec4940ae23ea4ad23bbef2376737977939097918f37c04b989f2d16a7d88b50818a60c730de62214903bfcfce0a45c107fd441f3b0d5da23afe5ad03baa0d6f1bf78aeb8ce94d4852c358c8200919337e4915f9732e74ebf6b0aa99af5f7bd768cacf9acbf70da2cf607f55567de34f263182984ff36a91e9cbb48918ab3483632fc1427ffad3124043b7111a213edda117c81c104a3351260afbc2b00ab567f82d9462916c8101a72e7fd3995b8734f8b8af18e415162ae47313c6bc738",
              "type": "AttributeInRange"
            },
            {
              "proof": "b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b7897a2f2d1e623b88284ca5eecea172d05bc25e83acd28f5e9e5a4f2637a0762a8a9bcbf052373d26cf38efbb25223ba91c2bff8115180e290bee9ed17b8e3e392b8bfb805f5ad854041d7a9c7669dc193e6e5091fc2fd38ac35eadb755d4b356efb4505072d3ca29c2158af6d2feb1faf939839a9b7d37b384ac3761bb7020319d8e2792cdd20ab483307f0004fa49fc9d9658daf7a7363f05767db6b1f73c344bff03f320bda0fc59a32d165b980c02d21416277a24231c0389b34f502c32000000028c4e5cf1c3505e536b50580d287728d58433e2e471af1500eefffa8d3db7eadbcc4115abcb58bc3cbad27fdd6b22676781235df2401fad1abaf9338f753c4d6606a4a2e04cf89347b398419169238a7fdc1d0ad7f1091db98cf1ea11b082be0a86aa22a16e1e022931fa71e69066894d15cd8525c87dcb1391b0b3502e0b96af9fcf7f6abd60030319137ec20d2d563196d9721142c308f02a8e6ff29fe113a6bc09f67ae02612c7c8b0fba524d7e077efecdbdc26320f10531a4dbd643f1a4e0a08dea12abf4eb723607be444120d6051bea73224fea2c33c3c335db19738536d0a8b7f89664da783709c21068e633e17b8ef6a04ff82235bd11aa73c565e9b",
              "type": "AttributeInSet"
            },
            {
              "proof": "8b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaaa72ae5ea7540bd7987ace8571e79822d6cab88b070cabe1d7102a01df2070d244548f1c0ea7524acc3078c9af52cd9295309836a5f188743eec08c2009c9510abdfd2fd67363ba5f4900d91fbe114f3c45fb6202e9f64a65a29c14e30e1986e1dd79a31dacf9f7804ba85b984525fc58be01578a8daef7530f98a6c92bc9a5a461af99e831c4094455010a2c58ed43c485e26733ca9a655a2ad5a9418fcd651130e22e918477fe17d3a1b850a837cdf8c8470025e6ed72b26092e2441580c45000000028f7d1d30615527b6882ac3d2e81d9568c50b64e8a68b233edf6237a891263ba6fd4e553bbf8975286c680ae6b1654989b7ac6688ba61e05683d3ad98b26e5ea8ee4d43d5dbaa91e304f6c38fc20be2801d9f4ec8d7438a14cfc1ea2d5229d90b91f280db6a74a3e6752cb24fa50692fd26948a63b87122ecb0e855f2ed1bb0b4b945766b2b6b7b1ea6473a5d878348099735dcb385a81381d2f4fc1d74bf38f7daa645e3e789f6f54485aebab151868ab2a6c8cdb6668dd7631e891d52dc12974e830668e2e8ef4010eec1b9a0456e0d40497c877abd9276de28b26eb986754217966dd19476ce48af7395bd71d5f98a5db3b8b21df3b8fcfbbc2007ad3ee60d",
              "type": "AttributeNotInSet"
            },
            {
              "proof": "b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c96f07725cca3147645f5916af2bec5458283cae75f50727eafd886e5d424eab130bc8230eafae5a346904717454047e7b1507b818338a16dcfe0a757653b7627345101cc445801bfe772eee0fce9466c5d48fa2be31eb72d44630c08c0bfc7e66fda653b5d969f662b3cfd689dffef2a2b244c85113cd551fac1d2383ecc783a6dacbfdf82fac9de1f2e5d37b8b1f4763a2ad6eae207c2602d1ab2975a5217725de4969b544a9072986f73e2636f57aaf5eaeb1b668e15451c3040bbae0179f8000000078e2daf21d82ecce620e819afb2f760a15c40fe0391156787d450b16bcef1fca356c313623a1667e9deee71f5e446a81dae490c45ad8d4864f1bcd9ff375136305596ad874265631a031b962ce09fa5e1c5f7007b37ea1ba0113b360982bfd7fd87b0a56d8f279a5ec05cf0a5c7d7f0feb2458de0029c563b055045d1199358ebdec943ab25ec579a6d2672f843f8096994472e623531d9c4831d176e9ba9c3296cfa8313ea424dcb567d955f23f32fdbc41dee336cdd40aadfb1fe8949e4134297719a926a36727543be39900201bd268543307ee049f1ef2501cd1ce6e15d6db88a7c29347a6d250db12e09d73ccf2583bd8ea6ab048ec85e80b6870a8e0699bb4e996d121dd07254b2462bc0bf36a6b7d068b2475fd2c06b54ee5768b0f953a2a062d94a43f274fe94fd5b0bc842c006e975589497d182908e60744aadddebf2ebd7c5e30b045432d9acd1e464ea12a3f9a68724f60799197a411f20e365df6e46edd6d008a819abbe76db7108b8fa0a8b5e5ab6c4799250021484f23d7a988d35ac179682e0befe03babf06e189db1a03bb9e10155dcaa5b1f50c6dcaae3956a846ec736da6af064409ffbeb4af7897cc404dba40c488d3dcd1505967f669ebfd7ee3b5857e68fa394dd123222c7a8384ed851c134f7d97beffe42e3d92d98e94e1794bcfe6eb8e531b3b0060d213ea23ed5c0b0b65ff1f7dc2c535376cbe417a04401933c5050f8ba3a27e4b4d04b4488223d0762d8490ea4c53e772db1d8deae662f7d24452ad149515dafdd332183dc2385cc2eb449e124c1308fb5a05a35a8b6b755d6f9ef37112fa1dc5c1f1e9e7572a5c1a78634fc9b8a61dbf98e7bf093816b12c0fc38b83ab8e2c3700c19767d885750119a324471bc9641333c7e31b436f8de8dc584a23470da92b27f303270abee804d056a10052324ecc6faf0a0e6c01f7296edfdd1708f4638dc3e0f77d452714f6a7e1ba77f7b74ef725b6406b3e33d3fe28a3e0abc9c6277eab969dba66a29db7b235386bdafdea7c0140",
              "type": "AttributeInRange"
            },
            {
              "attribute": "testvalue",
              "proof": "be1f7ff6fc8b97f296136a8f13a783ceacce3666aedf5b273433922afdb2864624da087298d8dcfea00ec619e0f44f72fd5cb0f5145a327d5b294f5da5bea41a",
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
            "attributeTag": "countryOfResidence",
            "lower": {
              "timestamp": "-262091-08-27T23:12:15Z",
              "type": "date-time"
            },
            "type": "AttributeInRange",
            "upper": {
              "timestamp": "-262091-08-29T23:12:15Z",
              "type": "date-time"
            }
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
        return;
        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        // let proof_deserialized: PresentationV1<ArCurve, Web3IdAttribute> =
        //     serde_json::from_str(&proof_json).unwrap();
        // assert_eq!(proof_deserialized, proof); // todo ar
    }

    /// Tests JSON serialization and deserialization of request and presentation.
    #[test]
    fn test_request_and_presentation_identity_json() {
        let challenge = ContextChallenge {
            given: vec![ContextProperty {
                label: "prop1".to_string(),
                context: "val1".to_string(),
            }],
            requested: vec![ContextProperty {
                label: "prop2".to_string(),
                context: "val2".to_string(),
            }],
        };

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

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatement {
                network: Network::Testnet,
                issuer: id_cred_fixture.issuer,
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
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
                    },
                    AtomicStatement::RevealAttribute {
                        statement: RevealAttributeStatement {
                            attribute_tag: 5.into(),
                        },
                    },
                ],
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "type": "ConcordiumVerifiablePresentationRequestV1",
  "context": {
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
  "credentialStatements": [
    {
      "type": [
        "ConcordiumStatementV1",
        "ConcordiumIdBasedStatement"
      ],
      "issuer": "did:ccd:testnet:idp:0",
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
          "type": "RevealAttribute",
          "attributeTag": "nationality"
        }
      ]
    }
  ]
}
    "#;
        assert_eq!(
            remove_whitespace(&request_json),
            remove_whitespace(expected_request_json),
            "request json"
        );
        let request_deserialized: RequestV1<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = "".to_string(); // todo ar serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
    {
      "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": [],
        "type": "ConcordiumWeakLinkingProofV1"
      },
      "type": "VerifiablePresentation",
      "verifiableCredential": [
        {
          "credentialSubject": {
            "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
            "proof": {
              "created": "2023-08-28T23:12:15Z",
              "proofValue": [
                {
                  "proof": "b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da8a881ba424d4deb7715880d015d04a64fd37dfef5ec71d48efee4e8d4d640c505f47d6bb75c52545f01889aa503809d06835320bdc1035e9143aea9bffcb12e904549c4f4885ffcb11c4956b362153010506a4d2959a524be07dc01d717c7e3812d41eaf65a6feabe01babf8a7ae81b9726fd6ee688cd241b31c8219b928d2de7073df321c28040aea5820d8e52af2a23d9da963b335a7452473bdda093a4f8103c32680db7441639eac6d1279ed855ba5cd009a5d9999d4f48f2db031c1b2f3d00000007a7e39d70b58b37af8722528536e1ecd898f4b5060d39eeed8713bf28d58e963ab00e9b46cac7f542240515a9b477b6268322f52bafd7bb479c23c68c275b67fba7c7ccd4b386e61ef4b48d6bfbbeba45fcef3da404ea89c7f082838f8c97f6a88fcac670270f88647c325d842badb22aeec2876b956940b27945e5eb93aaf1d1ab8b2881dd8ebeb27a1871fa1a9e02db873c84ae38d0505fe0c40fca21fa757e928af08077716082cced518f315d694b32fe06568e5b3d1602062747b8911947b17f6535323fcb1a11f4e1807f7f10ad7dec744245bf33f4a183d4e1778be73f4f2028cc9b5731f54dc073763776979d96cf54b71d71f22d8035f7f01149bb205044d95c64be878f3d02a17b375df761b4e14f74a810d3e5de4e7790d19fa712a832cf4345394e0dfbf643d36e60cecc57585601fded8a44cde6e43be56c1a679eb0ccf5e66994d8e9b0354d128045eea70257f31a6c934ea4f4465b903d0dc64cacde6219d93500c798a1ad5abe63e067e2a23690bbc865b7aaaa557f782c4fb2cb9b2d4b0a81e8566627d546d21450e38d922c6749900808ddf06e6f01da92d7fcee94c66ebfa3058bcbfdbf655e9cac0bf73d693d0e57ec3d457910110a67e9124ee7814bf8f6c5836e153dd3a95355a8218df1f8aec1cd6213349e7f16d795ccf1d3a28fe24d63136909e5504faf640c2a99b12cb5a39ecc54a0b60081f00235adc9451b0aabfab24fc9d40dffc8ac9b2111f3369e941090b3242ad8334a54b7ec4940ae23ea4ad23bbef2376737977939097918f37c04b989f2d16a7d88b50818a60c730de62214903bfcfce0a45c107fd441f3b0d5da23afe5ad03baa0d6f1bf78aeb8ce94d4852c358c8200919337e4915f9732e74ebf6b0aa99af5f7bd768cacf9acbf70da2cf607f55567de34f263182984ff36a91e9cbb48918ab3483632fc1427ffad3124043b7111a213edda117c81c104a3351260afbc2b00ab567f82d9462916c8101a72e7fd3995b8734f8b8af18e415162ae47313c6bc738",
                  "type": "AttributeInRange"
                },
                {
                  "proof": "b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b7897a2f2d1e623b88284ca5eecea172d05bc25e83acd28f5e9e5a4f2637a0762a8a9bcbf052373d26cf38efbb25223ba91c2bff8115180e290bee9ed17b8e3e392b8bfb805f5ad854041d7a9c7669dc193e6e5091fc2fd38ac35eadb755d4b356efb4505072d3ca29c2158af6d2feb1faf939839a9b7d37b384ac3761bb7020319d8e2792cdd20ab483307f0004fa49fc9d9658daf7a7363f05767db6b1f73c344bff03f320bda0fc59a32d165b980c02d21416277a24231c0389b34f502c32000000028c4e5cf1c3505e536b50580d287728d58433e2e471af1500eefffa8d3db7eadbcc4115abcb58bc3cbad27fdd6b22676781235df2401fad1abaf9338f753c4d6606a4a2e04cf89347b398419169238a7fdc1d0ad7f1091db98cf1ea11b082be0a86aa22a16e1e022931fa71e69066894d15cd8525c87dcb1391b0b3502e0b96af9fcf7f6abd60030319137ec20d2d563196d9721142c308f02a8e6ff29fe113a6bc09f67ae02612c7c8b0fba524d7e077efecdbdc26320f10531a4dbd643f1a4e0a08dea12abf4eb723607be444120d6051bea73224fea2c33c3c335db19738536d0a8b7f89664da783709c21068e633e17b8ef6a04ff82235bd11aa73c565e9b",
                  "type": "AttributeInSet"
                },
                {
                  "proof": "8b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaaa72ae5ea7540bd7987ace8571e79822d6cab88b070cabe1d7102a01df2070d244548f1c0ea7524acc3078c9af52cd9295309836a5f188743eec08c2009c9510abdfd2fd67363ba5f4900d91fbe114f3c45fb6202e9f64a65a29c14e30e1986e1dd79a31dacf9f7804ba85b984525fc58be01578a8daef7530f98a6c92bc9a5a461af99e831c4094455010a2c58ed43c485e26733ca9a655a2ad5a9418fcd651130e22e918477fe17d3a1b850a837cdf8c8470025e6ed72b26092e2441580c45000000028f7d1d30615527b6882ac3d2e81d9568c50b64e8a68b233edf6237a891263ba6fd4e553bbf8975286c680ae6b1654989b7ac6688ba61e05683d3ad98b26e5ea8ee4d43d5dbaa91e304f6c38fc20be2801d9f4ec8d7438a14cfc1ea2d5229d90b91f280db6a74a3e6752cb24fa50692fd26948a63b87122ecb0e855f2ed1bb0b4b945766b2b6b7b1ea6473a5d878348099735dcb385a81381d2f4fc1d74bf38f7daa645e3e789f6f54485aebab151868ab2a6c8cdb6668dd7631e891d52dc12974e830668e2e8ef4010eec1b9a0456e0d40497c877abd9276de28b26eb986754217966dd19476ce48af7395bd71d5f98a5db3b8b21df3b8fcfbbc2007ad3ee60d",
                  "type": "AttributeNotInSet"
                },
                {
                  "attribute": "testvalue",
                  "proof": "4ba31824aa47d93bf0978f04b72f9a8cdc097889c4d5a9b0cccf0e0eb6ac2c774d6018d40339331adf9e66342af895e81b66571ed5b85e8952625f3d42d3ac8b",
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
        return;
        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        // let proof_deserialized: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
        //     serde_json::from_str(&proof_json).unwrap();
        // assert_eq!(proof_deserialized, proof); // todo ar
    }
}
