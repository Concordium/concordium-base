use std::collections::HashMap;

use crate::statement::{AcceptableRequest, RequestCheckError, WalletConfig};
use concordium_base::{
    common::{base16_decode, cbor},
    id::{
        constants::{self, ArCurve, IpPairing},
        types::*,
    },
    web3id::{
        v1::{
            anchor::{
                RequestedSubjectClaims, UnfilledContextInformation, VerificationRequest,
                VerificationRequestData,
            },
            OwnedCredentialProofPrivateInputs, PresentationV1, ProveError, RequestV1,
        },
        OwnedCommitmentInputs, Presentation, ProofError, Request, Web3IdAttribute, Web3IdSigner,
    },
};
use serde::{de, Deserialize as SerdeDeserialize};

/// Serializeable wrapper for a SecretKey.
#[derive(SerdeDeserialize)]
pub struct Web3IdSecretKey(#[serde(deserialize_with = "base16_decode")] ed25519_dalek::SecretKey);

impl Web3IdSigner for Web3IdSecretKey {
    fn id(&self) -> ed25519_dalek::VerifyingKey {
        self.0.id()
    }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        self.0.sign(msg)
    }
}

/// The input used for creating a PresentationV1 through its implemented prove function below
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationV1Input {
    request: RequestV1<ArCurve, Web3IdAttribute>,
    inputs: Vec<OwnedCredentialProofPrivateInputs<IpPairing, ArCurve, Web3IdAttribute>>,
    global: GlobalContext<ArCurve>,
}

/// Creates a PresentationV1 by calling prove on the RequestV1
impl PresentationV1Input {
    pub fn prove(
        self,
    ) -> Result<PresentationV1<IpPairing, constants::ArCurve, Web3IdAttribute>, ProveError> {
        let borrowed_credential_proof_inputs = self.inputs.iter().map(|owned| owned.borrow());
        self.request
            .prove(&self.global, borrowed_credential_proof_inputs)
    }
}

/// Input for Verification request creation
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRequestV1Input {
    /// Context information for a verifiable presentation request.
    pub context: UnfilledContextInformation,
    /// The claims for a list of subjects containing requested statements about the subjects.
    pub subject_claims: Vec<RequestedSubjectClaims>,
    /// The optional public info to register with the anchor.
    pub public_info: Option<PublicInfo>,
}

#[derive(Clone)]
pub struct PublicInfo(pub HashMap<String, cbor::value::Value>);

impl<'de> serde::Deserialize<'de> for PublicInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mapped: Result<HashMap<String, cbor::value::Value>, D::Error> = string_map
            .into_iter()
            .map(|(k, v)| {
                let bytes = hex::decode(&v).map_err(de::Error::custom)?;
                let value: cbor::value::Value =
                    cbor::cbor_decode(&bytes).map_err(de::Error::custom)?;
                Ok((k, value))
            })
            .collect();
        Ok(Self(mapped?))
    }
}

impl From<VerificationRequestV1Input> for VerificationRequestData {
    fn from(value: VerificationRequestV1Input) -> Self {
        VerificationRequestData {
            context: value.context,
            subject_claims: value.subject_claims,
        }
    }
}

/// The input used for creating a web3Id proof. It requires the request itself,
/// the global context of the chain, and the secret commitments for the
/// attributes.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3IdProofInput {
    request: Request<constants::ArCurve, Web3IdAttribute>,
    global_context: GlobalContext<constants::ArCurve>,
    commitment_inputs:
        Vec<OwnedCommitmentInputs<constants::ArCurve, Web3IdAttribute, Web3IdSecretKey>>,
}

impl Web3IdProofInput {
    /// Creates a web3Id proof.
    pub fn create_proof(
        self,
    ) -> Result<Presentation<constants::ArCurve, Web3IdAttribute>, ProofError> {
        self.request.prove(
            &self.global_context,
            self.commitment_inputs.iter().map(Into::into),
        )
    }
}

impl AcceptableRequest<constants::ArCurve, Web3IdAttribute> for Web3IdProofInput {
    fn acceptable_request(
        &self,
        config: &WalletConfig<constants::ArCurve, Web3IdAttribute>,
    ) -> Result<(), RequestCheckError> {
        self.request.acceptable_request(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::read_web3_id_request;
    use concordium_base::web3id::Presentation;

    #[test]
    pub fn create_web3_id_proof_test() -> anyhow::Result<()> {
        let request = read_web3_id_request();
        let proof = request.create_proof();
        let data = serde_json::to_string_pretty(&proof?)?;
        assert!(
            serde_json::from_str::<Presentation<constants::ArCurve, Web3IdAttribute>>(&data)
                .is_ok(),
            "Cannot deserialize proof correctly."
        );
        Ok(())
    }
}
