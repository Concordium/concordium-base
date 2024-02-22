use crate::statement::{AcceptableRequest, RequestCheckError, WalletConfig};
use concordium_base::{
    common::base16_decode,
    id::{constants, types::*},
    web3id::{
        OwnedCommitmentInputs, Presentation, ProofError, Request, Web3IdAttribute, Web3IdSigner,
    },
};
use serde::Deserialize as SerdeDeserialize;

/// Serializeable wrapper for a SecretKey.
#[derive(SerdeDeserialize)]
pub struct Web3IdSecretKey(#[serde(deserialize_with = "base16_decode")] ed25519_dalek::SecretKey);

impl Web3IdSigner for Web3IdSecretKey {
    fn id(&self) -> ed25519_dalek::VerifyingKey { self.0.id() }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature { self.0.sign(msg) }
}

/// The input used for creating a web3Id proof. It requires the request itself,
/// the global context of the chain, and the secret commitments for the
/// attributes.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3IdProofInput {
    request:           Request<constants::ArCurve, Web3IdAttribute>,
    global_context:    GlobalContext<constants::ArCurve>,
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
