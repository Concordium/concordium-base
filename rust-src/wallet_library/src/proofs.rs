use anyhow::Result;
use concordium_base::{
    common::base16_decode,
    id::{constants, types::*},
    web3id::{OwnedCommitmentInputs, Presentation, Request, Web3IdAttribute, Web3IdSigner},
};
use serde::Deserialize as SerdeDeserialize;

/// Serializeable wrapper for a SecretKey.
#[derive(SerdeDeserialize)]
pub struct Web3SecretKey(#[serde(deserialize_with = "base16_decode")] ed25519_dalek::SecretKey);

impl Web3IdSigner for Web3SecretKey {
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
        Vec<OwnedCommitmentInputs<constants::ArCurve, Web3IdAttribute, Web3SecretKey>>,
}

/// creates a web3Id proof.
pub fn create_web3_id_proof(
    input: Web3IdProofInput,
) -> Result<Presentation<constants::ArCurve, Web3IdAttribute>> {
    let presentation = input.request.prove(
        &input.global_context,
        input.commitment_inputs.iter().map(Into::into),
    );
    presentation.map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use concordium_base::{
        base::CredentialRegistrationID,
        pedersen_commitment,
        web3id::{did::Network, CredentialStatement},
    };

    use super::*;
    use crate::test_helpers::*;
    use concordium_base::{
        curve_arithmetic::Curve,
        id::id_proof_types::{
            AtomicStatement, AttributeInRangeStatement, AttributeNotInSetStatement,
        },
        web3id::Challenge,
    };
    use rand::Rng;
    use std::{collections::BTreeMap, marker::PhantomData};

    #[test]
    pub fn create_web3_id_proof_test_only_identity() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::new(rng.gen());
        let params = GlobalContext::generate("Test".into());
        let cred_id_exp = constants::ArCurve::generate_scalar(&mut rng);
        let cred_id = CredentialRegistrationID::from_exponent(&params, cred_id_exp);
        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id,
            statement: vec![
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower:         Web3IdAttribute::Numeric(80),
                        upper:         Web3IdAttribute::Numeric(1237),
                        _phantom:      PhantomData,
                    },
                },
                AtomicStatement::AttributeNotInSet {
                    statement: AttributeNotInSetStatement {
                        attribute_tag: 1u8.into(),
                        set:           [
                            Web3IdAttribute::String(constants::AttributeKind("ff".into())),
                            Web3IdAttribute::String(constants::AttributeKind("aa".into())),
                            Web3IdAttribute::String(constants::AttributeKind("zz".into())),
                        ]
                        .into_iter()
                        .collect(),
                        _phantom:      PhantomData,
                    },
                },
            ],
        }];
        let request = Request::<constants::ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };
        let global_context = read_global();
        let mut values = BTreeMap::new();
        values.insert(3.into(), Web3IdAttribute::Numeric(137));
        values.insert(
            1.into(),
            Web3IdAttribute::String(constants::AttributeKind("xkcd".into())),
        );
        let mut randomness = BTreeMap::new();
        for tag in values.keys() {
            randomness.insert(
                *tag,
                pedersen_commitment::Randomness::<constants::ArCurve>::generate(&mut rng),
            );
        }
        let secrets = OwnedCommitmentInputs::Account {
            values,
            randomness,
            issuer: IpIdentity::from(4u32),
        };
        let commitment_inputs = vec![secrets.into()];
        let proof = create_web3_id_proof(Web3IdProofInput {
            request,
            global_context,
            commitment_inputs,
        });

        let data = serde_json::to_string_pretty(&proof?)?;
        assert!(
            serde_json::from_str::<Presentation<constants::ArCurve, Web3IdAttribute>>(&data)
                .is_ok(),
            "Cannot deserialize proof correctly."
        );
        Ok(())
    }
}
