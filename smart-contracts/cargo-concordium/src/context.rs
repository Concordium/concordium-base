use anyhow::anyhow;
use concordium_contracts_common::{
    AccountAddress, Address, Amount, ContractAddress, EntrypointName, OwnedEntrypointName,
    OwnedPolicy, Serial, SlotTime,
};
use serde::Deserialize;
use wasm_chain_integration::{v0, v1, ExecResult};

/// A chain metadata with an optional field.
/// Used when simulating contracts to allow the user to only specify the
/// necessary context fields.
/// The default value is `None` for all `Option` fields.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainMetadataOpt {
    slot_time: Option<SlotTime>,
}

impl v0::HasChainMetadata for ChainMetadataOpt {
    fn slot_time(&self) -> ExecResult<SlotTime> { unwrap_ctx_field(self.slot_time, "slotTime") }
}

/// An init context with optional fields.
/// Used when simulating contracts to allow the user to only specify the
/// context fields used by the contract.
/// The default value is `None` for all `Option` fields and the default of
/// `ChainMetadataOpt` for `metadata`.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitContextOpt {
    #[serde(default)]
    metadata:        ChainMetadataOpt,
    init_origin:     Option<AccountAddress>,
    #[serde(deserialize_with = "deserialize_policy_bytes_from_json")]
    sender_policies: Option<v0::OwnedPolicyBytes>,
}

impl v0::HasInitContext for InitContextOpt {
    type MetadataType = ChainMetadataOpt;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn init_origin(&self) -> ExecResult<&AccountAddress> {
        unwrap_ctx_field(self.init_origin.as_ref(), "initOrigin")
    }

    fn sender_policies(&self) -> ExecResult<&[u8]> {
        unwrap_ctx_field(self.sender_policies.as_ref().map(Vec::as_ref), "senderPolicies")
    }
}

/// A receive context with optional fields.
/// Used when simulating contracts to allow the user to only specify the
/// context fields used by the contract.
/// The default value is `None` for all `Option` fields and the default of
/// `ChainMetadataOpt` for `metadata`.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiveContextOpt {
    #[serde(default)]
    metadata:                ChainMetadataOpt,
    invoker:                 Option<AccountAddress>,
    self_address:            Option<ContractAddress>,
    // This is pub(crate) because it is overwritten when `--balance` is used.
    pub(crate) self_balance: Option<Amount>,
    sender:                  Option<Address>,
    owner:                   Option<AccountAddress>,
    #[serde(deserialize_with = "deserialize_policy_bytes_from_json")]
    sender_policies:         Option<v0::OwnedPolicyBytes>,
}

impl v0::HasReceiveContext for ReceiveContextOpt {
    type MetadataType = ChainMetadataOpt;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> {
        unwrap_ctx_field(self.invoker.as_ref(), "invoker")
    }

    fn self_address(&self) -> ExecResult<&ContractAddress> {
        unwrap_ctx_field(self.self_address.as_ref(), "selfAddress")
    }

    fn self_balance(&self) -> ExecResult<Amount> {
        unwrap_ctx_field(self.self_balance, "selfBalance")
    }

    fn sender(&self) -> ExecResult<&Address> { unwrap_ctx_field(self.sender.as_ref(), "sender") }

    fn owner(&self) -> ExecResult<&AccountAddress> {
        unwrap_ctx_field(self.owner.as_ref(), "owner")
    }

    fn sender_policies(&self) -> ExecResult<&[u8]> {
        unwrap_ctx_field(self.sender_policies.as_ref().map(Vec::as_ref), "senderPolicies")
    }
}

// Error handling when unwrapping
fn unwrap_ctx_field<A>(opt: Option<A>, name: &str) -> ExecResult<A> {
    match opt {
        Some(v) => Ok(v),
        None => Err(anyhow!(
            "Missing field '{}' in the context. Make sure to provide a context file with all the \
             fields the contract uses.",
            name,
        )),
    }
}

/// A receive context with optional fields.
/// Used when simulating contracts to allow the user to only specify the
/// context fields used by the contract.
/// The default value is `None` for all `Option` fields and the default of
/// `ChainMetadataOpt` for `metadata`.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiveContextOptV1 {
    #[serde(flatten)]
    pub(crate) common: ReceiveContextOpt,
    entrypoint:        Option<OwnedEntrypointName>,
}

impl v0::HasReceiveContext for ReceiveContextOptV1 {
    type MetadataType = ChainMetadataOpt;

    fn metadata(&self) -> &Self::MetadataType { &self.common.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> {
        unwrap_ctx_field(self.common.invoker.as_ref(), "invoker")
    }

    fn self_address(&self) -> ExecResult<&ContractAddress> {
        unwrap_ctx_field(self.common.self_address.as_ref(), "selfAddress")
    }

    fn self_balance(&self) -> ExecResult<Amount> {
        unwrap_ctx_field(self.common.self_balance, "selfBalance")
    }

    fn sender(&self) -> ExecResult<&Address> {
        unwrap_ctx_field(self.common.sender.as_ref(), "sender")
    }

    fn owner(&self) -> ExecResult<&AccountAddress> {
        unwrap_ctx_field(self.common.owner.as_ref(), "owner")
    }

    fn sender_policies(&self) -> ExecResult<&[u8]> {
        unwrap_ctx_field(self.common.sender_policies.as_ref().map(Vec::as_ref), "senderPolicies")
    }
}

impl v1::HasReceiveContext for ReceiveContextOptV1 {
    fn entrypoint(&self) -> ExecResult<EntrypointName> {
        let ep = unwrap_ctx_field(self.entrypoint.as_ref(), "entrypoint")?;
        Ok(ep.as_entrypoint_name())
    }
}

fn deserialize_policy_bytes_from_json<'de, D: serde::de::Deserializer<'de>>(
    des: D,
) -> Result<Option<v0::OwnedPolicyBytes>, D::Error> {
    let policies = Option::<Vec<OwnedPolicy>>::deserialize(des)?;
    // It might be better to define a serialization instance in the future.
    // Its a bit finicky since this is not the usual serialization, it prepends
    // length of data so that data can be skipped and loaded lazily inside the
    // contract.
    if let Some(policies) = policies {
        let mut out = Vec::new();
        let len = policies.len() as u16;
        len.serial(&mut out).expect("Cannot fail writing to vec.");
        for policy in policies.iter() {
            let bytes = concordium_contracts_common::to_bytes(policy);
            let internal_len = bytes.len() as u16;
            internal_len.serial(&mut out).expect("Cannot fail writing to vec.");
            out.extend_from_slice(&bytes);
        }
        Ok(Some(out))
    } else {
        Ok(None)
    }
}
