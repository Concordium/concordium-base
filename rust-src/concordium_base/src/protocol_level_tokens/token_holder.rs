use concordium_contracts_common::AccountAddress;

/// A token holder is an entity that can hold tokens. Currently, this is limited
/// to accounts, but in the future it may be extended to other entities.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenHolder {
    /// The account address of the holder.
    Account(AccountAddress),
}
