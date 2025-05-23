use concordium_contracts_common::AccountAddress;

/// A destination that can receive and hold tokens.
/// Currently, this can only be a Concordium account address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenHolder {
    HolderAccount(HolderAccount),
}

/// Account address that holds tokens
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderAccount {
    /// Concordium address
    pub address: AccountAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_info: Option<CoinInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoinInfo {
    CCD
}
