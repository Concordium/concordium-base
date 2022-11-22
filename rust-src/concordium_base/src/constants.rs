/// Maximum size of a transaction payload.
pub const MAX_PAYLOAD_SIZE: u32 = MAX_WASM_MODULE_SIZE + 1 + 4 + 4;

/// Minimum valid transaction nonce. Nonces must be strictly sequential starting
/// with [MIN_NONCE].
pub const MIN_NONCE: crate::base::Nonce = crate::base::Nonce { nonce: 1 };

/// Maximum allowed size of data to register via the register data transaction.
pub const MAX_REGISTERED_DATA_SIZE: usize = 256;

/// Max allowed memo size.
pub const MAX_MEMO_SIZE: usize = 256;

/// Maximum allowed length of a smart contract parameter.
pub const MAX_PARAMETER_LEN: usize = 65535;

/// Maximum allowed size of the Wasm module to deploy on the chain.
pub const MAX_WASM_MODULE_SIZE: u32 = 8 * 65536;

/// Curve used for encrypted transfers. This is the same as the anonymity
/// revoker curve.
pub type EncryptedAmountsCurve = id::constants::ArCurve;

/// The maximum allowed length of a [`UrlText`](crate::base::UrlText) in bytes.
pub const MAX_URL_TEXT_LENGTH: usize = 2048;

/// Size of the sha256 digest in bytes.
pub const SHA256: usize = 32;
