//! Common constants such as buffer sizes for keypairs and proofs.

/// The length of a VRF `Proof`, in bytes.
pub const PROOF_LENGTH: usize = 80;

/// The length of a ed25519 `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;

/// The length of an ed25519 `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an ed25519 `Keypair`, in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The length of the "key" portion of an "expanded" ed25519 secret key, in
/// bytes.
const EXPANDED_SECRET_KEY_KEY_LENGTH: usize = 32;

/// The length of the "nonce" portion of an "expanded" ed25519 secret key, in
/// bytes.
const EXPANDED_SECRET_KEY_NONCE_LENGTH: usize = 32;

/// The length of an "expanded" ed25519 key, `ExpandedSecretKey`, in bytes.
pub const EXPANDED_SECRET_KEY_LENGTH: usize =
    EXPANDED_SECRET_KEY_KEY_LENGTH + EXPANDED_SECRET_KEY_NONCE_LENGTH;

/// Suite string as defined by <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#suites>
pub const SUITE_STRING: [u8; 1] = [3u8];

/// Strings combined with inputs to the hash function for domain separation, as
/// discussed in <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.7.7>
pub const ZERO_STRING: [u8; 1] = [0u8];
pub const ONE_STRING: [u8; 1] = [1u8];
pub const TWO_STRING: [u8; 1] = [2u8];
pub const THREE_STRING: [u8; 1] = [3u8];
