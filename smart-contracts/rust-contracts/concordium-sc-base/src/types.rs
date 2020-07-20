/// A type representing the constract state bytes.
#[derive(Default)]
pub struct ContractState {
    pub(crate) current_position: u32,
}

/// The type of amounts on the chain.
pub type Amount = u64;

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq)]
pub struct AccountAddress(pub(crate) [u8; 32]);

/// Chain context accessible to the init methods.
pub struct InitContext {}

/// Chain context accessible to the receive methods.
pub struct ReceiveContext {}
