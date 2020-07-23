use crate::*;

/// A type representing the constract state bytes.
#[derive(Default)]
pub struct ContractState {
    pub(crate) current_position: u32,
}

/// The type of amounts on the chain.
pub type Amount = u64;

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord)]
pub struct AccountAddress(pub(crate) [u8; 32]);

impl convert::AsRef<[u8; 32]> for AccountAddress {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl convert::AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Address of a contract.
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct ContractAddress {
    pub(crate) index:    u64,
    pub(crate) subindex: u64,
}

/// Chain context accessible to the init methods.
///
/// TODO: We could optimize this to be initialized lazily
pub struct InitContext {
    pub(crate) metadata:    ChainMetadata,
    pub(crate) init_origin: AccountAddress,
}

/// Either an address of an account, or contract.
pub enum Address {
    Account(AccountAddress),
    Contract(ContractAddress),
}

/// Chain context accessible to the receive methods.
///
/// TODO: We could optimize this to be initialized lazily.
pub struct ReceiveContext {
    pub(crate) metadata:     ChainMetadata,
    pub(crate) invoker:      AccountAddress,
    pub(crate) self_address: ContractAddress,
    pub(crate) self_balance: Amount,
    pub(crate) sender:       Address,
    pub(crate) owner:        AccountAddress,
}

/// Chain metadata accessible to both receive and init methods.
pub struct ChainMetadata {
    pub(crate) slot_number:      u64,
    pub(crate) block_height:     u64,
    pub(crate) finalized_height: u64,
    pub(crate) slot_time:        u64,
}

/// Actions that can be produced at the end of a contract execution. This
/// type is deliberately not cloneable so that we can enforce that
/// `and_then` and `or_else` can only be used when more than one event is
/// created.
///
/// This type is marked as `must_use` since functions that produce
/// values of the type are effectful.
#[must_use]
pub struct Action {
    pub(crate) _private: (),
}

/// Result of a successful smart contract execution receive method.
pub enum ReceiveActions {
    /// Simply accept the invocation, with no additional actions.
    Accept,
    /// Accept with the given action tree.
    AcceptWith(Action),
}

/// A non-descript error message, signalling rejection of a smart contract
/// invocation.
#[derive(Default)]
pub struct Reject {}

#[macro_export]
/// The `bail` macro can be used for cleaner error handling. If the function has
/// result type Result<_, Reject> then invoking `bail` will terminate execution
/// early with an error. If the macro is invoked with a string message the
/// message will be logged before the function terminates.
macro_rules! bail {
    () => {
        return Err(Reject {})
    };
    ($e:expr) => {{
        $crate::events::log_str($e);
        return Err(Reject {});
    }};
}

#[macro_export]
/// The `ensure` macro can be used for cleaner error handling. It is analogous
/// to `assert`, but instead of panicking it uses `bail` to terminate execution
/// of the function early.
macro_rules! ensure {
    ($p:expr) => {
        if !$p {
            return Err(Reject {});
        }
    };
    ($p:expr, $e:expr) => {{
        if !$p {
            $crate::bail!($e)
        }
    }};
}

/// The expected return type of the receive method of a smart contract.
pub type ReceiveResult = Result<ReceiveActions, Reject>;

/// The expected return type of the init method of the smart contract,
/// parametrized by the state type of the smart contract.
pub type InitResult<S> = Result<S, Reject>;
