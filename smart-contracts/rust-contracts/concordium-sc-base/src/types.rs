/// A type representing the constract state bytes.
#[derive(Default)]
pub struct ContractState {
    pub(crate) current_position: u32,
}

#[derive(Default)]
/// A type representing the parameter to init and receive methods.
pub struct Parameter {
    pub(crate) current_position: u32,
}

/// A type representing the logger.
#[derive(Default)]
pub struct Logger {
    pub(crate) _private: (),
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
    pub(crate) _private: u32,
}

impl Action {
    pub fn tag(&self) -> u32 { self._private }
}

/// A non-descript error message, signalling rejection of a smart contract
/// invocation.
#[derive(Default, Eq, PartialEq)]
pub struct Reject {}

#[macro_export]
/// The `bail` macro can be used for cleaner error handling. If the function has
/// result type Result<_, Reject> then invoking `bail` will terminate execution
/// early with an error. If the macro is invoked with a string message the
/// message will be logged before the function terminates.
macro_rules! bail {
    () => {
        return Err(Reject {});
    };
    ($e:expr) => {{
        // logs are not retained in case of rejection.
        // $crate::events::log_bytes($e);
        return Err(Reject {});
    }};
    ($fmt:expr, $($arg:tt)+) => {{
        // format_err!-like formatting
        // logs are not retained in case of rejection.
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
    ($p:expr, $($arg:tt)+) => {{
        if !$p {
            $crate::bail!($($arg:tt)+)
        }
    }};
}

/// ## Variants of `ensure` for ease of use in certain contexts.
#[macro_export]
/// Ensure the first two arguments are equal, using `bail` otherwise.
macro_rules! ensure_eq {
    ($l:expr, $r:expr) => {
        $crate::ensure!($l == $r)
    };
    ($l:expr, $r:expr, $($arg:tt)+) => {
        $crate::ensure!($l == $r, $($arg:tt)+)
    };
}

#[macro_export]
/// Ensure the first two arguments are __not__ equal, using `bail` otherwise.
macro_rules! ensure_ne {
    ($l:expr, $r:expr) => {
        $crate::ensure!($l != $r)
    };
    ($l:expr, $r:expr, $($arg:tt)+) => {
        $crate::ensure!($l != $r, $($arg:tt)+)
    };
}

/// The expected return type of the receive method of a smart contract.
pub type ReceiveResult<A> = Result<A, Reject>;

/// The expected return type of the init method of the smart contract,
/// parametrized by the state type of the smart contract.
pub type InitResult<S> = Result<S, Reject>;
