//! This library provides functionality that builds on top of the [Wasm engine](https://docs.rs/concordium-wasm)
//! and adds high-level functions for executing smart contracts on the
//! Concordium chain.
//!
//! Concordium supports two versions of smart contracts, the legacy [`v0`]
//! version and the [`v1`] version. The latter is essentially better in
//! every way. They differ in two main ways
//! - [`v0`] uses message passing for inter-contract communication, and has a
//!   flat state. The state is limited to 16kB and the entire state is written
//!   every time a contract update is done.
//! - [`v1`] uses synchronous calls for inter-contract communication, and its
//!   state is a trie-based structure, which supports efficient partial state
//!   updates. The trie is implemented in the [`v1::trie`] module.
//!
//! Both [`v0`] and [`v1`] modules are structured similarly. The main
//! entrypoints used by users of this library are [`v0::invoke_init`] (resp.
//! [`v1::invoke_init`]) and [`v0::invoke_receive`] (resp.
//! [`v1::invoke_receive`]) functions, and their variants.
//!
//! The respective modules provide more details on the data types involved, and
//! any specifics of the different versions.
//!
//! ## Features
//!
//! This crate has the following features. None are enabled by default.
//!
//! ### `display-state`
//! This feature exposes the function
//! [`display_tree`](v1::trie::PersistentState::display_tree) for displaying the
//! V1 contract state in a reasonably readable format. This is useful for deep
//! inspection of smart contract state, and debugging.
//!
//! ### `async`
//! Exposes construction of smart contract state from streams of key-value
//! pairs, such as those received from the node's API. See
//! - [`try_from_stream`](v1::trie::PersistentState::try_from_stream)
//! - [`from_stream`](v1::trie::PersistentState::from_stream)
//!
//! ### `enable-ffi`
//! This enables foreign function exports. This is an **internal** feature and
//! there are no guarantees about the stability of foreign exports.
//!
//! ### `fuzz-coverage` and `fuzz`
//! These features are also **internal** and exist to support fuzzing. They are
//! used to derive Arbitrary instances and to disable inlining, the latter is
//! necessary since the fuzzer used has bugs which prevent the coverage report
//! being generated when functions are inlined.
pub mod constants;
pub mod resumption;
pub mod utils;
pub mod v0;
pub mod v1;
#[cfg(test)]
mod validation_tests;
use anyhow::bail;
use derive_more::{Display, From, Into};

/// Re-export the underlying Wasm execution engine used by Concordium.
pub use concordium_wasm as wasm;

/// A helper macro used to check that the declared type of a Wasm import matches
/// the required one.
///
/// # Example 1
/// ```ignore
/// type_matches!(ty => [I32, I64])
/// ```
/// The declared type `ty` must have **no return value** and parameters of types
/// `I32` and `I64`
///
/// # Example 2
/// ```ignore
/// type_matches!(ty => []; I64)
/// ```
/// The declared type `ty` must have return type I64 and no arguments.
///
/// # Example 3
/// ```ignore
/// type_matches!(ty => [I32, I64, I32]; I64)
/// ```
/// The declared type `ty` must have return type I64 and arguments of types
/// `I32, I64, I32` in that order.
macro_rules! type_matches {
    ($goal:expr => $params:expr) => {
        $goal.result.is_none() && $params == $goal.parameters.as_slice()
    };
    ($goal:expr => []; $result:expr) => {
        $goal.result == Some($result) && $goal.parameters.is_empty()
    };
    ($goal:expr => $params:expr; $result:expr) => {
        $goal.result == Some($result) && $params == $goal.parameters.as_slice()
    };
}
pub(crate) use type_matches;
use v1::EnergyLabel;

/// Result of contract execution. This is just a wrapper around
/// [`anyhow::Result`].
pub type ExecResult<A> = anyhow::Result<A>;

pub trait DebugInfo {
    const ENABLE_DEBUG: bool;

    fn empty_trace() -> Self;

    fn trace_host_call(&mut self, f: v1::ImportFunc, energy_used: InterpreterEnergy);

    fn combine(&mut self, other: Self);
}

impl DebugInfo for () {
    const ENABLE_DEBUG: bool = false;

    #[inline(always)]
    fn empty_trace() -> Self {}

    #[inline(always)]
    fn trace_host_call(&mut self, _f: v1::ImportFunc, _energy_used: InterpreterEnergy) {
        // do nothing
    }

    #[inline(always)]
    fn combine(&mut self, _other: Self) {
        // do nothing
    }
}

#[derive(Debug, Clone, Copy, From, Into, Display, derive_more::FromStr)]
#[display(fmt = "{}", energy)]
#[repr(transparent)]
pub struct InterpreterEnergy {
    /// Energy left to use
    pub energy: u64,
}

pub trait LabelEnergy: std::fmt::Debug {
    fn label(&mut self, value: EnergyLabel, amount: u64);

    fn combine(&mut self, other: &Self);
}

impl LabelEnergy for () {
    #[inline(always)]
    fn label(&mut self, _value: EnergyLabel, _amount: u64) {}

    #[inline(always)]
    fn combine(&mut self, _other: &Self) {}
}

impl InterpreterEnergy {
    pub fn new(energy: u64) -> Self { Self::from(energy) }

    /// Subtract the given amount from the energy, bottoming out at 0.
    pub fn subtract(self, consumed: u64) -> Self {
        Self {
            energy: self.energy.saturating_sub(consumed),
        }
    }

    /// Saturating interpreter energy subtraction.
    ///
    /// Computes `self - rhs` bottoming out at `0` instead of underflowing.
    pub fn saturating_sub(self, consumed: &Self) -> Self {
        Self {
            energy: self.energy.saturating_sub(consumed.energy),
        }
    }

    pub fn tick_energy(&mut self, amount: u64) -> ExecResult<()> {
        if self.energy >= amount {
            self.energy -= amount;
            Ok(())
        } else {
            self.energy = 0;
            bail!(OutOfEnergy)
        }
    }

    /// Charge energy for allocating the given number of pages.
    /// Since there is a hard limit on the amount of memory this is not so
    /// essential. The base cost of calling this host function is already
    /// covered by the metering transformation, hence if num_pages=0 it is
    /// OK for this function to charge nothing.
    ///
    /// This function will charge regardless of whether memory allocation
    /// actually happens, i.e., even if growing the memory would go over the
    /// maximum. This is OK since trying to allocate too much memory is likely
    /// going to lead to program failure anyhow.
    pub fn charge_memory_alloc(&mut self, num_pages: u32) -> ExecResult<()> {
        let to_charge = u64::from(num_pages) * u64::from(constants::MEMORY_COST_FACTOR); // this cannot overflow because of the cast.
        self.tick_energy(to_charge)
    }
}

#[derive(Debug)]
/// An error raised by the interpreter when no more interpreter energy remains
/// for execution.
pub struct OutOfEnergy;

impl std::fmt::Display for OutOfEnergy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { "Out of energy".fmt(f) }
}
