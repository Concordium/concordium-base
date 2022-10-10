pub mod constants;
#[cfg(feature = "fuzz")]
pub mod fuzz;
pub mod resumption;
pub mod utils;
pub mod v0;
pub mod v1;
#[cfg(test)]
mod validation_tests;
use anyhow::{bail, Context};
use derive_more::{Display, From, Into};

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

/// Result of contract execution. This is just a wrapper around
/// [anyhow::Result].
pub type ExecResult<A> = anyhow::Result<A>;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, From, Into, Display)]
#[display(fmt = "{}", energy)]
/// Interpreter energy used to count execution steps in the interpreter.
/// This energy is converted to NRG by the scheduler.
pub struct InterpreterEnergy {
    /// Energy left to use
    pub energy: u64,
}

impl InterpreterEnergy {
    /// Subtract the given amount from the energy, bottoming out at 0.
    pub fn subtract(self, consumed: u64) -> Self {
        Self {
            energy: self.energy.saturating_sub(consumed),
        }
    }
}

impl std::str::FromStr for InterpreterEnergy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let energy = s.parse::<u64>().context("Could not parse interpreter energy.")?;
        Ok(Self {
            energy,
        })
    }
}

#[derive(Debug)]
pub struct OutOfEnergy;

impl std::fmt::Display for OutOfEnergy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { "Out of energy".fmt(f) }
}

impl InterpreterEnergy {
    pub fn tick_energy(&mut self, amount: u64) -> ExecResult<()> {
        if self.energy >= amount {
            self.energy -= amount;
            Ok(())
        } else {
            self.energy = 0;
            bail!(OutOfEnergy)
        }
    }

    /// TODO: This needs more specification. At the moment it is not used, but
    /// should be.
    pub fn charge_stack(&mut self, amount: u64) -> ExecResult<()> {
        if self.energy >= amount {
            self.energy -= amount;
            Ok(())
        } else {
            self.energy = 0;
            bail!("Out of energy.")
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
