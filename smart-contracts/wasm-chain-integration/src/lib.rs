pub mod constants;
#[cfg(feature = "fuzz")]
pub mod fuzz;
pub mod resumption;
pub mod utils;
pub mod v0;
#[cfg(test)]
mod validation_tests;

use anyhow::bail;

/// Result of contract execution. This is just a wrapper around
/// [anyhow::Result].
pub type ExecResult<A> = anyhow::Result<A>;

#[derive(Clone, Copy)]
/// Interpreter energy used to count execution steps in the interpreter.
/// This energy is converted to NRG by the scheduler.
pub struct InterpreterEnergy {
    /// Energy left to use
    pub energy: u64,
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
