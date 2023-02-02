//! This module defines the notion of suspended Wasm computation
//! used by V1 contracts to execute host operations such as transfers and
//! contract calls.
use crate::ExecResult;
use concordium_wasm::{
    artifact::{Artifact, RunnableCode, TryFromImport},
    machine::{ExecutionOutcome, Host, RunConfig},
};
use std::sync::Arc;

/// Interrupted state of the computation that may be resumed.
#[derive(Debug)]
pub struct InterruptedState<Imports, R, Host> {
    /// The [`Host`] that was used for execution that was interrupted.
    pub(crate) host:     Host,
    /// The artifact that is running.
    pub(crate) artifact: Arc<Artifact<Imports, R>>,
    /// The runtime configuration at the time the interrupt was triggered.
    pub(crate) config:   RunConfig,
}

impl<Imports: TryFromImport, H: Host<Imports>, R: RunnableCode> InterruptedState<Imports, R, H> {
    /// Resume the suspended computation. Return the updated host together with
    /// the execution outcome.
    pub fn resume(mut self) -> ExecResult<(H, ExecutionOutcome<H::Interrupt>)> {
        let host = &mut self.host;
        let result = self.artifact.run_config(host, self.config)?;
        Ok((self.host, result))
    }
}
