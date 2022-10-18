use std::sync::Arc;

use crate::ExecResult;
use wasm_transform::{
    artifact::{Artifact, RunnableCode, TryFromImport},
    machine::{ExecutionOutcome, Host, RunConfig},
};

/// Interrupted state of the computation that may be resumed.
#[derive(Debug)]
pub struct InterruptedState<Imports, R, Host> {
    pub(crate) host:     Host,
    pub(crate) artifact: Arc<Artifact<Imports, R>>,
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
