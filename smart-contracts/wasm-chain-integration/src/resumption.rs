use crate::ExecResult;
use wasm_transform::{
    artifact::{OwnedArtifact, TryFromImport},
    machine::{ExecutionOutcome, Host, RunConfig},
};

/// Interrupted state of the computation that may be resumed.
pub struct InterruptedState<Imports, H> {
    pub(crate) host:     H,
    pub(crate) artifact: OwnedArtifact<Imports>,
    pub(crate) config:   RunConfig,
}

impl<Imports: TryFromImport, H: Host<Imports>> InterruptedState<Imports, H> {
    /// Resume the suspended computation.
    pub fn resume(mut self) -> ExecResult<ExecutionOutcome<H::Interrupt>> {
        let host = &mut self.host;
        self.artifact.run_config(host, self.config)
    }
}
