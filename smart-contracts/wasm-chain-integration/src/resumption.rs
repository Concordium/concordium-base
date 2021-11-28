use crate::{ExecResult, ProcessedImports};
use wasm_transform::{
    artifact::OwnedArtifact,
    machine::{ExecutionOutcome, Host, RunConfig},
};

/// Interrupted state of the computation that may be resumed.
pub struct InterruptedState<H> {
    pub(crate) host:     H,
    pub(crate) artifact: OwnedArtifact<ProcessedImports>,
    pub(crate) config:   RunConfig,
}

impl<H: Host<ProcessedImports>> InterruptedState<H> {
    /// Resume the suspended computation.
    pub fn resume(mut self) -> ExecResult<ExecutionOutcome<H::Interrupt>> {
        let host = &mut self.host;
        self.artifact.run_config(host, self.config)
    }
}
