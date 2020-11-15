use crate::{
    artifact::*,
    output::{OutResult, Output},
    types::*,
};
use std::io::Write;

impl Output for ArtifactData {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.offset.output(out)?;
        self.init.output(out)?;
        Ok(())
    }
}

impl Output for GlobalInit {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match *self {
            GlobalInit::I32(x) => {
                0u8.output(out)?;
                x.output(out)
            }
            GlobalInit::I64(x) => {
                1u8.output(out)?;
                x.output(out)
            }
        }
    }
}

impl Output for (Name, Name) {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.0.output(out)?;
        self.1.output(out)?;
        Ok(())
    }
}

impl Output for ArtifactMemory {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.init_size.output(out)?;
        self.max_size.output(out)?;
        self.init.output(out)
    }
}

impl<C: RunnableCode> Output for C {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.num_params().output(out)?;
        self.type_idx().output(out)?;
        self.return_type().output(out)?;
        self.locals().output(out)?;
        self.code().output(out)
    }
}

impl Output for InstantiatedGlobals {
    fn output(&self, out: &mut impl Write) -> OutResult<()> { self.inits.output(out) }
}

impl<ImportFunc: Output, CompiledCode: RunnableCode> Output for Artifact<ImportFunc, CompiledCode> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.imports.output(out)?;
        self.ty.output(out)?;
        self.table.functions.output(out)?;
        self.memory.output(out)?;
        self.global.output(out)?;
        (self.export.len() as u32).output(out)?;
        for (name, idx) in self.export.iter() {
            name.output(out)?;
            idx.output(out)?;
        }
        self.code.output(out)
    }
}
