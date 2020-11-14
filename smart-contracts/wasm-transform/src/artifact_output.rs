use std::{convert::TryInto, io::Write};

use crate::{artifact::*, output::OutResult, types::*};

pub trait Output {
    fn output(&self, out: &mut impl Write) -> OutResult<()>;
}

/// Output as little endian bytes.
impl Output for u8 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

/// Output as little endian bytes.
impl Output for u32 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

impl Output for i32 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

impl Output for i64 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

/// Output as little endian 4 bytes.
impl Output for usize {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        let len: u32 = (*self).try_into()?;
        len.output(out)
    }
}

impl Output for Option<ValueType> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match self {
            Some(ValueType::I32) => {
                out.write_all(&[0u8])?;
            }
            Some(ValueType::I64) => {
                out.write_all(&[1u8])?;
            }
            None => {
                out.write_all(&[255u8])?;
            }
        }
        Ok(())
    }
}

impl Output for Option<FuncIndex> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match self {
            Some(x) => x.output(out),
            None => (!0u32).output(out), /* this is fine because the maximum number of functions
                                          * is less than 2^32 */
        }
    }
}

impl Output for ValueType {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match self {
            ValueType::I32 => {
                out.write_all(&[0u8])?;
            }
            ValueType::I64 => {
                out.write_all(&[1u8])?;
            }
        }
        Ok(())
    }
}

impl Output for FunctionType {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.parameters.len().output(out)?;
        for t in self.parameters.iter() {
            t.output(out)?;
        }
        self.result.output(out)
    }
}

impl Output for Data {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.offset.output(out)?;
        self.init.len().output(out)?;
        out.write_all(&self.init)?;
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

impl<ImportFunc: Output, CompiledCode: RunnableCode> Output for Artifact<ImportFunc, CompiledCode> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        self.imports.len().output(out)?;
        for i in self.imports.iter() {
            i.output(out)?;
        }
        self.ty.len().output(out)?;
        for ft in self.ty.iter() {
            ft.output(out)?;
        }
        self.table.functions.len().output(out)?;
        for t in self.table.functions.iter() {
            t.output(out)?;
        }
        match self.memory.as_ref() {
            Some(mem) => {
                mem.init_size.output(out)?;
                mem.max_size.output(out)?;
                mem.init.len().output(out)?;
                for init in mem.init.iter() {
                    init.output(out)?;
                }
            }
            None => (!0u32).output(out)?,
        }
        self.global.inits.len().output(out)?;
        for g in self.global.inits.iter() {
            g.output(out)?;
        }
        self.export.len().output(out)?;
        for (name, idx) in self.export.iter() {
            name.len().output(out)?;
            out.write_all(name.as_bytes())?;
            idx.output(out)?;
        }
        self.code.len().output(out)?;
        for code in self.code.iter() {
            code.num_params().output(out)?;
            code.type_idx().output(out)?;
            code.return_type().output(out)?;
            code.locals().len().output(out)?;
            for local in code.locals() {
                local.output(out)?;
            }
            code.code().len().output(out)?;
            out.write_all(code.code())?;
        }
        Ok(())
    }
}
