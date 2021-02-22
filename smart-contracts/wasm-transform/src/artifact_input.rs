//! Utilities for parsing of artifacts from byte streams.

use crate::{
    artifact::{
        Artifact, ArtifactData, ArtifactLocal, ArtifactMemory, ArtifactNamedImport,
        CompiledFunctionBytes, InstantiatedGlobals, InstantiatedTable,
    },
    parse::*,
    types::{BlockType, FuncIndex, FunctionType, GlobalInit, Name, TypeIndex, ValueType},
};
use anyhow::bail;
use std::{collections::BTreeMap, io::Cursor};

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ArtifactLocal {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let multiplicity = cursor.next(ctx)?;
        let ty = cursor.next(ctx)?;
        Ok(ArtifactLocal {
            multiplicity,
            ty,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ArtifactNamedImport {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mod_name = cursor.next(ctx)?;
        let item_name = cursor.next(ctx)?;
        let ty = cursor.next(ctx)?;
        Ok(ArtifactNamedImport {
            mod_name,
            item_name,
            ty,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for InstantiatedGlobals {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(ctx, cursor)?;
        let mut inits = Vec::with_capacity(len as usize);
        for _ in 0..len {
            match Byte::parse(ctx, cursor)? {
                0 => {
                    inits.push(GlobalInit::I32(cursor.next(ctx)?));
                }
                1 => {
                    inits.push(GlobalInit::I64(cursor.next(ctx)?));
                }
                _ => bail!("Unsupported global init tag."),
            }
        }
        Ok(InstantiatedGlobals {
            inits,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for CompiledFunctionBytes<'a> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let type_idx = TypeIndex::parse(ctx, cursor)?;
        let return_type = BlockType::parse(ctx, cursor)?;
        let params: &'a [ValueType] = cursor.next(ctx)?;
        let num_locals: u32 = cursor.next(ctx)?;
        let locals: Vec<ArtifactLocal> = cursor.next(ctx)?;
        let code = cursor.next(ctx)?;
        Ok(CompiledFunctionBytes {
            type_idx,
            return_type,
            params,
            num_locals,
            locals,
            code,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for InstantiatedTable {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let functions = cursor.next(ctx)?;
        Ok(InstantiatedTable {
            functions,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ArtifactMemory {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let init_size = cursor.next(ctx)?;
        let max_size = cursor.next(ctx)?;
        let init = Vec::<ArtifactData>::parse(ctx, cursor)?;
        Ok(ArtifactMemory {
            init_size,
            max_size,
            init,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ArtifactData {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let offset = cursor.next(ctx)?;
        let init = cursor.next(ctx)?;
        Ok(Self {
            offset,
            init,
        })
    }
}

/// NB: This implementation is only meant to be used on trusted sources.
/// It optimistically allocates memory, which could lead to problems if the
/// input is untrusted.
impl<'a, Ctx: Copy, I: Parseable<'a, Ctx>> Parseable<'a, Ctx>
    for Artifact<I, CompiledFunctionBytes<'a>>
{
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let imports: Vec<I> = Vec::parse(ctx, cursor)?;
        let ty: Vec<FunctionType> = Vec::parse(ctx, cursor)?;
        let table = InstantiatedTable::parse(ctx, cursor)?;
        let memory = cursor.next(ctx)?;
        let global = InstantiatedGlobals::parse(ctx, cursor)?;
        let export_len = u32::parse(ctx, cursor)?;
        let mut export = BTreeMap::new();
        for _ in 0..export_len {
            let name = Name::parse(ctx, cursor)?;
            let idx = FuncIndex::parse(ctx, cursor)?;
            if export.insert(name, idx).is_some() {
                bail!("Duplicate names in export list. This should not happen in artifacts.")
            }
        }
        let code = Vec::parse(ctx, cursor)?;
        Ok(Artifact {
            imports,
            ty,
            table,
            memory,
            global,
            export,
            code,
        })
    }
}
