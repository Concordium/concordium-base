//! Utilities for parsing of artifacts from byte streams.

use crate::{
    artifact::{
        Artifact, ArtifactData, ArtifactMemory, ArtifactNamedImport, CompiledFunctionBytes,
        InstantiatedGlobals, InstantiatedTable,
    },
    parse::*,
    types::{BlockType, FuncIndex, FunctionType, GlobalInit, Name, TypeIndex, ValueType},
};
use anyhow::bail;
use std::{collections::BTreeMap, io::Cursor};

impl<'a> Parseable<'a> for ArtifactNamedImport {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mod_name = cursor.next()?;
        let item_name = cursor.next()?;
        let ty = cursor.next()?;
        Ok(ArtifactNamedImport {
            mod_name,
            item_name,
            ty,
        })
    }
}

impl<'a> Parseable<'a> for InstantiatedGlobals {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(cursor)?;
        let mut inits = Vec::with_capacity(len as usize);
        for _ in 0..len {
            match Byte::parse(cursor)? {
                0 => {
                    inits.push(GlobalInit::I32(cursor.next()?));
                }
                1 => {
                    inits.push(GlobalInit::I64(cursor.next()?));
                }
                _ => bail!("Unsupported global init tag."),
            }
        }
        Ok(InstantiatedGlobals {
            inits,
        })
    }
}

impl<'a> Parseable<'a> for CompiledFunctionBytes<'a> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let num_params = u32::parse(cursor)?;
        let type_idx = TypeIndex::parse(cursor)?;
        let return_type = BlockType::parse(cursor)?;
        let locals: &'a [ValueType] = cursor.next()?;
        let code = cursor.next()?;
        Ok(CompiledFunctionBytes {
            num_params,
            type_idx,
            return_type,
            locals,
            code,
        })
    }
}

impl<'a> Parseable<'a> for InstantiatedTable {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let functions = cursor.next()?;
        Ok(InstantiatedTable {
            functions,
        })
    }
}

impl<'a> Parseable<'a> for ArtifactMemory {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let init_size = cursor.next()?;
        let max_size = cursor.next()?;
        let init = Vec::<ArtifactData>::parse(cursor)?;
        Ok(ArtifactMemory {
            init_size,
            max_size,
            init,
        })
    }
}

impl<'a> Parseable<'a> for ArtifactData {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let offset = cursor.next()?;
        let init = cursor.next()?;
        Ok(Self {
            offset,
            init,
        })
    }
}

/// NB: This implementation is only meant to be used on trusted sources.
/// It optimistically allocates memory, which could lead to problems if the
/// input is untrusted.
impl<'a, I: Parseable<'a>> Parseable<'a> for Artifact<I, CompiledFunctionBytes<'a>> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let imports: Vec<I> = Vec::parse(cursor)?;
        let ty: Vec<FunctionType> = Vec::parse(cursor)?;
        let table = InstantiatedTable::parse(cursor)?;
        let memory = cursor.next()?;
        let global = InstantiatedGlobals::parse(cursor)?;
        let export_len = u32::parse(cursor)?;
        let mut export = BTreeMap::new();
        for _ in 0..export_len {
            let name = Name::parse(cursor)?;
            let idx = FuncIndex::parse(cursor)?;
            if export.insert(name, idx).is_some() {
                bail!("Duplicate names in export list. This should not happen in artifacts.")
            }
        }
        let code = Vec::parse(cursor)?;
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
