//! Functionality for outputting Wasm modules in binary format.

use crate::{
    constants::{MAGIC_HASH, VERSION},
    parse::{Byte, SectionId, Skeleton, UnparsedSection},
    types::{BlockType, CustomSection, FunctionType, Name, ValueType},
};
use std::{
    convert::{TryFrom, TryInto},
    io::Write,
};

pub type OutResult<A> = anyhow::Result<A>;

/// Output data in a format compatible with Parseable.
pub trait Output {
    fn output(&self, out: &mut impl Write) -> OutResult<()>;
}

/// Output as little endian bytes.
impl Output for Byte {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

impl Output for u16 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        leb128::write::unsigned(out, u64::from(*self))?;
        Ok(())
    }
}

impl Output for u32 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        leb128::write::unsigned(out, u64::from(*self))?;
        Ok(())
    }
}

impl Output for u64 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        leb128::write::unsigned(out, *self)?;
        Ok(())
    }
}

impl Output for i32 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        leb128::write::signed(out, i64::from(*self))?;
        Ok(())
    }
}

impl Output for i64 {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        leb128::write::signed(out, *self)?;
        Ok(())
    }
}

impl Output for ValueType {
    fn output(&self, out: &mut impl Write) -> OutResult<()> { u8::from(*self).output(out) }
}

impl Output for FunctionType {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        0x60u8.output(out)?;
        self.parameters.output(out)?;
        self.result.output(out)
    }
}

impl<'a> Output for UnparsedSection<'a> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&[self.section_id as u8])?;
        let len = u32::try_from(self.bytes.len())?;
        len.output(out)?;
        out.write_all(self.bytes)?;
        Ok(())
    }
}

impl<'a, A: Output> Output for &'a [A] {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        let len: u32 = self.len().try_into()?;
        len.output(out)?;
        for a in self.iter() {
            a.output(out)?;
        }
        Ok(())
    }
}

/// This implementation records the length of the vector as a u32 and then
/// writes the elements in order.
impl<A: Output> Output for Vec<A> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> { self.as_slice().output(out) }
}

impl Output for BlockType {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match self {
            BlockType::EmptyType => 0x40u8.output(out),
            BlockType::ValueType(vt) => u8::from(*vt).output(out),
        }
    }
}

/// The instance for a byte array is a special case of the instance for generic
/// A, but it is more efficient to do one write so we have a special case.
impl<A: Output> Output for Option<A> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        match self.as_ref() {
            Some(v) => {
                1u8.output(out)?;
                v.output(out)?;
            }
            None => {
                0u8.output(out)?;
            }
        }
        Ok(())
    }
}

/// Names are output as byte arrays.
impl Output for Name {
    fn output(&self, out: &mut impl Write) -> OutResult<()> { self.name.as_bytes().output(out) }
}

/// Write out the skeleton. All the custom sections are written at the end.
/// This makes it possible to output additional ones incrementally.
impl<'a> Output for Skeleton<'a> {
    fn output(&self, out: &mut impl Write) -> OutResult<()> {
        out.write_all(&MAGIC_HASH)?;
        out.write_all(&VERSION)?;
        if let Some(ref tys) = self.ty {
            tys.output(out)?;
        }
        if let Some(ref imports) = self.import {
            imports.output(out)?;
        }
        if let Some(ref funcs) = self.func {
            funcs.output(out)?;
        }
        if let Some(ref tables) = self.table {
            tables.output(out)?;
        }
        if let Some(ref memories) = self.memory {
            memories.output(out)?;
        }
        if let Some(ref globals) = self.global {
            globals.output(out)?;
        }
        if let Some(ref exports) = self.export {
            exports.output(out)?;
        }
        if let Some(ref start) = self.start {
            start.output(out)?;
        }
        if let Some(ref element) = self.element {
            element.output(out)?;
        }
        if let Some(ref code) = self.code {
            code.output(out)?;
        }
        if let Some(ref data) = self.data {
            data.output(out)?;
        }
        for cs in self.custom.iter() {
            cs.output(out)?;
        }
        Ok(())
    }
}

/// Output a custom section into the given writer.
pub fn write_custom_section(out: &mut impl Write, cs: &CustomSection) -> OutResult<()> {
    out.write_all(&[SectionId::Custom as u8])?;
    let name_len = cs.name.name.as_bytes().len();
    // temporary buffer for writing length of the name so we can retrieve how many
    // bytes are needed.
    let mut tmp_out = Vec::with_capacity(5);
    let num_bytes = {
        (name_len as u32).output(&mut tmp_out)?;
        tmp_out.len()
    };
    // total number of bytes for the contents of the custom section
    let bytes_len: u32 = name_len as u32 + num_bytes as u32 + cs.contents.len() as u32;
    bytes_len.output(out)?;
    // write out the name length
    out.write_all(&tmp_out)?;
    // write out the name bytes
    out.write_all(cs.name.name.as_bytes())?;
    // and the remaining contents
    out.write_all(cs.contents)?;
    Ok(())
}
