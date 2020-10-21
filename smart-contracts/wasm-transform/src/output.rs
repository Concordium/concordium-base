//! Functionality for outputting Wasm modules in binary format.

use crate::{
    parse::{SectionId, Skeleton, UnparsedSection, MAGIC_HASH, VERSION},
    types::CustomSection,
};
use std::{convert::TryFrom, io::Write};

pub type OutResult<A> = anyhow::Result<A>;

/// Write a u32 in LEB128 and return then number of bytes used.
fn write_u32(out: &mut impl Write, x: u32) -> OutResult<usize> {
    let num_bytes = leb128::write::unsigned(out, u64::from(x))?;
    Ok(num_bytes)
}

fn write_section<'a>(out: &mut impl Write, sec: &UnparsedSection<'a>) -> OutResult<()> {
    out.write_all(&[sec.section_id as u8])?;
    let len = u32::try_from(sec.bytes.len())?;
    write_u32(out, len)?;
    out.write_all(sec.bytes)?;
    Ok(())
}

/// Write out the skeleton. All the custom sections are written at the end.
/// This makes it possible to output additional ones incrementally.
pub fn write_skeleton<'a>(out: &mut impl Write, skeleton: &Skeleton<'a>) -> OutResult<()> {
    out.write_all(&MAGIC_HASH)?;
    out.write_all(&VERSION)?;
    if let Some(ref tys) = skeleton.ty {
        write_section(out, tys)?;
    }
    if let Some(ref imports) = skeleton.import {
        write_section(out, imports)?;
    }
    if let Some(ref funcs) = skeleton.func {
        write_section(out, funcs)?;
    }
    if let Some(ref tables) = skeleton.table {
        write_section(out, tables)?;
    }
    if let Some(ref memories) = skeleton.memory {
        write_section(out, memories)?;
    }
    if let Some(ref globals) = skeleton.global {
        write_section(out, globals)?;
    }
    if let Some(ref exports) = skeleton.export {
        write_section(out, exports)?;
    }
    if let Some(ref start) = skeleton.start {
        write_section(out, start)?;
    }
    if let Some(ref element) = skeleton.element {
        write_section(out, element)?;
    }
    if let Some(ref code) = skeleton.code {
        write_section(out, code)?;
    }
    if let Some(ref data) = skeleton.data {
        write_section(out, data)?;
    }
    for cs in skeleton.custom.iter() {
        write_section(out, cs)?;
    }
    Ok(())
}

/// Output a custom section into the given writer.
pub fn write_custom_section(out: &mut impl Write, cs: &CustomSection) -> OutResult<()> {
    out.write_all(&[SectionId::Custom as u8])?;
    let name_len = cs.name.name.as_bytes().len();
    // temporary buffer for writing length of the name so we can retrieve how many
    // bytes are needed.
    let mut tmp_out = Vec::with_capacity(5);
    let num_bytes = write_u32(&mut tmp_out, name_len as u32)?;
    // total number of bytes for the contents of the custom section
    let bytes_len = name_len as u32 + num_bytes as u32 + cs.contents.len() as u32;
    write_u32(out, bytes_len)?;
    // write out the name length
    out.write_all(&tmp_out)?;
    // write out the name bytes
    out.write_all(cs.name.name.as_bytes())?;
    // and the remaining contents
    out.write_all(cs.contents)?;
    Ok(())
}
