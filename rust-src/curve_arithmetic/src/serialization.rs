use failure::Error;
use std::io::{Cursor, Read};

use crate::curve_arithmetic::Curve;
use byteorder::{BigEndian, ReadBytesExt};

pub fn read_exact_bytes<'a>(cur: &mut Cursor<&[u8]>, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
    cur.read_exact(buf)?;
    Ok(buf)
}

pub fn read_curve_scalar<C: Curve>(
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<C::Scalar, Error> {
    let s = C::bytes_to_scalar(read_exact_bytes(cur, buf)?)?;
    Ok(s)
}

pub fn read_curve<C: Curve>(cur: &mut Cursor<&[u8]>, buf: &mut [u8]) -> Result<C, Error> {
    let s = C::bytes_to_curve(read_exact_bytes(cur, buf)?)?;
    Ok(s)
}

pub fn read_curve_scalars<C: Curve>(
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<Vec<C::Scalar>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        res.push(read_curve_scalar::<C>(cur, buf)?);
    }
    Ok(res)
}

pub fn read_curve_elements<C: Curve>(
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<Vec<C>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        res.push(read_curve::<C>(cur, buf)?);
    }
    Ok(res)
}

pub fn write_curve_element<C: Curve>(elem: &C, out: &mut Vec<u8>) {
    out.extend_from_slice(&elem.curve_to_bytes());
}

pub fn write_curve_scalar<C: Curve>(elem: &C::Scalar, out: &mut Vec<u8>) {
    out.extend_from_slice(&C::scalar_to_bytes(elem));
}

pub fn write_curve_elements<C: Curve>(elems: &[C], out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
    for elem in elems.iter() {
        out.extend_from_slice(&elem.curve_to_bytes());
    }
}

pub fn write_curve_scalars<C: Curve>(elems: &[C::Scalar], out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
    for elem in elems.iter() {
        out.extend_from_slice(&C::scalar_to_bytes(elem));
    }
}
