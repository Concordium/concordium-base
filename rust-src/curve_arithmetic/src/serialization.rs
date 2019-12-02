use failure::Error;
use std::io::Cursor;

use crate::curve_arithmetic::{Curve, Pairing};
use byteorder::{BigEndian, ReadBytesExt};

use common;

pub fn read_curve_scalar<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<C::Scalar, Error> {
    let s = C::bytes_to_scalar(cur)?;
    Ok(s)
}

pub fn read_curve<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<C, Error> {
    let s = C::bytes_to_curve(cur)?;
    Ok(s)
}

/// Read 4 bytes in big-endian encoding and convert to usize.
pub fn read_length(cur: &mut Cursor<&[u8]>) -> Result<usize, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    Ok(len as usize)
}

/// Read a list of scalars of a given length.
pub fn read_curve_scalars_length<C: Curve>(
    cur: &mut Cursor<&[u8]>,
    len: usize,
) -> Result<Vec<C::Scalar>, Error> {
    let mut res = common::safe_with_capacity(len);
    for _ in 0..len {
        res.push(read_curve_scalar::<C>(cur)?);
    }
    Ok(res)
}

/// Read the length and a list of scalars of that length.
pub fn read_curve_scalars<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<Vec<C::Scalar>, Error> {
    let len = read_length(cur)?;
    read_curve_scalars_length::<C>(cur, len)
}

/// TODO:Unify.
pub fn read_pairing_scalars<P: Pairing>(
    cur: &mut Cursor<&[u8]>,
) -> Result<Vec<P::ScalarField>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = common::safe_with_capacity(len as usize);
    for _ in 0..len {
        res.push(P::bytes_to_scalar(cur)?);
    }
    Ok(res)
}

/// TODO:Unify.
pub fn read_pairing_scalar<P: Pairing>(cur: &mut Cursor<&[u8]>) -> Result<P::ScalarField, Error> {
    let res = P::bytes_to_scalar(cur)?;
    Ok(res)
}

pub fn read_curve_elements<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<Vec<C>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = common::safe_with_capacity(len as usize);
    for _ in 0..len {
        res.push(read_curve::<C>(cur)?);
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

/// Write the length of the slice as a 32-bit big-endian unsigned integer.
/// The precondition of this method is that the length fits into such a value.
/// If this is not the case the behaviour of this method is unspecified.
pub fn write_length<A>(elems: &[A], out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
}

/// Write out the scalars in sequence without outputting length.
pub fn write_curve_scalars_no_length<C: Curve>(elems: &[C::Scalar], out: &mut Vec<u8>) {
    for elem in elems.iter() {
        out.extend_from_slice(&C::scalar_to_bytes(elem));
    }
}

pub fn write_curve_scalars<C: Curve>(elems: &[C::Scalar], out: &mut Vec<u8>) {
    write_length(elems, out);
    write_curve_scalars_no_length::<C>(elems, out);
}

pub fn write_pairing_scalar<C: Pairing>(elem: &C::ScalarField, out: &mut Vec<u8>) {
    out.extend_from_slice(&C::scalar_to_bytes(elem));
}

pub fn write_pairing_scalars<P: Pairing>(elems: &[P::ScalarField], out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
    for elem in elems.iter() {
        out.extend_from_slice(&P::scalar_to_bytes(elem));
    }
}
