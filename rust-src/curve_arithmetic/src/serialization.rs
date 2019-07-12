use failure::Error;
use std::io::Cursor;

use crate::curve_arithmetic::{Curve,Pairing};
use byteorder::{BigEndian, ReadBytesExt};

pub fn read_curve_scalar<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<C::Scalar, Error> {
    let s = C::bytes_to_scalar(cur)?;
    Ok(s)
}

pub fn read_curve<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<C, Error> {
    let s = C::bytes_to_curve(cur)?;
    Ok(s)
}

pub fn read_curve_scalars<C: Curve>(cur: &mut Cursor<&[u8]>) -> Result<Vec<C::Scalar>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        res.push(read_curve_scalar::<C>(cur)?);
    }
    Ok(res)
}

/// TODO:Unify.
pub fn read_pairing_scalars<P: Pairing>(cur: &mut Cursor<&[u8]>) -> Result<Vec<P::ScalarField>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = Vec::with_capacity(len as usize);
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
    let mut res = Vec::with_capacity(len as usize);
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

pub fn write_curve_scalars<C: Curve>(elems: &[C::Scalar], out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
    for elem in elems.iter() {
        out.extend_from_slice(&C::scalar_to_bytes(elem));
    }
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
