use failure::Error;
use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};
use curve_arithmetic::curve_arithmetic::Pairing;

pub fn read_exact_bytes<'a>(cur: &mut Cursor<&[u8]>, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
    cur.read_exact(buf)?;
    Ok(buf)
}

pub fn write_elems<A, F: Fn(&A) -> Box<[u8]>>(elems: &[A], ser: &F, out: &mut Vec<u8>) {
    let elems_len = elems.len() as u32;
    out.extend_from_slice(&elems_len.to_be_bytes());
    for elem in elems.iter() {
        out.extend_from_slice(&ser(elem));
    }
}

pub fn write_elem<A, F: Fn(&A) -> Box<[u8]>>(elem: &A, ser: &F, out: &mut Vec<u8>) {
    out.extend_from_slice(&ser(elem));
}

pub fn write_pairing_scalars<C: Pairing>(elems: &[C::ScalarField], out: &mut Vec<u8>) {
    write_elems(elems, &C::scalar_to_bytes, out)
}

pub fn write_pairing_scalar<C: Pairing>(elem: &C::ScalarField, out: &mut Vec<u8>) {
    out.extend_from_slice(&C::scalar_to_bytes(elem));
}

pub fn read_elems<A, F: Fn(&[u8]) -> Result<A, Error>>(
    des: &F,
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<Vec<A>, Error> {
    let len = cur.read_u32::<BigEndian>()?;
    let mut res = Vec::with_capacity(len as usize);
    for _ in 0..len {
        res.push(read_elem::<A, F>(des, cur, buf)?);
    }
    Ok(res)
}

pub fn read_elem<A, F: Fn(&[u8]) -> Result<A, Error>>(
    des: &F,
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<A, Error> {
    let s = des(read_exact_bytes(cur, buf)?)?;
    Ok(s)
}

pub fn read_pairing_scalar<C: Pairing>(
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<C::ScalarField, Error> {
    let f: for<'r> fn(&'r [u8]) -> Result<C::ScalarField, Error> = |x| {
        let r = C::bytes_to_scalar(x)?;
        Ok(r)
    };
    read_elem(&f, cur, buf)
}

pub fn read_pairing_scalars<C: Pairing>(
    cur: &mut Cursor<&[u8]>,
    buf: &mut [u8],
) -> Result<Vec<C::ScalarField>, Error> {
    let f: for<'r> fn(&'r [u8]) -> Result<C::ScalarField, Error> = |x| {
        let r = C::bytes_to_scalar(x)?;
        Ok(r)
    };
    read_elems(&f, cur, buf)
}
