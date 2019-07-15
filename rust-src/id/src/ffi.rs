use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use pairing::bls12_381::G1;
use std::io::{Cursor, Read};

#[derive(Copy, Clone)]
pub enum AttributeKind {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl AttributeKind {
    pub fn size_of(&self) -> usize {
        match self {
            AttributeKind::U8(_) => 1,
            AttributeKind::U16(_) => 2,
            AttributeKind::U32(_) => 4,
            AttributeKind::U64(_) => 8,
        }
    }

    fn to_u64(&self) -> u64 {
        match self {
            AttributeKind::U8(x) => (*x as u64),
            AttributeKind::U16(x) => (*x as u64),
            AttributeKind::U32(x) => (*x as u64),
            AttributeKind::U64(x) => (*x as u64),
        }
    }
}

impl Attribute<<G1 as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <G1 as Curve>::Scalar {
        <G1 as Curve>::scalar_from_u64(self.to_u64()).unwrap()
    }

    fn to_bytes(&self) -> Box<[u8]> {
        match self {
            AttributeKind::U8(_) => {
                let mut buff = [0u8; 2];
                buff.copy_from_slice(&(1 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U16(_) => {
                let mut buff = [0u8; 3];
                buff.copy_from_slice(&(2 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U32(_) => {
                let mut buff = [0u8; 5];
                buff.copy_from_slice(&(4 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U64(_) => {
                let mut buff = [0u8; 9];
                buff.copy_from_slice(&(8 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
        }
    }

    fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let bytes = cur.get_ref();
        let size = bytes[0];
        match size {
            1 => {
                let mut buf = [0u8; 1];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U8(u8::from_be_bytes(buf)))
            }
            2 => {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U16(u16::from_be_bytes(buf)))
            }
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U32(u32::from_be_bytes(buf)))
            }
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U64(u64::from_be_bytes(buf)))
            }
            _ => None,
        }
    }
}

/*
pub extern "C" fn verify_cdi(global_context_ptr: *const u8, ip_info_ptr: *const u8, cdi_ptr: *const u8) -> int32_t {
    if global_context_ptr.is_null() {
        return -3;
    }
    if ip_info_ptr.is_null(){
        return -4
    }
    if cdi_ptr.is_null(){
        return -5
    }

}

*/






