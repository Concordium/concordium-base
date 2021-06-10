pub use crate::serialize::*;

use std::io::Cursor;

pub fn serialize_deserialize<A: Serialize>(x: &A) -> ParseResult<A> {
    let mut buf = Vec::<u8>::new();
    x.serial(&mut buf);
    A::deserial(&mut Cursor::new(buf))
}
