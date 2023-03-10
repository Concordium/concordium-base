use std::io::Cursor;

/// A simple function that serializes and then immediately deserializes a value.
/// This should always return Ok(v) where `v` is equivalent to the given
/// argument. Used for testing.
#[cfg(test)]
pub fn serialize_deserialize<A: super::Serialize>(x: &A) -> ParseResult<A> {
    let mut buf = Vec::<u8>::new();
    x.serial(&mut buf);
    A::deserial(&mut Cursor::new(buf))
}
