/// A simple function that serializes and then immediately deserializes a value.
/// This should always return Ok(v) where `v` is equivalent to the given
/// argument. Used for testing.
#[cfg(test)]
pub fn serialize_deserialize<A: super::Serialize>(x: &A) -> super::ParseResult<A> {
    use std::io::Cursor;
    let mut buf = Vec::<u8>::new();
    x.serial(&mut buf);
    A::deserial(&mut Cursor::new(buf))
}

/// RNG with fixed seed to generate the stability test cases
#[cfg(test)]
pub fn seed0() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0)
}
