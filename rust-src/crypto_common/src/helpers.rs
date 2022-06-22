pub use crate::serialize::*;
use std::io::Cursor;

/// A simple function that serializes and then immediately deserializes a value.
/// This should always return Ok(v) where `v` is equivalent to the given
/// argument. Used for testing.
pub fn serialize_deserialize<A: Serialize>(x: &A) -> ParseResult<A> {
    let mut buf = Vec::<u8>::new();
    x.serial(&mut buf);
    A::deserial(&mut Cursor::new(buf))
}

/// Only used for its schemars::JsonSchema implementation.
pub struct HexSchema;

/// Regex that describes byte arrays in hex format. Allowing an even number of
/// 0-9, a-f characters.
pub const REGEX_HEX: &str = "^(([0-9]?[a-f]?){2})*$";

impl schemars::JsonSchema for HexSchema {
    fn schema_name() -> String { "HexString".into() }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::*;
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(
                StringValidation {
                    max_length: None,
                    min_length: Some(0),
                    pattern:    Some(REGEX_HEX.into()),
                }
                .into(),
            ),
            ..SchemaObject::default()
        })
    }
}
