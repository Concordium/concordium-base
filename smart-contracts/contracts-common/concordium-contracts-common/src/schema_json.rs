use crate::{constants::*, schema::*, *};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use serde_json::Value;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, thiserror::Error, Clone)]
pub enum JsonError {
    #[error("Failed writing")]
    FailedWriting,
    #[error("Unsigned integer required")]
    UnsignedIntRequired,
    #[error("Signed integer required")]
    SignedIntRequired,
    #[error("Failed parsing account address")]
    FailedParsingAccountAddress,
    #[error("{0}")]
    WrongJsonType(String),
    #[error("{0}")]
    FieldError(String),
    #[error("{0}")]
    EnumError(String),
    #[error("{0}")]
    MapError(String),
    #[error("{0}")]
    PairError(String),
    #[error("{0}")]
    ArrayError(String),
    #[error("{0}")]
    ParseError(String),
    #[error("{0}")]
    ByteArrayError(String),
    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("{0}")]
    TryFromIntError(#[from] core::num::TryFromIntError),
    #[error("{0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("{0}")]
    ParseDurationError(#[from] ParseDurationError),
    #[error("{0}")]
    ParseTimestampError(#[from] ParseTimestampError),
}

// Serializes a value to the provided output buffer
macro_rules! serial {
    ($value:ident, $out:ident) => {
        $value.serial($out).or(Err(JsonError::FailedWriting))
    };
}

// Either the given condition holds otherwise the provided error and
// accompanying message is returned
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

/// Uses the schema to parse JSON into bytes
/// It is assumed the array of values for Map and Set are already ordered.
fn write_bytes_from_json_schema_type<W: Write>(
    schema: &Type,
    json: &serde_json::Value,
    out: &mut W,
) -> Result<(), JsonError> {
    use JsonError::*;

    match schema {
        Type::Unit => Ok(()),
        Type::Bool => {
            if let Value::Bool(b) = json {
                serial!(b, out)
            } else {
                Err(WrongJsonType("JSON boolean required".to_string()))
            }
        }
        Type::U8 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u8 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::U16 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u16 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::U32 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u32 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::U64 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I8 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i8 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I16 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i16 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I32 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i32 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I64 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::Amount => {
            if let Value::String(string) = json {
                let amount: u64 = string.parse()?;
                serial!(amount, out)
            } else {
                Err(WrongJsonType("JSON string required".to_string()))
            }
        }
        Type::AccountAddress => {
            if let Value::String(string) = json {
                let account: AccountAddress =
                    string.parse().or(Err(JsonError::FailedParsingAccountAddress))?;
                serial!(account, out)
            } else {
                Err(WrongJsonType("JSON string required".to_string()))
            }
        }
        Type::ContractAddress => {
            if let Value::Object(fields) = json {
                ensure!(
                    fields.len() <= 2,
                    FieldError("Only index and optionally subindex are allowed".to_string())
                );

                let index = fields
                    .get("index")
                    .and_then(|v| match v {
                        Value::Number(n) => n.as_u64(),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        FieldError("'index' is required in a Contract address".to_string())
                    })?;
                let subindex = fields
                    .get("subindex")
                    .and_then(|v| match v {
                        Value::Number(n) => n.as_u64(),
                        _ => None,
                    })
                    .unwrap_or(0);
                let contract = ContractAddress {
                    index,
                    subindex,
                };
                serial!(contract, out)
            } else {
                Err(WrongJsonType("JSON Object with 'index' field required".to_string()))
            }
        }
        Type::Timestamp => {
            if let Value::String(string) = json {
                let timestamp: Timestamp = string.parse()?;
                serial!(timestamp, out)
            } else {
                Err(WrongJsonType("JSON String required for timestamp".to_string()))
            }
        }
        Type::Duration => {
            if let Value::String(string) = json {
                let duration: Duration = string.parse()?;
                serial!(duration, out)
            } else {
                Err(WrongJsonType("JSON String required for duration".to_string()))
            }
        }
        Type::Pair(left_type, right_type) => {
            if let Value::Array(values) = json {
                ensure!(
                    values.len() == 2,
                    PairError("Only pairs of two are supported".to_string())
                );
                write_bytes_from_json_schema_type(left_type, &values[0], out)?;
                write_bytes_from_json_schema_type(right_type, &values[1], out)
            } else {
                Err(WrongJsonType("JSON Array required for a pair".to_string()))
            }
        }
        Type::List(size_len, ty) => {
            if let Value::Array(values) = json {
                let len = values.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Array required".to_string()))
            }
        }
        Type::Set(size_len, ty) => {
            if let Value::Array(values) = json {
                let len = values.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Array required".to_string()))
            }
        }
        Type::Map(size_len, key_ty, val_ty) => {
            if let Value::Array(entries) = json {
                let len = entries.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for entry in entries {
                    if let Value::Array(pair) = entry {
                        ensure!(pair.len() == 2, MapError("Expected key-value pair".to_string()));
                        write_bytes_from_json_schema_type(key_ty, &pair[0], out)?;
                        write_bytes_from_json_schema_type(val_ty, &pair[1], out)?;
                    } else {
                        return Err(WrongJsonType(
                            "Expected key value pairs as JSON arrays".to_string(),
                        ));
                    }
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Array required".to_string()))
            }
        }
        Type::Array(len, ty) => {
            if let Value::Array(values) = json {
                ensure!(
                    (values.len() as u32) == *len,
                    ArrayError(format!(
                        "Expected array with {} elements, but it had {} elements",
                        len,
                        values.len()
                    ))
                );
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Array required".to_string()))
            }
        }
        Type::Struct(fields_ty) => write_bytes_from_json_schema_fields(fields_ty, json, out),
        Type::Enum(variants_ty) => {
            if let Value::Object(map) = json {
                ensure!(map.len() == 1, EnumError("Only one variant allowed".to_string()));
                let (variant_name, fields_value) = map.iter().next().unwrap(); // Safe since we already checked the length
                let schema_fields_opt = variants_ty
                    .iter()
                    .enumerate()
                    .find(|(_, (variant_name_schema, _))| variant_name_schema == variant_name);
                if let Some((i, (_, variant_fields))) = schema_fields_opt {
                    if variants_ty.len() <= 256 {
                        out.write_u8(i as u8).or(Err(JsonError::FailedWriting))?;
                    } else if variants_ty.len() <= 256 * 256 {
                        out.write_u16(i as u16).or(Err(JsonError::FailedWriting))?;
                    } else {
                        return Err(EnumError(
                            "Enums with more than 65536 variants are not supported.".to_string(),
                        ));
                    };
                    write_bytes_from_json_schema_fields(variant_fields, fields_value, out)
                } else {
                    // Non-existing variant
                    Err(EnumError(format!("Unknown variant: {}", variant_name)))
                }
            } else {
                Err(WrongJsonType("JSON Object with one field required for an Enum".to_string()))
            }
        }
        Type::TaggedEnum(variants_ty) => {
            if let Value::Object(fields) = json {
                ensure!(fields.len() == 1, EnumError("Only one variant allowed.".to_string()));
                let (variant_name, fields_value) = fields.iter().next().unwrap(); // Safe since we already checked the length
                let schema_fields_opt = variants_ty
                    .iter()
                    .find(|(_, (variant_name_schema, _))| variant_name_schema == variant_name);
                if let Some((&i, (_, variant_fields))) = schema_fields_opt {
                    out.write_u8(i).or(Err(JsonError::FailedWriting))?;
                    write_bytes_from_json_schema_fields(variant_fields, fields_value, out)
                } else {
                    // Non-existing variant
                    Err(EnumError(format!("Unknown variant: {}", variant_name)))
                }
            } else {
                Err(WrongJsonType("JSON Object required for an EnumTag".to_string()))
            }
        }
        Type::String(size_len) => {
            if let Value::String(string) = json {
                let len = string.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                serial_vector_no_length(string.as_bytes(), out).or(Err(JsonError::FailedWriting))
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::ContractName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields.get("contract").ok_or_else(|| {
                    FieldError("Missing field 'contract' of type JSON String.".to_string())
                })?;
                ensure!(
                    fields.len() == 1,
                    FieldError(format!(
                        "Expected only one field but {} were provided.",
                        fields.len()
                    ))
                );
                if let Value::String(name) = contract {
                    let contract_name = format!("init_{}", name);
                    let len = contract_name.len();
                    write_bytes_for_length_of_size(len, size_len, out)?;
                    serial_vector_no_length(contract_name.as_bytes(), out)
                        .or(Err(JsonError::FailedWriting))
                } else {
                    Err(WrongJsonType("JSON String required for field 'contract'.".to_string()))
                }
            } else {
                Err(WrongJsonType("JSON Object required for contract name.".to_string()))
            }
        }
        Type::ReceiveName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields.get("contract").ok_or_else(|| {
                    FieldError("Missing field 'contract' of type JSON String.".to_string())
                })?;
                let func = fields.get("func").ok_or_else(|| {
                    WrongJsonType("Missing field 'func' of type JSON String.".to_string())
                })?;
                ensure!(
                    fields.len() == 2,
                    FieldError(format!(
                        "Expected exactly two fields but {} were provided.",
                        fields.len()
                    ))
                );
                if let Value::String(contract) = contract {
                    if let Value::String(func) = func {
                        let receive_name = format!("{}.{}", contract, func);
                        let len = receive_name.len();
                        write_bytes_for_length_of_size(len, size_len, out)?;
                        serial_vector_no_length(receive_name.as_bytes(), out)
                            .or(Err(JsonError::FailedWriting))
                    } else {
                        Err(WrongJsonType("JSON String required for field 'func'.".to_string()))
                    }
                } else {
                    Err(WrongJsonType("JSON String required for field 'contract'.".to_string()))
                }
            } else {
                Err(WrongJsonType("JSON Object required for contract name.".to_string()))
            }
        }
        Type::U128 => {
            if let Value::String(string) = json {
                let n: u128 = string
                    .parse()
                    .map_err(|_| ParseError("Could not parse as u128.".to_string()))?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::I128 => {
            if let Value::String(string) = json {
                let n: i128 = string
                    .parse()
                    .map_err(|_| ParseError("Could not parse as i128.".to_string()))?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::ULeb128(constraint) => {
            if let Value::String(string) = json {
                let biguint = string
                    .parse()
                    .map_err(|_| ParseError("Could not parse integer.".to_string()))?;
                serial_biguint(biguint, *constraint, out).or(Err(JsonError::FailedWriting))
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::ILeb128(constraint) => {
            if let Value::String(string) = json {
                let bigint = string
                    .parse()
                    .map_err(|_| ParseError("Could not parse integer.".to_string()))?;
                serial_bigint(bigint, *constraint, out).or(Err(JsonError::FailedWriting))
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::ByteList(size_len) => {
            if let Value::String(string) = json {
                let bytes = hex::decode(string)?;
                let len = bytes.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for value in bytes {
                    serial!(value, out)?
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
        Type::ByteArray(len) => {
            if let Value::String(string) = json {
                let bytes = hex::decode(string)?;
                ensure!(
                    *len == bytes.len() as u32,
                    ByteArrayError("Mismatching number of bytes".to_string())
                );
                for value in bytes {
                    serial!(value, out)?;
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON String required".to_string()))
            }
        }
    }
}

impl Type {
    /// Serialize the given JSON value into the binary format represented by the
    /// schema. If the JSON value does not match the schema an error will be
    /// returned.
    pub fn serial_value(&self, json: &serde_json::Value) -> Result<Vec<u8>, JsonError> {
        let mut out = Vec::new();
        self.serial_value_into(json, &mut out)?;
        Ok(out)
    }

    /// Serialize the given JSON value into the binary format represented by the
    /// schema. The resulting byte array is written into the provided sink.
    /// If the JSON value does not match the schema an error will be returned.
    pub fn serial_value_into(
        &self,
        json: &serde_json::Value,
        out: &mut impl Write,
    ) -> Result<(), JsonError> {
        write_bytes_from_json_schema_type(self, json, out)
    }

    /// Uses the schema to parse JSON into bytes
    /// It is assumed the array of values for Map and Set are already ordered.
    #[deprecated(
        since = "5.2.0",
        note = "Use the more ergonomic [`serial_value_into`](Self::serial_value_into) instead."
    )]
    pub fn write_bytes_from_json_schema_type<W: Write>(
        schema: &Type,
        json: &serde_json::Value,
        out: &mut W,
    ) -> Result<(), JsonError> {
        write_bytes_from_json_schema_type(schema, json, out)
    }
}

fn serial_biguint<W: Write>(bigint: BigUint, constraint: u32, out: &mut W) -> Result<(), W::Err> {
    let mut value = bigint;
    for _ in 0..constraint {
        // Read the first byte of the value
        let mut byte = value.iter_u32_digits().next().unwrap_or(0) as u8;
        byte &= 0b0111_1111;
        value >>= 7;
        if !value.is_zero() {
            byte |= 0b1000_0000;
        }
        out.write_u8(byte)?;

        if value.is_zero() {
            return Ok(());
        }
    }
    Err(W::Err::default())
}

fn serial_bigint<W: Write>(bigint: BigInt, constraint: u32, out: &mut W) -> Result<(), W::Err> {
    let mut value = bigint;
    for _ in 0..constraint {
        // Read the first byte of the value
        // FIXME: This will allocate a vector where we only need the first byte and can
        // hopefully be improved.
        let mut byte = value.to_signed_bytes_le()[0] & 0b0111_1111;
        value >>= 7;

        if (value.is_zero() && (byte & 0b0100_0000) == 0)
            || (value == BigInt::from(-1) && (byte & 0b0100_0000) != 0)
        {
            out.write_u8(byte)?;
            return Ok(());
        }

        byte |= 0b1000_0000;
        out.write_u8(byte)?;
    }
    Err(W::Err::default())
}

fn write_bytes_from_json_schema_fields<W: Write>(
    fields: &Fields,
    json: &serde_json::Value,
    out: &mut W,
) -> Result<(), JsonError> {
    use JsonError::*;

    match fields {
        Fields::Named(fields) => {
            if let Value::Object(map) = json {
                ensure!(
                    fields.len() >= map.len(),
                    FieldError("Too many fields provided".to_string())
                );
                for (field_name, field_ty) in fields {
                    let field_value_opt = map.get(field_name);
                    if let Some(field_value) = field_value_opt {
                        write_bytes_from_json_schema_type(field_ty, field_value, out)?;
                    } else {
                        return Err(FieldError(format!("Missing field: {}", field_name)));
                    }
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Object required for named fields".to_string()))
            }
        }
        Fields::Unnamed(fields) => {
            if let Value::Array(values) = json {
                ensure!(
                    fields.len() == values.len(),
                    FieldError(format!("Expected {} unnamed fields", fields.len()))
                );
                for (field_ty, value) in fields.iter().zip(values.iter()) {
                    write_bytes_from_json_schema_type(field_ty, value, out)?;
                }
                Ok(())
            } else {
                Err(WrongJsonType("JSON Array required for unnamed fields".to_string()))
            }
        }
        Fields::None => Ok(()),
    }
}

/// Serializes the length using the number of bytes specified by the size_len.
/// Returns an error if the length cannot be represented by the number of bytes.
fn write_bytes_for_length_of_size<W: Write>(
    len: usize,
    size_len: &SizeLength,
    out: &mut W,
) -> Result<(), JsonError> {
    match size_len {
        SizeLength::U8 => {
            let len: u8 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U16 => {
            let len: u16 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U32 => {
            let len: u32 = len.try_into()?;
            serial!(len, out)
        }
        SizeLength::U64 => {
            let len: u64 = len.try_into()?;
            serial!(len, out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_biguint_0() {
        let mut bytes = Vec::new();
        serial_biguint(0u8.into(), 1, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([0]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_biguint_10() {
        let mut bytes = Vec::new();
        serial_biguint(10u8.into(), 1, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([10]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_biguint_129() {
        let mut bytes = Vec::new();
        serial_biguint(129u8.into(), 2, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([129, 1]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_biguint_u64_max() {
        let mut bytes = Vec::new();
        serial_biguint(u64::MAX.into(), 10, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([255, 255, 255, 255, 255, 255, 255, 255, 255, 1]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_biguint_u256_max() {
        let u256_max = BigUint::from_bytes_le(&[
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        let mut bytes = Vec::new();
        serial_biguint(u256_max, 37, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            0b0000_1111,
        ]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_biguint_contraint_fails() {
        let mut bytes = Vec::new();
        serial_biguint(129u8.into(), 1, &mut bytes).expect_err("Serialization should have failed");
    }

    #[test]
    fn test_serial_bigint_0() {
        let mut bytes = Vec::new();
        serial_bigint(0.into(), 1, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([0]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_bigint_10() {
        let mut bytes = Vec::new();
        serial_bigint(10.into(), 1, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([10]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_bigint_neg_10() {
        let mut bytes = Vec::new();
        serial_bigint((-10).into(), 1, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([0b0111_0110]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_bigint_neg_129() {
        let mut bytes = Vec::new();
        serial_bigint((-129).into(), 2, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([0b1111_1111, 0b0111_1110]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_bigint_i64_min() {
        let mut bytes = Vec::new();
        serial_bigint(i64::MIN.into(), 10, &mut bytes).expect("Serializing failed");
        let expected = Vec::from([128, 128, 128, 128, 128, 128, 128, 128, 128, 0b0111_1111]);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_bigint_constraint_fails() {
        let mut bytes = Vec::new();
        serial_bigint(i64::MIN.into(), 2, &mut bytes).expect_err("Deserialising should fail");
    }

    #[test]
    fn test_deserial_biguint_0() {
        let mut cursor = Cursor::new([0]);
        let int = deserial_biguint(&mut cursor, 1).expect("Deserialising should not fail");
        assert_eq!(int, 0u8.into())
    }

    #[test]
    fn test_deserial_biguint_10() {
        let mut cursor = Cursor::new([10]);
        let int = deserial_biguint(&mut cursor, 1).expect("Deserialising should not fail");
        assert_eq!(int, 10u8.into())
    }

    #[test]
    fn test_deserial_biguint_129() {
        let mut cursor = Cursor::new([129, 1]);
        let int = deserial_biguint(&mut cursor, 2).expect("Deserialising should not fail");
        assert_eq!(int, 129u8.into())
    }

    #[test]
    fn test_deserial_biguint_u64_max() {
        let mut cursor = Cursor::new([255, 255, 255, 255, 255, 255, 255, 255, 255, 1]);
        let int = deserial_biguint(&mut cursor, 10).expect("Deserialising should not fail");
        assert_eq!(int, u64::MAX.into())
    }

    #[test]
    fn test_deserial_biguint_u256_max() {
        let mut cursor = Cursor::new([
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            255,
            0b0000_1111,
        ]);
        let int = deserial_biguint(&mut cursor, 37).expect("Deserialising should not fail");
        let u256_max = BigUint::from_bytes_le(&[
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        assert_eq!(int, u256_max)
    }

    #[test]
    fn test_deserial_biguint_padding_allowed() {
        let mut cursor = Cursor::new([129, 128, 128, 128, 128, 0]);
        let int = deserial_biguint(&mut cursor, 6).expect("Deserialising should not fail");
        assert_eq!(int, 1u8.into())
    }

    #[test]
    fn test_deserial_biguint_contraint_fails() {
        let mut cursor = Cursor::new([129, 1]);
        deserial_biguint(&mut cursor, 1).expect_err("Deserialising should fail");
    }

    #[test]
    fn test_deserial_bigint_0() {
        let mut cursor = Cursor::new([0]);
        let int = deserial_bigint(&mut cursor, 1).expect("Deserialising should not fail");
        assert_eq!(int, 0u8.into())
    }

    #[test]
    fn test_deserial_bigint_10() {
        let mut cursor = Cursor::new([10]);
        let int = deserial_bigint(&mut cursor, 1).expect("Deserialising should not fail");
        assert_eq!(int, 10u8.into())
    }

    #[test]
    fn test_deserial_bigint_neg_10() {
        let mut cursor = Cursor::new([0b0111_0110]);
        let int = deserial_bigint(&mut cursor, 2).expect("Deserialising should not fail");
        assert_eq!(int, (-10).into())
    }

    #[test]
    fn test_deserial_bigint_neg_129() {
        let mut cursor = Cursor::new([0b1111_1111, 0b0111_1110]);
        let int = deserial_bigint(&mut cursor, 3).expect("Deserialising should not fail");
        assert_eq!(int, (-129).into())
    }

    #[test]
    fn test_deserial_bigint_i64_min() {
        let mut cursor = Cursor::new([128, 128, 128, 128, 128, 128, 128, 128, 128, 0b0111_1111]);
        let int = deserial_bigint(&mut cursor, 10).expect("Deserialising should not fail");
        assert_eq!(int, BigInt::from(i64::MIN))
    }

    #[test]
    fn test_deserial_bigint_constraint_fails() {
        let mut cursor = Cursor::new([128, 128, 128, 128, 128, 128, 128, 128, 128, 0b0111_1111]);
        deserial_bigint(&mut cursor, 9).expect_err("Deserialising should fail");
    }
}

impl Fields {
    pub fn to_json<R: Read>(&self, source: &mut R) -> ParseResult<serde_json::Value> {
        use serde_json::*;

        match self {
            Fields::Named(fields) => {
                let mut values = map::Map::new();
                for (key, ty) in fields.iter() {
                    let value = ty.to_json(source)?;
                    values.insert(key.to_string(), value);
                }
                Ok(Value::Object(values))
            }
            Fields::Unnamed(fields) => {
                let mut values = Vec::new();
                for ty in fields.iter() {
                    values.push(ty.to_json(source)?);
                }
                Ok(Value::Array(values))
            }
            Fields::None => Ok(Value::Array(vec![])),
        }
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(_: std::string::FromUtf8Error) -> Self { ParseError::default() }
}

fn item_list_to_json<R: Read>(
    source: &mut R,
    size_len: SizeLength,
    item_to_json: impl Fn(&mut R) -> ParseResult<serde_json::Value>,
) -> ParseResult<Vec<serde_json::Value>> {
    let len = deserial_length(source, size_len)?;
    let mut values = Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));
    for _ in 0..len {
        let value = item_to_json(source)?;
        values.push(value);
    }
    Ok(values)
}

fn deserial_string<R: Read>(source: &mut R, size_len: SizeLength) -> ParseResult<String> {
    let len = deserial_length(source, size_len)?;
    // we are doing this case analysis so that we have a fast path for safe,
    // most common, lengths, and a slower one longer ones.
    if len <= MAX_PREALLOCATED_CAPACITY {
        let mut bytes = vec![0u8; len];
        source.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    } else {
        let mut bytes: Vec<u8> = Vec::with_capacity(MAX_PREALLOCATED_CAPACITY);
        let mut buf = [0u8; 64];
        let mut read = 0;
        while read < len {
            let new = source.read(&mut buf)?;
            if new == 0 {
                break;
            } else {
                read += new;
                bytes.extend_from_slice(&buf[..new]);
            }
        }
        if read == len {
            Ok(String::from_utf8(bytes)?)
        } else {
            Err(ParseError {})
        }
    }
}

impl Type {
    /// Uses the schema to deserialize bytes into pretty json
    pub fn to_json_string_pretty(&self, bytes: &[u8]) -> ParseResult<String> {
        let source = &mut Cursor::new(bytes);
        let js = self.to_json(source)?;
        serde_json::to_string_pretty(&js).map_err(|_| ParseError::default())
    }

    /// Uses the schema to deserialize bytes into json
    pub fn to_json<R: Read>(&self, source: &mut R) -> ParseResult<serde_json::Value> {
        use serde_json::*;

        match self {
            Type::Unit => Ok(Value::Null),
            Type::Bool => {
                let n = bool::deserial(source)?;
                Ok(Value::Bool(n))
            }
            Type::U8 => {
                let n = u8::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U16 => {
                let n = u16::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U32 => {
                let n = u32::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U64 => {
                let n = u64::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U128 => {
                let n = u128::deserial(source)?;
                Ok(Value::String(n.to_string()))
            }
            Type::I8 => {
                let n = i8::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I16 => {
                let n = i16::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I32 => {
                let n = i32::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I64 => {
                let n = i64::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I128 => {
                let n = i128::deserial(source)?;
                Ok(Value::String(n.to_string()))
            }
            Type::Amount => {
                let n = Amount::deserial(source)?;
                Ok(Value::String(n.micro_ccd().to_string()))
            }
            Type::AccountAddress => {
                let address = AccountAddress::deserial(source)?;
                Ok(Value::String(address.to_string()))
            }
            Type::ContractAddress => {
                let address = ContractAddress::deserial(source)?;
                Ok(serde_json::to_value(address).map_err(|_| ParseError {})?)
            }
            Type::Timestamp => {
                let timestamp = Timestamp::deserial(source)?;
                Ok(Value::String(timestamp.to_string()))
            }
            Type::Duration => {
                let duration = Duration::deserial(source)?;
                Ok(Value::String(duration.to_string()))
            }
            Type::Pair(left_type, right_type) => {
                let left = left_type.to_json(source)?;
                let right = right_type.to_json(source)?;
                Ok(Value::Array(vec![left, right]))
            }
            Type::List(size_len, ty) => {
                let values = item_list_to_json(source, *size_len, |s| ty.to_json(s))?;
                Ok(Value::Array(values))
            }
            Type::Set(size_len, ty) => {
                let values = item_list_to_json(source, *size_len, |s| ty.to_json(s))?;
                Ok(Value::Array(values))
            }
            Type::Map(size_len, key_type, value_type) => {
                let values = item_list_to_json(source, *size_len, |s| {
                    let key = key_type.to_json(s)?;
                    let value = value_type.to_json(s)?;
                    Ok(Value::Array(vec![key, value]))
                })?;
                Ok(Value::Array(values))
            }
            Type::Array(len, ty) => {
                let len: usize = (*len).try_into()?;
                let mut values = Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));
                for _ in 0..len {
                    let value = ty.to_json(source)?;
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            Type::Struct(fields_ty) => {
                let fields = fields_ty.to_json(source)?;
                Ok(fields)
            }
            Type::Enum(variants) => {
                let idx = if variants.len() <= 256 {
                    u8::deserial(source)? as usize
                } else {
                    u16::deserial(source)? as usize
                };
                let (name, fields_ty) = variants.get(idx).ok_or_else(ParseError::default)?;
                let fields = fields_ty.to_json(source)?;
                Ok(json!({ name: fields }))
            }
            Type::TaggedEnum(variants) => {
                let idx = u8::deserial(source)?;

                let (name, fields_ty) = variants.get(&idx).ok_or_else(ParseError::default)?;
                let fields = fields_ty.to_json(source)?;
                Ok(json!({ name: fields }))
            }
            Type::String(size_len) => {
                let string = deserial_string(source, *size_len)?;
                Ok(Value::String(string))
            }
            Type::ContractName(size_len) => {
                let contract_name = OwnedContractName::new(deserial_string(source, *size_len)?)
                    .map_err(|_| ParseError::default())?;
                let name_without_init = contract_name.as_contract_name().contract_name();
                Ok(json!({ "contract": name_without_init }))
            }
            Type::ReceiveName(size_len) => {
                let owned_receive_name = OwnedReceiveName::new(deserial_string(source, *size_len)?)
                    .map_err(|_| ParseError::default())?;
                let receive_name = owned_receive_name.as_receive_name();
                let contract_name = receive_name.contract_name();
                let func_name = receive_name.entrypoint_name();
                Ok(json!({"contract": contract_name, "func": func_name}))
            }
            Type::ULeb128(constraint) => {
                let int = deserial_biguint(source, *constraint)?;
                Ok(Value::String(int.to_string()))
            }
            Type::ILeb128(constraint) => {
                let int = deserial_bigint(source, *constraint)?;
                Ok(Value::String(int.to_string()))
            }
            Type::ByteList(size_len) => {
                let len = deserial_length(source, *size_len)?;
                let mut string =
                    String::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, 2 * len));
                for _ in 0..len {
                    let byte = source.read_u8()?;
                    string.push_str(&format!("{:02x?}", byte));
                }
                Ok(Value::String(string))
            }
            Type::ByteArray(len) => {
                let len = usize::try_from(*len)?;
                let mut string =
                    String::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, 2 * len));
                for _ in 0..len {
                    let byte = source.read_u8()?;
                    string.push_str(&format!("{:02x?}", byte));
                }
                Ok(Value::String(string))
            }
        }
    }
}

fn deserial_biguint<R: Read>(source: &mut R, constraint: u32) -> ParseResult<BigUint> {
    let mut result = BigUint::zero();
    let mut shift = 0;
    for _ in 0..constraint {
        let byte = source.read_u8()?;
        let value_byte = BigUint::from(byte & 0b0111_1111);
        result += value_byte << shift;
        shift += 7;

        if byte & 0b1000_0000 == 0 {
            return Ok(result);
        }
    }
    Err(ParseError {})
}

fn deserial_bigint<R: Read>(source: &mut R, constraint: u32) -> ParseResult<BigInt> {
    let mut result = BigInt::zero();
    let mut shift = 0;
    for _ in 0..constraint {
        let byte = source.read_u8()?;
        let value_byte = BigInt::from(byte & 0b0111_1111);
        result += value_byte << shift;
        shift += 7;

        if byte & 0b1000_0000 == 0 {
            if byte & 0b0100_0000 != 0 {
                result -= BigInt::from(2).pow(shift)
            }
            return Ok(result);
        }
    }
    Err(ParseError {})
}
