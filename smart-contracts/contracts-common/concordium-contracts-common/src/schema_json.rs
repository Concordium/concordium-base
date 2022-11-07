use crate::{schema::*, *};
//use anyhow::{anyhow, bail, ensure, Context};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use serde_json::Value;
use std::convert::TryInto;
use thiserror;

#[derive(Debug, thiserror::Error)]
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

macro_rules! serial {
    ($value:ident, $out:ident) => {
        $value.serial($out).or(Err(JsonError::FailedWriting))
    };
}

macro_rules! err {
    ($err:ident, $msg:expr) => {
        JsonError::$err($msg.to_string())
    };
}

macro_rules! wrong_json_type {
    ($msg:literal) => {
        Err(JsonError::WrongJsonType($msg.to_string()))
    };
}

macro_rules! ensure {
    ($err:ident, $cond:expr, $msg:expr) => {
        if !$cond {
            return Err(JsonError::$err($msg.to_string()));
        }
    };
}

/// Uses the schema to parse JSON into bytes
/// It is assumed the array of values for Map and Set are already ordered.
pub fn write_bytes_from_json_schema_type<W: Write>(
    schema: &Type,
    json: &serde_json::Value,
    out: &mut W,
) -> Result<(), JsonError> {
    match schema {
        Type::Unit => Ok(()),
        Type::Bool => {
            if let Value::Bool(b) = json {
                serial!(b, out)
            } else {
                wrong_json_type!("JSON bool required")
            }
        }
        Type::U8 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u8 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::U16 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u16 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::U32 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                let n: u32 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::U64 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::UnsignedIntRequired)?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::I8 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i8 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::I16 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i16 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::I32 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                let n: i32 = n.try_into()?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::I64 => {
            if let Value::Number(n) = json {
                let n = n.as_u64().ok_or(JsonError::SignedIntRequired)?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON number required")
            }
        }
        Type::Amount => {
            if let Value::String(string) = json {
                let amount: u64 = string.parse()?;
                serial!(amount, out)
            } else {
                wrong_json_type!("JSON string required")
            }
        }
        Type::AccountAddress => {
            if let Value::String(string) = json {
                let account: AccountAddress =
                    string.parse().or(Err(JsonError::FailedParsingAccountAddress))?;
                serial!(account, out)
            } else {
                wrong_json_type!("JSON string required")
            }
        }
        Type::ContractAddress => {
            if let Value::Object(fields) = json {
                ensure!(
                    FieldError,
                    fields.len() <= 2,
                    "Only index and optionally subindex are allowed"
                );

                let index = fields
                    .get("index")
                    .and_then(|v| match v {
                        Value::Number(n) => n.as_u64(),
                        _ => None,
                    })
                    .ok_or(err!(FieldError, "'index' is required in a Contract address"))?;
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
                wrong_json_type!("JSON Object with 'index' field required")
            }
        }
        Type::Timestamp => {
            if let Value::String(string) = json {
                let timestamp: Timestamp = string.parse()?;
                serial!(timestamp, out)
            } else {
                wrong_json_type!("JSON String required for timestamp")
            }
        }
        Type::Duration => {
            if let Value::String(string) = json {
                let duration: Duration = string.parse()?;
                serial!(duration, out)
            } else {
                wrong_json_type!("JSON String required for duration")
            }
        }
        Type::Pair(left_type, right_type) => {
            if let Value::Array(values) = json {
                ensure!(PairError, values.len() == 2, "Only pairs of two are supported");

                write_bytes_from_json_schema_type(left_type, &values[0], out)?;
                write_bytes_from_json_schema_type(right_type, &values[1], out)
            } else {
                wrong_json_type!("JSON Array required for a pair")
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
                wrong_json_type!("JSON Array required")
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
                wrong_json_type!("JSON Array required")
            }
        }
        Type::Map(size_len, key_ty, val_ty) => {
            if let Value::Array(entries) = json {
                let len = entries.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                for entry in entries {
                    if let Value::Array(pair) = entry {
                        ensure!(MapError, pair.len() == 2, "Expected key-value pair");
                        write_bytes_from_json_schema_type(key_ty, &pair[0], out)?;
                        write_bytes_from_json_schema_type(val_ty, &pair[1], out)?;
                    } else {
                        wrong_json_type!("Expected key value pairs as JSON arrays")?
                    }
                }
                Ok(())
            } else {
                wrong_json_type!("JSON Array required")
            }
        }
        Type::Array(len, ty) => {
            if let Value::Array(values) = json {
                ensure!(
                    ArrayError,
                    (values.len() as u32) == *len,
                    format!(
                        "Expected array with {} elements, but it had {} elements",
                        len,
                        values.len()
                    )
                );
                for value in values {
                    write_bytes_from_json_schema_type(ty, value, out)?;
                }
                Ok(())
            } else {
                wrong_json_type!("JSON Array required")
            }
        }
        Type::Struct(fields_ty) => write_bytes_from_json_schema_fields(fields_ty, json, out),
        Type::Enum(variants_ty) => {
            if let Value::Object(map) = json {
                ensure!(EnumError, map.len() == 1, "Only one variant allowed");
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
                        return Err(err!(
                            EnumError,
                            "Enums with more than 65536 variants are not supported."
                        ));
                    };
                    write_bytes_from_json_schema_fields(variant_fields, fields_value, out)
                } else {
                    // Non-existing variant
                    Err(err!(EnumError, format!("Unknown variant: {}", variant_name)))
                }
            } else {
                wrong_json_type!("JSON Object with one field required for an Enum")
            }
        }
        Type::EnumTag(variants_ty) => {
            if let Value::Object(fields) = json {
                ensure!(EnumError, fields.len() == 1, "Only one variant allowed.");
                let (variant_name, fields_value) = fields.iter().next().unwrap(); // Safe since we already checked the length
                let schema_fields_opt = variants_ty
                    .iter()
                    .find(|(_, (variant_name_schema, _))| variant_name_schema == variant_name);
                if let Some((&i, (_, variant_fields))) = schema_fields_opt {
                    out.write_u8(i).or(Err(JsonError::FailedWriting))?;
                    write_bytes_from_json_schema_fields(variant_fields, fields_value, out)
                } else {
                    // Non-existing variant
                    Err(err!(EnumError, format!("Unknown variant: {}", variant_name)))
                }
            } else {
                wrong_json_type!("JSON Object required for an EnumTag")
            }
        }
        Type::String(size_len) => {
            if let Value::String(string) = json {
                let len = string.len();
                write_bytes_for_length_of_size(len, size_len, out)?;
                serial_vector_no_length(string.as_bytes(), out).or(Err(JsonError::FailedWriting))
            } else {
                wrong_json_type!("JSON String required")
            }
        }
        Type::ContractName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields
                    .get("contract")
                    .ok_or(err!(FieldError, "Missing field 'contract' of type JSON String."))?;
                ensure!(
                    FieldError,
                    fields.len() == 1,
                    format!("Expected only one field but {} were provided.", fields.len())
                );
                if let Value::String(name) = contract {
                    let contract_name = format!("init_{}", name);
                    let len = contract_name.len();
                    write_bytes_for_length_of_size(len, size_len, out)?;
                    serial_vector_no_length(contract_name.as_bytes(), out)
                        .or(Err(JsonError::FailedWriting))
                } else {
                    wrong_json_type!("JSON String required for field 'contract'.")
                }
            } else {
                wrong_json_type!("JSON Object required for contract name.")
            }
        }
        Type::ReceiveName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields
                    .get("contract")
                    .ok_or(err!(FieldError, "Missing field 'contract' of type JSON String."))?;
                let func = fields
                    .get("func")
                    .ok_or(err!(WrongJsonType, "Missing field 'func' of type JSON String."))?;
                ensure!(
                    FieldError,
                    fields.len() == 2,
                    format!("Expected exactly two fields but {} were provided.", fields.len())
                );
                if let Value::String(contract) = contract {
                    if let Value::String(func) = func {
                        let receive_name = format!("{}.{}", contract, func);
                        let len = receive_name.len();
                        write_bytes_for_length_of_size(len, size_len, out)?;
                        serial_vector_no_length(receive_name.as_bytes(), out)
                            .or(Err(JsonError::FailedWriting))
                    } else {
                        wrong_json_type!("JSON String required for field 'func'.")
                    }
                } else {
                    wrong_json_type!("JSON String required for field 'contract'.")
                }
            } else {
                wrong_json_type!("JSON Object required for contract name.")
            }
        }
        Type::U128 => {
            if let Value::String(string) = json {
                let n: u128 =
                    string.parse().or(Err(err!(ParseError, "Could not parse as u128.")))?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON String required")
            }
        }
        Type::I128 => {
            if let Value::String(string) = json {
                let n: i128 =
                    string.parse().or(Err(err!(ParseError, "Could not parse as i128.")))?;
                serial!(n, out)
            } else {
                wrong_json_type!("JSON String required")
            }
        }
        Type::ULeb128(constraint) => {
            if let Value::String(string) = json {
                let biguint =
                    string.parse().or(Err(err!(ParseError, "Could not parse integer.")))?;
                serial_biguint(biguint, *constraint, out).or(Err(JsonError::FailedWriting))
            } else {
                wrong_json_type!("JSON String required")
            }
        }
        Type::ILeb128(constraint) => {
            if let Value::String(string) = json {
                let bigint =
                    string.parse().or(Err(err!(ParseError, "Could not parse integer.")))?;
                serial_bigint(bigint, *constraint, out).or(Err(JsonError::FailedWriting))
            } else {
                wrong_json_type!("JSON String required")
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
                wrong_json_type!("JSON String required")
            }
        }
        Type::ByteArray(len) => {
            if let Value::String(string) = json {
                let bytes = hex::decode(string)?;
                ensure!(ByteArrayError, *len == bytes.len() as u32, "Mismatching number of bytes");
                for value in bytes {
                    serial!(value, out)?;
                }
                Ok(())
            } else {
                wrong_json_type!("JSON String required")
            }
        }
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
    match fields {
        Fields::Named(fields) => {
            if let Value::Object(map) = json {
                ensure!(FieldError, fields.len() >= map.len(), "Too many fields provided");
                for (field_name, field_ty) in fields {
                    let field_value_opt = map.get(field_name);
                    if let Some(field_value) = field_value_opt {
                        write_bytes_from_json_schema_type(field_ty, field_value, out)?;
                    } else {
                        err!(FieldError, format!("Missing field: {}", field_name));
                    }
                }
                Ok(())
            } else {
                wrong_json_type!("JSON Object required for named fields")
            }
        }
        Fields::Unnamed(fields) => {
            if let Value::Array(values) = json {
                ensure!(
                    FieldError,
                    fields.len() == values.len(),
                    format!("Expected {} unnamed fields", fields.len())
                );
                for (field_ty, value) in fields.iter().zip(values.iter()) {
                    write_bytes_from_json_schema_type(field_ty, value, out)?;
                }
                Ok(())
            } else {
                wrong_json_type!("JSON Array required for unnamed fields")
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
}
