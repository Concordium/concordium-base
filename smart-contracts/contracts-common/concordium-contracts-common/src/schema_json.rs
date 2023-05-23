use crate::{constants::*, schema::*, *};
use core::fmt::Display;
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use serde_json::Value;
use std::convert::{TryFrom, TryInto};

/// Represents errors occurring while serializing data from the schema JSON
/// format.
#[derive(Debug, thiserror::Error, Clone)]
pub enum JsonError<'a> {
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
    /// Trace leading to the original [JsonError].
    #[error("{field} -> {error}")]
    TraceError {
        field: String,
        json:  &'a serde_json::Value,
        error: Box<JsonError<'a>>,
    },
}

impl<'a> JsonError<'a> {
    /// Wraps a [JsonError] in a [JsonError::TraceError], providing a trace to
    /// the origin of the error.
    fn add_trace(self, field: String, json: &'a serde_json::Value) -> Self {
        JsonError::TraceError {
            field,
            json,
            error: Box::new(self),
        }
    }

    /// Gets the underlying error of a [JsonError::TraceError]. For any other
    /// variant, this simply returns the error itself.
    pub fn get_error(&self) -> &Self {
        let mut out = self;
        loop {
            if let JsonError::TraceError {
                error,
                ..
            } = out
            {
                out = error;
            } else {
                break;
            }
        }
        out
    }

    /// Prints a formatted error message for variant. [JsonError::TraceError]
    /// supports printing a verbose form including a more detailed
    /// description of the error stack, which is returned if `verbose` is
    /// set to true.
    pub fn print(&self, verbose: bool) -> String {
        if !verbose {
            return format!("{}", self);
        }

        let mut out = String::new();
        let mut current_error = self;
        let mut is_initial_pass = true;

        loop {
            if let JsonError::TraceError {
                error,
                json,
                field,
            } = current_error
            {
                let formatted_json =
                    serde_json::to_string_pretty(json).unwrap_or_else(|_| format!("{}", json));
                if is_initial_pass {
                    out = format!("In {} of {}", field, formatted_json);
                } else {
                    out = format!("In {} of {}\n{}", field, formatted_json, out);
                }

                current_error = error;
                is_initial_pass = false;
            } else {
                out = format!("{}\n{}", current_error, out);
                break;
            }
        }

        out
    }
}

/// Wrapper around a list of bytes to represent data which failed to be
/// deserialized into schema type.
#[derive(Debug, Clone)]
pub struct ToJsonErrorData {
    bytes: Vec<u8>,
}

impl From<Vec<u8>> for ToJsonErrorData {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
        }
    }
}

impl From<ToJsonErrorData> for Vec<u8> {
    fn from(value: ToJsonErrorData) -> Self { value.bytes }
}

impl Display for ToJsonErrorData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.bytes.iter().try_for_each(|b| write!(f, "{:02x?}", b))
    }
}

/// Represents errors occurring while deserializing to the schema JSON format.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ToJsonError<'a> {
    /// JSON formatter failed to represent value.
    #[error("Failed to format as JSON")]
    FormatError,
    /// Failed to deserialize data to type expected from schema.
    #[error("Failed to deserialize {schema:?} from position {position} of bytes {data}")]
    DeserialError {
        position: u32,
        schema:   &'a Type,
        data:     ToJsonErrorData,
    },
    /// Trace leading to the original [ToJsonError].
    #[error("{schema:?} -> {error}")]
    TraceError {
        position: u32,
        schema:   &'a Type,
        error:    Box<ToJsonError<'a>>,
    },
}

impl<'a> ToJsonError<'a> {
    /// Wraps a [ToJsonError] in a [ToJsonError::TraceError], providing a trace
    /// to the origin of the error.
    fn add_trace(self, position: u32, schema: &'a Type) -> Self {
        ToJsonError::TraceError {
            position,
            schema,
            error: Box::new(self),
        }
    }

    /// Gets the underlying error of a [ToJsonError::TraceError]. For any other
    /// variant, this simply returns the error itself.
    pub fn get_error(&self) -> &Self {
        let mut out = self;
        loop {
            if let ToJsonError::TraceError {
                error,
                ..
            } = out
            {
                out = error;
            } else {
                break;
            }
        }
        out
    }

    /// Prints a formatted error message for variant. [ToJsonError::TraceError]
    /// supports printing a verbose form including a more detailed
    /// description of the error stack, which is returned if `verbose` is
    /// set to true.
    pub fn print(&self, verbose: bool) -> String {
        if !verbose {
            return format!("{}", self);
        }

        let mut out = String::new();
        let mut current_error = self;
        let mut is_initial_pass = true;

        loop {
            if let ToJsonError::TraceError {
                error,
                position,
                schema,
            } = current_error
            {
                if is_initial_pass {
                    out = format!("In deserializing position {} into type {:?}", position, schema);
                } else {
                    out = format!(
                        "In deserializing position {} into type {:?}\n{}",
                        position, schema, out
                    );
                }

                current_error = error;
                is_initial_pass = false;
            } else {
                out = format!("{}\n{}", current_error, out);
                break;
            }
        }

        out
    }
}

pub type ToJsonResult<'a, A> = Result<A, ToJsonError<'a>>;

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
fn write_bytes_from_json_schema_type<'a, W: Write>(
    schema: &Type,
    json: &'a serde_json::Value,
    out: &mut W,
) -> Result<(), JsonError<'a>> {
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
                let n = n.as_i64().ok_or(JsonError::SignedIntRequired)?;
                let n: i8 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I16 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or(JsonError::SignedIntRequired)?;
                let n: i16 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I32 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or(JsonError::SignedIntRequired)?;
                let n: i32 = n.try_into()?;
                serial!(n, out)
            } else {
                Err(WrongJsonType("JSON number required".to_string()))
            }
        }
        Type::I64 => {
            if let Value::Number(n) = json {
                let n = n.as_i64().ok_or(JsonError::SignedIntRequired)?;
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
                write_bytes_from_json_schema_type(left_type, &values[0], out)
                    .map_err(|e| e.add_trace("0".to_string(), json))?;
                write_bytes_from_json_schema_type(right_type, &values[1], out)
                    .map_err(|e| e.add_trace("1".to_string(), json))
            } else {
                Err(WrongJsonType("JSON Array required for a pair".to_string()))
            }
        }
        Type::List(size_len, ty) => {
            if let Value::Array(values) = json {
                let len = values.len();
                write_bytes_for_length_of_size(len, size_len, out)?;

                for (i, value) in values.iter().enumerate() {
                    write_bytes_from_json_schema_type(ty, value, out)
                        .map_err(|e| e.add_trace(format!("{}", i), json))?;
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

                for (i, value) in values.iter().enumerate() {
                    write_bytes_from_json_schema_type(ty, value, out)
                        .map_err(|e| e.add_trace(format!("{}", i), json))?;
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

                for (i, entry) in entries.iter().enumerate() {
                    if let Value::Array(pair) = entry {
                        ensure!(pair.len() == 2, MapError("Expected key-value pair".to_string()));
                        let result: Result<(), JsonError> = {
                            write_bytes_from_json_schema_type(key_ty, &pair[0], out)
                                .map_err(|e| e.add_trace("0".to_string(), entry))?;
                            write_bytes_from_json_schema_type(val_ty, &pair[1], out)
                                .map_err(|e| e.add_trace("1".to_string(), entry))?;
                            Ok(())
                        };
                        result.map_err(|e| e.add_trace(format!("{}", i), json))?;
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

                for (i, value) in values.iter().enumerate() {
                    write_bytes_from_json_schema_type(ty, value, out)
                        .map_err(|e| e.add_trace(format!("{}", i), json))?;
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
                        .map_err(|e| e.add_trace(format!("\"{}\"", variant_name), json))
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
                        .map_err(|e| e.add_trace(format!("'{}'", variant_name), json))
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
                    FieldError("Missing field \"contract\" of type JSON String.".to_string())
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
                    Err(WrongJsonType("JSON String required for field \"contract\".".to_string()))
                }
            } else {
                Err(WrongJsonType("JSON Object required for contract name.".to_string()))
            }
        }
        Type::ReceiveName(size_len) => {
            if let Value::Object(fields) = json {
                let contract = fields.get("contract").ok_or_else(|| {
                    FieldError("Missing field \"contract\" of type JSON String.".to_string())
                })?;
                let func = fields.get("func").ok_or_else(|| {
                    WrongJsonType("Missing field \"func\" of type JSON String.".to_string())
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
                        Err(WrongJsonType("JSON String required for field \"func\".".to_string()))
                    }
                } else {
                    Err(WrongJsonType("JSON String required for field \"contract\".".to_string()))
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
    pub fn serial_value<'a>(&self, json: &'a serde_json::Value) -> Result<Vec<u8>, JsonError<'a>> {
        let mut out = Vec::new();
        self.serial_value_into(json, &mut out)?;
        Ok(out)
    }

    /// Serialize the given JSON value into the binary format represented by the
    /// schema. The resulting byte array is written into the provided sink.
    /// If the JSON value does not match the schema an error will be returned.
    pub fn serial_value_into<'a>(
        &self,
        json: &'a serde_json::Value,
        out: &mut impl Write,
    ) -> Result<(), JsonError<'a>> {
        write_bytes_from_json_schema_type(self, json, out)
    }

    /// Uses the schema to parse JSON into bytes
    /// It is assumed the array of values for Map and Set are already ordered.
    #[deprecated(
        since = "5.2.0",
        note = "Use the more ergonomic [`serial_value_into`](Self::serial_value_into) instead."
    )]
    pub fn write_bytes_from_json_schema_type<'a, W: Write>(
        schema: &Type,
        json: &'a serde_json::Value,
        out: &mut W,
    ) -> Result<(), JsonError<'a>> {
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

fn write_bytes_from_json_schema_fields<'a, W: Write>(
    fields: &Fields,
    json: &'a serde_json::Value,
    out: &mut W,
) -> Result<(), JsonError<'a>> {
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
                        write_bytes_from_json_schema_type(field_ty, field_value, out)
                            .map_err(|e| e.add_trace(format!("\"{}\"", field_name), json))?;
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
                for (i, (field_ty, value)) in fields.iter().zip(values.iter()).enumerate() {
                    write_bytes_from_json_schema_type(field_ty, value, out)
                        .map_err(|e| e.add_trace(format!("{}", i), json))?;
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
) -> Result<(), JsonError<'static>> {
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
    use serde_json::json;

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
    fn test_serial_account_address() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema = Type::AccountAddress;
        let bytes =
            schema.serial_value(&json!(format!("{}", &account))).expect("Serializing failed");

        let expected = Vec::from(account_bytes);
        assert_eq!(expected, bytes)
    }

    #[test]
    fn test_serial_account_address_wrong_address_fails() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema = Type::AccountAddress;
        let json = json!(format!("{}", &account).get(1..));
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(err, JsonError::FailedParsingAccountAddress))
    }

    #[test]
    fn test_serial_account_wrong_type_fails() {
        let schema = Type::AccountAddress;
        let json = json!(123);
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(err, JsonError::WrongJsonType(_)))
    }

    #[test]
    fn test_serial_list_fails_with_trace() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema = Type::List(SizeLength::U8, Box::new(Type::AccountAddress));
        let json = json!([format!("{}", account), 123]);
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(
            err,
            JsonError::TraceError {
                field,
                error,
                ..
            } if matches!(*error, JsonError::WrongJsonType(_)) && field == "1"
        ));
    }

    #[test]
    fn test_serial_object_fails_with_trace() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema = Type::Struct(Fields::Named(vec![
            ("account".into(), Type::AccountAddress),
            ("contract".into(), Type::ContractAddress),
        ]));
        let json = json!({ "account": format!("{}", account), "contract": {} });
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(
            err,
            JsonError::TraceError {
                field,
                error,
                ..
            } if matches!(*error, JsonError::FieldError(_)) && field == "\"contract\""
        ));
    }

    #[test]
    fn test_serial_fails_with_nested_trace() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema_object = Type::Struct(Fields::Named(vec![
            ("account".into(), Type::AccountAddress),
            ("contract".into(), Type::ContractAddress),
        ]));
        let schema = Type::List(SizeLength::U8, Box::new(schema_object));
        let json = json!([{ "account": format!("{}", account), "contract": { "index": 0, "subindex": 0} }, { "account": format!("{}", account), "contract": {} }]);
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(
            err,
            JsonError::TraceError {
                field,
                error,
                ..
            } if field == "1" && matches!(
                *error.to_owned(),
                JsonError::TraceError {
                    field,
                    error,
                    ..
                } if field == "\"contract\"" && matches!(*error, JsonError::FieldError(_))
            )
        ));
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

    #[test]
    fn test_deserial_account_address() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let mut cursor = Cursor::new(&account_bytes);
        let schema = Type::AccountAddress;
        let value = schema.to_json(&mut cursor).expect("Deserializing should not fail");

        let expected = json!(format!("{}", AccountAddress(account_bytes)));
        assert_eq!(expected, value)
    }

    #[test]
    fn test_deserial_malformed_account_address_fails() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let mut cursor = Cursor::new(&account_bytes[..30]); // Malformed account address
        let schema = Type::AccountAddress;
        let err = schema.to_json(&mut cursor).expect_err("Deserializing should fail");

        assert!(matches!(err, ToJsonError::DeserialError {
            position: 0,
            schema: Type::AccountAddress,
            ..
        }))
    }

    #[test]
    fn test_deserial_malformed_list_fails() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let mut list_bytes = vec![2, 0];
        list_bytes.extend_from_slice(&account_bytes);
        list_bytes.extend_from_slice(&account_bytes[..30]); // Malformed account address

        let mut cursor = Cursor::new(list_bytes);
        let schema = Type::List(SizeLength::U8, Box::new(Type::AccountAddress));
        let err = schema.to_json(&mut cursor).expect_err("Deserializing should fail");

        assert!(matches!(
            err,
            ToJsonError::TraceError {
                position: 0,
                schema: Type::List(_, _),
                error,
            } if matches!(
                *error,
                ToJsonError::DeserialError {
                    position: 33,
                    schema: Type::AccountAddress, ..
                }
            )
        ))
    }

    #[test]
    fn test_deserial_malformed_nested_list_fails() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let contract_bytes = [0u8; 16];
        let mut list_bytes = vec![2, 0];
        list_bytes.extend_from_slice(&account_bytes);
        list_bytes.extend_from_slice(&contract_bytes);
        list_bytes.extend_from_slice(&account_bytes);
        list_bytes.extend_from_slice(&contract_bytes[..10]); // Malformed contract address.

        let mut cursor = Cursor::new(list_bytes);
        let schema_object = Type::Struct(Fields::Named(vec![
            ("a".into(), Type::AccountAddress),
            ("b".into(), Type::ContractAddress),
        ]));
        let schema = Type::List(SizeLength::U8, Box::new(schema_object));
        let err = schema.to_json(&mut cursor).expect_err("Deserializing should fail");

        assert!(matches!(
            err,
            ToJsonError::TraceError {
                position: 0,
                schema: Type::List(_,_),
                error,
            } if matches!(
                *error.to_owned(),
                ToJsonError::TraceError {
                    position: 49,
                    schema: Type::Struct(_),
                    error
                } if matches!(
                    *error,
                    ToJsonError::DeserialError {
                        position: 81,
                        schema: Type::ContractAddress,
                        ..
                    }
                )
            )
        ))
    }
}

impl Fields {
    pub fn to_json<'a, T: AsRef<[u8]>>(
        &'a self,
        source: &mut Cursor<T>,
    ) -> ToJsonResult<'a, serde_json::Value> {
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

fn item_list_to_json<'a, T: AsRef<[u8]>>(
    source: &mut Cursor<T>,
    size_len: SizeLength,
    item_to_json: impl Fn(&mut Cursor<T>) -> ToJsonResult<'a, serde_json::Value>,
    schema: &'a Type,
) -> ToJsonResult<'a, Vec<serde_json::Value>> {
    let data = source.data.as_ref().to_owned().into();
    let position = source.cursor_position();
    let len = deserial_length(source, size_len).map_err(|_| ToJsonError::DeserialError {
        data,
        position,
        schema,
    })?;
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
    pub fn to_json_string_pretty<'a>(&'a self, bytes: &'a [u8]) -> ToJsonResult<'a, String> {
        let source = &mut Cursor::new(bytes);
        let js = self.to_json(source)?;
        serde_json::to_string_pretty(&js).map_err(|_| ToJsonError::FormatError {})
    }

    /// Uses the schema to deserialize bytes into json
    pub fn to_json<'a, T: AsRef<[u8]>>(
        &'a self,
        source: &mut Cursor<T>,
    ) -> ToJsonResult<'a, serde_json::Value> {
        use serde_json::*;

        let data = source.data.as_ref().to_owned().into();
        let position = source.cursor_position();

        let deserial_error = ToJsonError::DeserialError {
            data,
            position,
            schema: self,
        };

        match self {
            Type::Unit => Ok(Value::Null),
            Type::Bool => {
                let n = bool::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Bool(n))
            }
            Type::U8 => {
                let n = u8::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::U16 => {
                let n = u16::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::U32 => {
                let n = u32::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::U64 => {
                let n = u64::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::U128 => {
                let n = u128::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(n.to_string()))
            }
            Type::I8 => {
                let n = i8::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::I16 => {
                let n = i16::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::I32 => {
                let n = i32::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::I64 => {
                let n = i64::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::Number(n.into()))
            }
            Type::I128 => {
                let n = i128::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(n.to_string()))
            }
            Type::Amount => {
                let n = Amount::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(n.micro_ccd().to_string()))
            }
            Type::AccountAddress => {
                let address = AccountAddress::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(address.to_string()))
            }
            Type::ContractAddress => {
                let address = ContractAddress::deserial(source).map_err(|_| deserial_error)?;
                Ok(serde_json::to_value(address).map_err(|_| ToJsonError::FormatError {})?)
            }
            Type::Timestamp => {
                let timestamp = Timestamp::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(timestamp.to_string()))
            }
            Type::Duration => {
                let duration = Duration::deserial(source).map_err(|_| deserial_error)?;
                Ok(Value::String(duration.to_string()))
            }
            Type::Pair(left_type, right_type) => {
                let left = left_type.to_json(source).map_err(|e| e.add_trace(position, self))?;
                let right = right_type.to_json(source).map_err(|e| e.add_trace(position, self))?;
                Ok(Value::Array(vec![left, right]))
            }
            Type::List(size_len, ty) => {
                let values = item_list_to_json(source, *size_len, |s| ty.to_json(s), self)
                    .map_err(|e| e.add_trace(position, self))?;
                Ok(Value::Array(values))
            }
            Type::Set(size_len, ty) => {
                let values = item_list_to_json(source, *size_len, |s| ty.to_json(s), self)
                    .map_err(|e| e.add_trace(position, self))?;
                Ok(Value::Array(values))
            }
            Type::Map(size_len, key_type, value_type) => {
                let values = item_list_to_json(
                    source,
                    *size_len,
                    |s| {
                        let key = key_type.to_json(s).map_err(|e| e.add_trace(position, self))?;
                        let value =
                            value_type.to_json(s).map_err(|e| e.add_trace(position, self))?;
                        Ok(Value::Array(vec![key, value]))
                    },
                    self,
                )?;
                Ok(Value::Array(values))
            }
            Type::Array(len, ty) => {
                let len: usize = (*len).try_into().map_err(|_| deserial_error)?;
                let mut values = Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));
                for _ in 0..len {
                    let value = ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            Type::Struct(fields_ty) => {
                let fields = fields_ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                Ok(fields)
            }
            Type::Enum(variants) => {
                let idx = if variants.len() <= 256 {
                    u8::deserial(source).map(|v| v as usize)
                } else {
                    u16::deserial(source).map(|v| v as usize)
                };

                // Map all error cases into the same error.
                if let Ok(Some((name, fields_ty))) = idx.map(|idx| variants.get(idx)) {
                    let fields =
                        fields_ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                    Ok(json!({ name: fields }))
                } else {
                    Err(deserial_error)
                }
            }
            Type::TaggedEnum(variants) => {
                let idx = u8::deserial(source);

                // Map all error cases into the same error.
                if let Ok(Some((name, fields_ty))) = idx.map(|idx| variants.get(&idx)) {
                    let fields =
                        fields_ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                    Ok(json!({ name: fields }))
                } else {
                    Err(deserial_error)
                }
            }
            Type::String(size_len) => {
                let string = deserial_string(source, *size_len).map_err(|_| deserial_error)?;
                Ok(Value::String(string))
            }
            Type::ContractName(size_len) => {
                let name = deserial_string(source, *size_len);
                let owned_contract_name =
                    name.and_then(|n| OwnedContractName::new(n).map_err(|_| ParseError {}));

                // Map all error cases into the same error.
                if let Ok(contract_name) = owned_contract_name {
                    let name_without_init = contract_name.as_contract_name().contract_name();
                    Ok(json!({ "contract": name_without_init }))
                } else {
                    Err(deserial_error)
                }
            }
            Type::ReceiveName(size_len) => {
                let name = deserial_string(source, *size_len);
                let owned_receive_name =
                    name.and_then(|n| OwnedReceiveName::new(n).map_err(|_| ParseError {}));

                // Map all error cases into the same error.
                if let Ok(owned_receive_name) = owned_receive_name {
                    let receive_name = owned_receive_name.as_receive_name();
                    let contract_name = receive_name.contract_name();
                    let func_name = receive_name.entrypoint_name();
                    Ok(json!({"contract": contract_name, "func": func_name}))
                } else {
                    Err(deserial_error)
                }
            }
            Type::ULeb128(constraint) => {
                let int = deserial_biguint(source, *constraint).map_err(|_| deserial_error)?;
                Ok(Value::String(int.to_string()))
            }
            Type::ILeb128(constraint) => {
                let int = deserial_bigint(source, *constraint).map_err(|_| deserial_error)?;
                Ok(Value::String(int.to_string()))
            }
            Type::ByteList(size_len) => {
                let len = deserial_length(source, *size_len);
                let bytes: ParseResult<Vec<u8>> = len.and_then(|len| {
                    let mut bytes =
                        Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));

                    for _ in 0..len {
                        let byte = source.read_u8();
                        bytes.push(byte);
                    }

                    bytes.into_iter().collect()
                });

                // Map all error cases into the same error.
                if let (Ok(len), Ok(bytes)) = (len, bytes) {
                    let mut string =
                        String::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, 2 * len));
                    bytes.into_iter().for_each(|b| string.push_str(&format!("{:02x?}", b)));
                    Ok(Value::String(string))
                } else {
                    Err(deserial_error)
                }
            }
            Type::ByteArray(len) => {
                let len = usize::try_from(*len).map_err(|_| ParseError {});
                let bytes: ParseResult<Vec<u8>> = len.and_then(|len| {
                    let mut bytes =
                        Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));

                    for _ in 0..len {
                        let byte = source.read_u8();
                        bytes.push(byte);
                    }

                    bytes.into_iter().collect()
                });

                // Map all error cases into the same error.
                if let (Ok(len), Ok(bytes)) = (len, bytes) {
                    let mut string =
                        String::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, 2 * len));
                    bytes.into_iter().for_each(|b| string.push_str(&format!("{:02x?}", b)));
                    Ok(Value::String(string))
                } else {
                    Err(deserial_error)
                }
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
