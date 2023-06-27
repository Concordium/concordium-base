use crate::{constants::*, schema::*, *};
use core::fmt::Display;
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use serde_json::{json, Map, Value};
use std::convert::{TryFrom, TryInto};

/// Trait which includes implementations for unwrapping recursive error
/// structures. Requires that the implementor supplies implementations for
/// accessing data for individual layers of the nested structure.
///
/// This is intended to be private to the module, as it merely serves the
/// purpose of code de-duplication.
trait TraceError {
    /// Returns an error message layer associated with this error, along with a
    /// reference to the error this error wraps. If this error is not a
    /// wrapping layer, None is expected to be returned.
    fn display_layer(&self, verbose: bool) -> (String, Option<&Self>);

    /// Returns a formatted error message for a [`TraceError`].
    /// It supports printing a verbose form including a more detailed
    /// description of the error stack, which is returned if `verbose` is
    /// set to true.
    fn display_nested(&self, verbose: bool) -> String {
        let mut out = String::new();
        let mut current_error = self;
        let mut is_initial_pass = true;

        loop {
            let (string, next_error) = current_error.display_layer(verbose);
            out = if is_initial_pass {
                is_initial_pass = false;
                string
            } else if verbose {
                format!("{}\n{}", string, out)
            } else {
                format!("{} -> {}", out, string)
            };

            if let Some(next) = next_error {
                current_error = next;
            } else {
                break;
            }
        }

        out
    }

    /// Gets a reference to the error this error wraps. If this error is not a
    /// wrapping layer, None is expected to be returned.
    fn get_inner_error(&self) -> Option<&Self>;

    /// Gets the innermost error of a [`TraceError`].
    fn get_innermost_error(&self) -> &Self {
        let mut out = self;
        while let Some(error) = self.get_inner_error() {
            out = error;
        }
        out
    }
}

/// Represents errors occurring while serializing data from the schema JSON
/// format.
///
/// # Examples
///
/// ## Simple type from invalid JSON value
/// ```
/// # use serde_json::json;
/// # use concordium_contracts_common::schema_json::*;
/// # use concordium_contracts_common::schema::*;
/// # use concordium_contracts_common::*;
/// #
/// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
/// let account = AccountAddress(account_bytes.clone());
/// let schema = Type::AccountAddress;
///
/// // Malformed JSON value due to incorrect account address
/// let json = json!(format!("{}", &account).get(1..));
/// let err = schema.serial_value(&json).expect_err("Serializing should fail");
///
/// assert!(matches!(err, JsonError::FailedParsingAccountAddress))
/// ```
///
/// ## Complex type from invalid JSON value
/// ```
/// # use serde_json::json;
/// # use concordium_contracts_common::schema_json::*;
/// # use concordium_contracts_common::schema::*;
/// # use concordium_contracts_common::*;
/// #
/// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
/// let account = AccountAddress(account_bytes.clone());
/// let schema = Type::Struct(Fields::Named(vec![
///    ("account".into(), Type::AccountAddress),
///    ("contract".into(), Type::ContractAddress),
/// ]));
///
/// // Malformed JSON value due to incorrect value for "contract" field
/// let json = json!({ "account": format!("{}", account), "contract": {} });
/// let err = schema.serial_value(&json).expect_err("Serializing should fail");
///
/// assert!(matches!(
///    err,
///    JsonError::TraceError {
///        field,
///        error,
///        ..
///    } if matches!(*error, JsonError::FieldError(_)) && field == "\"contract\""
/// ));
/// ```
#[derive(Debug, thiserror::Error, Clone)]
pub enum JsonError {
    FailedWriting,
    UnsignedIntRequired,
    SignedIntRequired,
    FailedParsingAccountAddress,
    WrongJsonType(String),
    FieldError(String),
    EnumError(String),
    MapError(String),
    PairError(String),
    ArrayError(String),
    ParseError(String),
    ByteArrayError(String),
    FromHexError(#[from] hex::FromHexError),
    TryFromIntError(#[from] core::num::TryFromIntError),
    ParseIntError(#[from] std::num::ParseIntError),
    ParseDurationError(#[from] ParseDurationError),
    ParseTimestampError(#[from] ParseTimestampError),
    /// Trace leading to the original [`JsonError`].
    TraceError {
        field: String,
        json:  serde_json::Value,
        error: Box<JsonError>,
    },
}

impl Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JsonError::FailedWriting => write!(f, "Failed writing"),
            JsonError::UnsignedIntRequired => write!(f, "Unsigned integer required"),
            JsonError::SignedIntRequired => write!(f, "Signed integer required"),
            JsonError::FailedParsingAccountAddress => write!(f, "Failed parsing account address"),
            JsonError::WrongJsonType(s) => write!(f, "{}", s),
            JsonError::FieldError(s) => write!(f, "{}", s),
            JsonError::EnumError(s) => write!(f, "{}", s),
            JsonError::MapError(s) => write!(f, "{}", s),
            JsonError::PairError(s) => write!(f, "{}", s),
            JsonError::ArrayError(s) => write!(f, "{}", s),
            JsonError::ParseError(s) => write!(f, "{}", s),
            JsonError::ByteArrayError(s) => write!(f, "{}", s),
            JsonError::FromHexError(e) => write!(f, "{}", e),
            JsonError::TryFromIntError(e) => write!(f, "{}", e),
            JsonError::ParseIntError(e) => write!(f, "{}", e),
            JsonError::ParseDurationError(e) => write!(f, "{}", e),
            JsonError::ParseTimestampError(e) => write!(f, "{}", e),
            JsonError::TraceError {
                ..
            } => write!(f, "{}", self.display(false)),
        }
    }
}

impl TraceError for JsonError {
    fn display_layer(&self, verbose: bool) -> (String, Option<&Self>) {
        if let JsonError::TraceError {
            error,
            json,
            field,
        } = self
        {
            let formatted_json =
                serde_json::to_string_pretty(json).unwrap_or_else(|_| format!("{}", json));
            let message = if verbose {
                format!("In {} of {}", field, formatted_json)
            } else {
                field.clone()
            };
            return (message, Some(error));
        }

        let message = format!("{}", self);
        (message, None)
    }

    fn get_inner_error(&self) -> Option<&Self> {
        if let JsonError::TraceError {
            error,
            ..
        } = self
        {
            return Some(error);
        }

        None
    }
}

impl JsonError {
    /// Wraps a [`JsonError`] in a [`JsonError::TraceError`], providing a trace
    /// to the origin of the error.
    fn add_trace(self, field: String, json: &serde_json::Value) -> Self {
        JsonError::TraceError {
            field,
            json: json.clone(),
            error: Box::new(self),
        }
    }

    /// Returns a formatted error message for variant. [`JsonError::TraceError`]
    /// supports printing a verbose form including a more detailed
    /// description of the error stack, which is returned if `verbose` is
    /// set to true.
    ///
    /// # Examples
    ///
    /// ## Display error from list of objects
    ///
    /// ```
    /// # use serde_json::json;
    /// # use concordium_contracts_common::schema_json::*;
    /// # use concordium_contracts_common::schema::*;
    /// # use concordium_contracts_common::*;
    /// #
    /// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
    /// let account = AccountAddress(account_bytes);
    /// let object_schema = Type::Struct(Fields::Named(vec![
    ///    ("account".into(), Type::AccountAddress),
    ///    ("contract".into(), Type::ContractAddress),
    /// ]));
    /// let schema = Type::List(SizeLength::U8, Box::new(object_schema));
    ///
    /// // Malformed JSON value due to incorrect value for "contract" field
    /// let json = json!([{ "account": format!("{}", account), "contract": {} }]);
    /// let err = schema.serial_value(&json).expect_err("Serializing should fail");
    ///
    /// // The error format points to the cause of the error from the root of the JSON.
    /// # #[rustfmt::skip]
    /// let expected = r#"0 -> "contract" -> 'index' is required in a Contract address"#.to_string();
    /// assert_eq!(expected, err.display(false));
    ///
    /// // Or if verbose, includes a stacktrace-like format.
    /// # #[rustfmt::skip]
    /// let expected_verbose = r#"'index' is required in a Contract address
    /// In "contract" of {
    ///   "account": "2wkBET2rRgE8pahuaczxKbmv7ciehqsne57F9gtzf1PVdr2VP3",
    ///   "contract": {}
    /// }
    /// In 0 of [
    ///   {
    ///     "account": "2wkBET2rRgE8pahuaczxKbmv7ciehqsne57F9gtzf1PVdr2VP3",
    ///     "contract": {}
    ///   }
    /// ]"#.to_string();
    /// assert_eq!(expected_verbose, err.display(true));
    /// ```
    pub fn display(&self, verbose: bool) -> String { self.display_nested(verbose) }

    /// Gets the underlying error of a [`JsonError::TraceError`]. For any other
    /// variant, this simply returns the error itself.
    pub fn get_error(&self) -> &Self { self.get_innermost_error() }
}

/// Wrapper around a list of bytes to represent data which failed to be
/// deserialized into schema type.
#[derive(Debug, Clone)]
pub struct ToJsonErrorData {
    pub bytes: Vec<u8>,
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
///
/// # Examples
///
/// ## Simple type from invalid byte sequence
/// ```
/// # use serde_json::json;
/// # use concordium_contracts_common::schema_json::*;
/// # use concordium_contracts_common::schema::*;
/// # use concordium_contracts_common::*;
/// #
/// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
/// let mut cursor = Cursor::new(&account_bytes[..30]); // Malformed account address
/// let schema = Type::AccountAddress;
/// let err = schema.to_json(&mut cursor).expect_err("Deserializing should fail");
///
/// assert!(matches!(err, ToJsonError::DeserialError {
///     position: 0,
///     schema: Type::AccountAddress,
///     ..
/// }))
/// ```
///
/// ## Complex type from invalid byte sequence
/// ```
/// # use serde_json::json;
/// # use concordium_contracts_common::schema_json::*;
/// # use concordium_contracts_common::schema::*;
/// # use concordium_contracts_common::*;
/// #
/// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
/// let mut list_bytes = vec![2, 0]; // 2 items in the list
/// list_bytes.extend_from_slice(&account_bytes); // Correct account address
/// list_bytes.extend_from_slice(&account_bytes[..30]); // Malformed account address
///
/// let mut cursor = Cursor::new(list_bytes);
/// let schema = Type::List(SizeLength::U8, Box::new(Type::AccountAddress));
/// let err = schema.to_json(&mut cursor).expect_err("Deserializing should fail");
///
/// assert!(matches!(
///    err,
///    ToJsonError::TraceError {
///        position: 0,
///        schema: Type::List(_, _),
///        error,
///    } if matches!(
///        *error,
///        ToJsonError::DeserialError {
///            position: 33,
///            schema: Type::AccountAddress, ..
///        }
///    )
/// ))
/// ```
#[derive(thiserror::Error, Debug, Clone)]
pub enum ToJsonError {
    /// JSON formatter failed to represent value.
    FormatError,
    /// Failed to deserialize data to type expected from schema.
    DeserialError {
        position: u32,
        schema:   Type,
        reason:   String,
        data:     ToJsonErrorData,
    },
    /// Trace leading to the original [ToJsonError].
    TraceError {
        position: u32,
        schema:   Type,
        error:    Box<ToJsonError>,
    },
}

impl Display for ToJsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ToJsonError::FormatError => write!(f, "Failed to format as JSON"),
            ToJsonError::DeserialError {
                position,
                schema,
                reason,
                data,
            } => write!(
                f,
                "Failed to deserialize {:?} due to: {} - from position {} of bytes {}",
                schema, reason, position, data
            ),
            ToJsonError::TraceError {
                ..
            } => write!(f, "{}", self.display(false)),
        }
    }
}

impl TraceError for ToJsonError {
    fn display_layer(&self, verbose: bool) -> (String, Option<&Self>) {
        if let ToJsonError::TraceError {
            error,
            position,
            schema,
        } = self
        {
            let message = if verbose {
                format!("In deserializing position {} into type {:?}", position, schema)
            } else {
                format!("{:?}", schema)
            };

            return (message, Some(error));
        }

        let message = format!("{}", self);
        (message, None)
    }

    fn get_inner_error(&self) -> Option<&Self> {
        if let ToJsonError::TraceError {
            error,
            ..
        } = self
        {
            return Some(error);
        }

        None
    }
}

impl ToJsonError {
    /// Wraps a [`ToJsonError`] in a [`ToJsonError::TraceError`], providing a
    /// trace to the origin of the error.
    fn add_trace(self, position: u32, schema: &Type) -> Self {
        ToJsonError::TraceError {
            position,
            schema: schema.clone(),
            error: Box::new(self),
        }
    }

    /// Returns a formatted error message for variant.
    /// [`ToJsonError::TraceError`] supports printing a verbose form
    /// including a more detailed description of the error stack, which is
    /// returned if `verbose` is set to true.
    ///
    /// # Examples
    ///
    /// ## Display error from failing to deserialize to list of objects
    ///
    /// ```
    /// # use serde_json::json;
    /// # use concordium_contracts_common::schema_json::*;
    /// # use concordium_contracts_common::schema::*;
    /// # use concordium_contracts_common::*;
    /// #
    /// let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
    /// let contract_bytes = [0u8; 16];
    /// let mut list_bytes = vec![2, 0];
    /// list_bytes.extend_from_slice(&account_bytes);
    /// list_bytes.extend_from_slice(&contract_bytes);
    /// // r#"<error-message>
    /// // In deserializing position <cursor-position> into type Struct(...)
    /// // In deserializing position <cursor-position> into type List(...)"#;
    /// list_bytes.extend_from_slice(&account_bytes);
    /// list_bytes.extend_from_slice(&contract_bytes[..10]); // Malformed contract address.

    /// let mut cursor = Cursor::new(list_bytes.clone());
    /// let schema_object = Type::Struct(Fields::Named(vec![
    ///     ("a".into(), Type::AccountAddress),
    ///     ("b".into(), Type::ContractAddress),
    /// ]));
    /// let schema = Type::List(SizeLength::U8, Box::new(schema_object));
    /// let err = schema.to_json(&mut cursor)
    ///                 .expect_err("Deserializing should fail");
    ///
    /// // The error format points to the position in the byte sequence that
    /// // failed to deserialize:
    /// err.display(false); // "List(...) -> Struct(...) -> <error-message>");
    ///
    /// // Or if verbose, includes a stacktrace-like format, similar to:
    /// // r#"<error-message>
    /// // In deserializing position <cursor-position> into type Struct(...)
    /// // In deserializing position <cursor-position> into type List(...)"#;
    /// err.display(true);
    /// ```
    pub fn display(&self, verbose: bool) -> String { self.display_nested(verbose) }

    /// Gets the underlying error of a [`ToJsonError::TraceError`]. For any
    /// other variant, this simply returns the error itself.
    pub fn get_error(&self) -> &Self { self.get_innermost_error() }
}

/// Error with the sole purpose of adding some context to [`ParseError`].
#[derive(thiserror::Error, Debug, Clone)]
#[error("{0}")]
struct ParseErrorWithReason(String);

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

impl Fields {
    /// Displays a template of the JSON to be used for the Fields.
    pub fn to_json_template(&self) -> serde_json::Value {
        match self {
            Fields::Named(vec) => {
                let mut map = Map::new();

                for (name, field) in vec.iter() {
                    map.insert(name.to_string(), field.to_json_template());
                }

                map.into()
            }
            Fields::Unnamed(vec) => {
                let mut new_vector = Vec::new();
                for element in vec.iter() {
                    new_vector.push(element.to_json_template())
                }

                new_vector.into()
            }
            Fields::None => serde_json::Value::Array(Vec::new()),
        }
    }
}

/// Displays a pretty-printed JSON-template of the schema.
impl Display for Type {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(&self.to_json_template()).unwrap())
    }
}

/// Displays the type value indented.
/// It should match the output of `concordium-client`.
fn display_type_schema_indented(
    mut out: String,
    type_schema: &Type,
    type_schema_name: &str,
    indent: usize,
) -> String {
    out = format!("{}{:>3$}{}:\n", out, "", type_schema_name, indent);
    out = format!(
        "{}{:>3$}{}\n",
        out,
        "",
        type_schema.to_string().replace('\n', "\n        "),
        indent + 2
    );
    out
}

/// Displays a pretty-printed JSON-template of the schema.
/// It should match the output of `concordium-client`.
impl Display for VersionedModuleSchema {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut out = String::new();
        match self {
            VersionedModuleSchema::V0(module_v0) => {
                for (contract_name, contract_schema) in module_v0.contracts.iter() {
                    out = format!("Contract: {:>30}\n", contract_name);
                    // State
                    if let Some(type_schema) = &contract_schema.state {
                        out = format!("{}{:>2}State:\n", out, "");
                        out = format!(
                            "{}{:>4}{}\n",
                            out,
                            "",
                            type_schema.to_string().replace('\n', "\n        ")
                        );
                    }
                    // Init Function
                    if let Some(type_schema) = &contract_schema.init {
                        out = format!("{}{:>2}Init:\n", out, "");
                        out = format!(
                            "{}{:>4}{}\n",
                            out,
                            "",
                            type_schema.to_string().replace('\n', "\n        ")
                        );
                    }
                    // Receive Functions
                    let receive_functions_map = &contract_schema.receive;
                    if !receive_functions_map.is_empty() {
                        out = format!("{}{:>2}Methods:\n", out, "");
                    }

                    for (function_name, type_schema) in receive_functions_map.iter() {
                        out = format!("{}{:>4}- {:?}\n", out, "", function_name);
                        out = format!(
                            "{}{:>6}{}\n",
                            out,
                            "",
                            type_schema.to_string().replace('\n', "\n        ")
                        );
                    }
                }
            }
            VersionedModuleSchema::V1(module_v1) => {
                for (contract_name, contract_schema) in module_v1.contracts.iter() {
                    out = format!("Contract: {:>30}\n", contract_name);
                    // Init Function
                    if let Some(schema) = &contract_schema.init {
                        out = format!("{}{:>2}Init:\n", out, "");

                        if let Some(type_schema) = schema.parameter() {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 4)
                        }
                        if let Some(type_schema) = schema.return_value() {
                            out = display_type_schema_indented(out, type_schema, "Return value", 4)
                        }
                    }

                    // Receive Functions
                    let receive_functions_map = &contract_schema.receive;
                    if !receive_functions_map.is_empty() {
                        out = format!("{}{:>2}Methods:\n", out, "");
                    }

                    for (function_name, schema) in receive_functions_map.iter() {
                        out = format!("{}{:>4}- {:?}\n", out, "", function_name);

                        if let Some(type_schema) = schema.parameter() {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 6)
                        }
                        if let Some(type_schema) = schema.return_value() {
                            out = display_type_schema_indented(out, type_schema, "Return value", 6)
                        }
                    }
                }
            }
            VersionedModuleSchema::V2(module_v2) => {
                for (contract_name, contract_schema) in module_v2.contracts.iter() {
                    out = format!("Contract: {:>30}\n", contract_name);
                    // Init Function
                    if let Some(FunctionV2 {
                        parameter,
                        return_value,
                        error,
                    }) = &contract_schema.init
                    {
                        out = format!("{}{:>2}Init:\n", out, "");

                        if let Some(type_schema) = parameter {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 4)
                        }

                        if let Some(type_schema) = error {
                            out = display_type_schema_indented(out, type_schema, "Error", 4)
                        }

                        if let Some(type_schema) = return_value {
                            out = display_type_schema_indented(out, type_schema, "Return value", 4)
                        }
                    }
                    // Receive Functions
                    let receive_functions_map = &contract_schema.receive;
                    if !receive_functions_map.is_empty() {
                        out = format!("{}{:>2}Methods:\n", out, "");
                    }

                    for (function_name, schema) in receive_functions_map.iter() {
                        out = format!("{}{:>4}- {:?}\n", out, "", function_name);

                        let FunctionV2 {
                            parameter,
                            return_value,
                            error,
                        } = schema;

                        if let Some(type_schema) = parameter {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 6)
                        }

                        if let Some(type_schema) = error {
                            out = display_type_schema_indented(out, type_schema, "Error", 6)
                        }

                        if let Some(type_schema) = return_value {
                            out = display_type_schema_indented(out, type_schema, "Return value", 6)
                        }
                    }
                }
            }
            VersionedModuleSchema::V3(module_v3) => {
                for (contract_name, contract_schema) in module_v3.contracts.iter() {
                    out = format!("Contract: {:>30}\n", contract_name);

                    // Init Function
                    if let Some(FunctionV2 {
                        parameter,
                        return_value,
                        error,
                    }) = &contract_schema.init
                    {
                        out = format!("{}{:>2}Init:\n", out, "");

                        if let Some(type_schema) = parameter {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 4)
                        }

                        if let Some(type_schema) = error {
                            out = display_type_schema_indented(out, type_schema, "Error", 4)
                        }

                        if let Some(type_schema) = return_value {
                            out = display_type_schema_indented(out, type_schema, "Return value", 4)
                        }
                    }

                    // Receive Functions
                    let receive_functions_map = &contract_schema.receive;

                    if !receive_functions_map.is_empty() {
                        out = format!("{}{:>2}Methods:\n", out, "");
                    }

                    for (function_name, schema) in receive_functions_map.iter() {
                        out = format!("{}{:>4}- {:?}\n", out, "", function_name);

                        let FunctionV2 {
                            parameter,
                            return_value,
                            error,
                        } = schema;

                        if let Some(type_schema) = parameter {
                            out = display_type_schema_indented(out, type_schema, "Parameter", 6)
                        }

                        if let Some(type_schema) = error {
                            out = display_type_schema_indented(out, type_schema, "Error", 6)
                        }

                        if let Some(type_schema) = return_value {
                            out = display_type_schema_indented(out, type_schema, "Return value", 6)
                        }
                    }

                    // Event
                    if let Some(type_schema) = &contract_schema.event {
                        out = display_type_schema_indented(out, type_schema, "Event", 2)
                    }
                }
            }
        }
        write!(f, "{}", out)
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

    /// Displays a template of the JSON to be used for the [`SchemaType`].
    pub fn to_json_template(&self) -> serde_json::Value {
        match self {
            Self::Enum(enum_type) => {
                let mut outer_map = Map::new();

                let mut vector = Vec::new();

                for (name, field) in enum_type.iter() {
                    let mut inner_map = Map::new();
                    inner_map.insert(name.to_string(), field.to_json_template());
                    vector.push(json!(inner_map))
                }
                outer_map.insert("Enum".to_string(), json!(vector));

                outer_map.into()
            }
            Self::TaggedEnum(tagged_enum) => {
                let mut outer_map = Map::new();

                let mut vector = Vec::new();

                for (_tag, (name, field)) in tagged_enum.iter() {
                    let mut inner_map = Map::new();
                    inner_map.insert(name.to_string(), field.to_json_template());
                    vector.push(json!(inner_map))
                }
                outer_map.insert("Enum".to_string(), json!(vector));

                outer_map.into()
            }
            Self::Struct(field) => field.to_json_template(),
            Self::ByteList(_) => "<String with lowercase hex>".into(),
            Self::ByteArray(size) => {
                format!("String of size {size} containing lowercase hex characters.").into()
            }
            Self::String(_) => "<String>".into(),
            Self::Unit => serde_json::Value::Array(Vec::new()),
            Self::Bool => "<Bool>".into(),
            Self::U8 => "<UInt8>".into(),
            Self::U16 => "<UInt16>".into(),
            Self::U32 => "<UInt32>".into(),
            Self::U64 => "<UInt64>".into(),
            Self::U128 => "<UInt128>".into(),
            Self::I8 => "<Int8>".into(),
            Self::I16 => "<Int16>".into(),
            Self::I32 => "<Int32>".into(),
            Self::I64 => "<Int64>".into(),
            Self::I128 => "<Int128>".into(),
            Self::ILeb128(size) => {
                format!("String of size at most {size} containing a signed integer.").into()
            }
            Self::ULeb128(size) => {
                format!("String of size at most {size} containing an unsigned integer.").into()
            }
            Self::Amount => "<Amount in microCCD>".into(),
            Self::AccountAddress => "<AccountAddress>".into(),
            Self::ContractAddress => {
                let mut contract_address = Map::new();
                contract_address.insert("index".to_string(), Type::U64.to_json_template());
                contract_address.insert("subindex".to_string(), Type::U64.to_json_template());
                contract_address.into()
            }
            Self::Timestamp => "<Timestamp (e.g. `2000-01-01T12:00:00Z`)>".into(),
            Self::Duration => "<Duration (e.g. `10d 1h 42s`)>".into(),
            Self::Pair(a, b) => vec![a.to_json_template(), b.to_json_template()].into(),
            Self::List(_, element) => vec![element.to_json_template()].into(),
            Self::Array(size, element) => {
                let mut vec = Vec::new();
                for _i in 0..*size {
                    vec.push(element.to_json_template())
                }
                vec.into()
            }
            Self::Set(_, element) => vec![element.to_json_template()].into(),
            Self::Map(_, key, value) => {
                vec![json!(vec![key.to_json_template(), value.to_json_template(),])].into()
            }
            Self::ContractName(_) => {
                let mut contract_name = Map::new();
                contract_name.insert("contract".to_string(), "<String>".into());
                contract_name.into()
            }
            Self::ReceiveName(_) => {
                let mut receive_name = Map::new();
                receive_name.insert("contract".to_string(), "<String>".into());
                receive_name.insert("func".to_string(), "<String>".into());
                receive_name.into()
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
    use serde_json::json;

    use super::*;
    use std::collections::BTreeMap;

    /// Tests schema template display of `VersionedModuleSchema::V3`
    #[test]
    fn test_schema_template_display_module_version_v3() {
        let mut receive_function_map = BTreeMap::new();
        receive_function_map.insert(String::from("MyFunction"), FunctionV2 {
            parameter:    Some(Type::AccountAddress),
            error:        Some(Type::AccountAddress),
            return_value: Some(Type::AccountAddress),
        });

        let mut map = BTreeMap::new();

        map.insert(String::from("MyContract"), ContractV3 {
            init:    Some(FunctionV2 {
                parameter:    Some(Type::AccountAddress),
                error:        Some(Type::AccountAddress),
                return_value: Some(Type::AccountAddress),
            }),
            receive: receive_function_map,
            event:   Some(Type::AccountAddress),
        });

        let schema = VersionedModuleSchema::V3(ModuleV3 {
            contracts: map,
        });

        let display = "Contract:                     MyContract
  Init:
    Parameter:
      \"<AccountAddress>\"
    Error:
      \"<AccountAddress>\"
    Return value:
      \"<AccountAddress>\"
  Methods:
    - \"MyFunction\"
      Parameter:
        \"<AccountAddress>\"
      Error:
        \"<AccountAddress>\"
      Return value:
        \"<AccountAddress>\"
  Event:
    \"<AccountAddress>\"\n";

        assert_eq!(display, format!("{}", schema));
    }

    /// Tests schema template display of `VersionedModuleSchema::V2`
    #[test]
    fn test_schema_template_display_module_version_v2() {
        let mut receive_function_map = BTreeMap::new();
        receive_function_map.insert(String::from("MyFunction"), FunctionV2 {
            parameter:    Some(Type::AccountAddress),
            error:        Some(Type::AccountAddress),
            return_value: Some(Type::AccountAddress),
        });

        let mut map = BTreeMap::new();

        map.insert(String::from("MyContract"), ContractV2 {
            init:    Some(FunctionV2 {
                parameter:    Some(Type::AccountAddress),
                error:        Some(Type::AccountAddress),
                return_value: Some(Type::AccountAddress),
            }),
            receive: receive_function_map,
        });

        let schema = VersionedModuleSchema::V2(ModuleV2 {
            contracts: map,
        });

        let display = "Contract:                     MyContract
  Init:
    Parameter:
      \"<AccountAddress>\"
    Error:
      \"<AccountAddress>\"
    Return value:
      \"<AccountAddress>\"
  Methods:
    - \"MyFunction\"
      Parameter:
        \"<AccountAddress>\"
      Error:
        \"<AccountAddress>\"
      Return value:
        \"<AccountAddress>\"\n";

        assert_eq!(display, format!("{}", schema));
    }

    /// Tests schema template display of `VersionedModuleSchema::V1`
    #[test]
    fn test_schema_template_display_module_version_v1() {
        let mut receive_function_map = BTreeMap::new();
        receive_function_map.insert(String::from("MyFunction"), FunctionV1::Both {
            parameter:    Type::AccountAddress,
            return_value: Type::AccountAddress,
        });

        let mut map = BTreeMap::new();

        map.insert(String::from("MyContract"), ContractV1 {
            init:    Some(FunctionV1::Both {
                parameter:    Type::AccountAddress,
                return_value: Type::AccountAddress,
            }),
            receive: receive_function_map,
        });

        let schema = VersionedModuleSchema::V1(ModuleV1 {
            contracts: map,
        });

        let display = "Contract:                     MyContract
  Init:
    Parameter:
      \"<AccountAddress>\"
    Return value:
      \"<AccountAddress>\"
  Methods:
    - \"MyFunction\"
      Parameter:
        \"<AccountAddress>\"
      Return value:
        \"<AccountAddress>\"\n";

        assert_eq!(display, format!("{}", schema));
    }

    /// Tests schema template display of `VersionedModuleSchema::V0`
    #[test]
    fn test_schema_template_display_module_version_v0() {
        let mut receive_function_map = BTreeMap::new();
        receive_function_map.insert(String::from("MyFunction"), Type::AccountAddress);

        let mut map = BTreeMap::new();

        map.insert(String::from("MyContract"), ContractV0 {
            state:   Some(Type::AccountAddress),
            init:    Some(Type::AccountAddress),
            receive: receive_function_map,
        });

        let schema = VersionedModuleSchema::V0(ModuleV0 {
            contracts: map,
        });

        let display = "Contract:                     MyContract
  State:
    \"<AccountAddress>\"
  Init:
    \"<AccountAddress>\"
  Methods:
    - \"MyFunction\"
      \"<AccountAddress>\"\n";

        assert_eq!(display, format!("{}", schema));
    }

    /// Tests schema template display in JSON of an Enum
    #[test]
    fn test_schema_template_display_enum() {
        let schema = Type::Enum(Vec::from([(
            String::from("Accounts"),
            Fields::Unnamed(Vec::from([Type::AccountAddress])),
        )]));
        assert_eq!(
            json!({"Enum": [{"Accounts": ["<AccountAddress>"]}]}),
            schema.to_json_template()
        );
    }

    /// Tests schema template display in JSON of an TaggedEnum
    #[test]
    fn test_schema_template_display_tagged_enum() {
        let mut map = BTreeMap::new();
        map.insert(
            8,
            (
                String::from("Accounts"),
                Fields::Named(Vec::from([(String::from("Account"), Type::AccountAddress)])),
            ),
        );

        let schema = Type::TaggedEnum(map);
        assert_eq!(
            json!({"Enum": [{"Accounts":{"Account":"<AccountAddress>"}}]}),
            schema.to_json_template()
        );
    }

    /// Tests schema template display in JSON of a Duration
    #[test]
    fn test_schema_template_display_duration() {
        let schema = Type::Duration;
        assert_eq!(json!("<Duration (e.g. `10d 1h 42s`)>"), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a Timestamp
    #[test]
    fn test_schema_template_display_timestamp() {
        let schema = Type::Timestamp;
        assert_eq!(json!("<Timestamp (e.g. `2000-01-01T12:00:00Z`)>"), schema.to_json_template());
    }

    /// Tests schema template display in JSON of an Struct with Field `None`
    #[test]
    fn test_schema_template_display_struct_with_none_field() {
        let schema = Type::Struct(Fields::None);
        assert_eq!(json!([]), schema.to_json_template());
    }

    /// Tests schema template display in JSON of an Struct with named Fields
    #[test]
    fn test_schema_template_display_struct_with_named_fields() {
        let schema = Type::Struct(Fields::Named(Vec::from([(
            String::from("Account"),
            Type::AccountAddress,
        )])));
        assert_eq!(json!({"Account":"<AccountAddress>"}), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a ContractName
    #[test]
    fn test_schema_template_display_contract_name() {
        let schema = Type::ContractName(schema_json::SizeLength::U8);
        assert_eq!(json!({"contract":"<String>"}), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a ReceiveName
    #[test]
    fn test_schema_template_display_receive_name() {
        let schema = Type::ReceiveName(schema_json::SizeLength::U8);
        assert_eq!(json!({"contract":"<String>","func":"<String>"}), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a Map
    #[test]
    fn test_schema_template_display_map() {
        let schema = Type::Map(
            schema_json::SizeLength::U8,
            Box::new(Type::U8),
            Box::new(Type::AccountAddress),
        );
        assert_eq!(json!([["<UInt8>", "<AccountAddress>"]]), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a Set
    #[test]
    fn test_schema_template_display_set() {
        let schema = Type::Set(schema_json::SizeLength::U8, Box::new(Type::U8));
        assert_eq!(json!(["<UInt8>"]), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a List
    #[test]
    fn test_schema_template_display_list() {
        let schema = Type::List(schema_json::SizeLength::U8, Box::new(Type::U8));
        assert_eq!(json!(["<UInt8>"]), schema.to_json_template());
    }

    /// Tests schema template display in JSON of an Array
    #[test]
    fn test_schema_template_display_array() {
        let schema = Type::Array(4, Box::new(Type::U8));
        assert_eq!(json!(["<UInt8>", "<UInt8>", "<UInt8>", "<UInt8>"]), schema.to_json_template());
    }

    /// Tests schema template display in JSON of a Pair
    #[test]
    fn test_schema_template_display_pair() {
        let schema = Type::Pair(Box::new(Type::AccountAddress), Box::new(Type::U8));
        assert_eq!(json!(("<AccountAddress>", "<UInt8>")), schema.to_json_template());
    }

    /// Tests schema template display in JSON of an ContractAddress
    #[test]
    fn test_schema_template_display_contract_address() {
        let schema = Type::ContractAddress;
        assert_eq!(
            json!({"index":"<UInt64>",
            "subindex":"<UInt64>"}),
            schema.to_json_template()
        );
    }

    /// Tests schema template display in JSON of a Unit
    #[test]
    fn test_schema_template_display_unit() {
        let schema = Type::Unit;
        assert_eq!(json!([]), schema.to_json_template());
    }

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

    /// Tests that attempting to serialize a valid byte sequence as
    /// [`Type::AccountAddress`] succeeds.
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

    /// Tests that attempting to serialize an invalid byte sequence as
    /// [`Type::AccountAddress`] fails with expected error type.
    #[test]
    fn test_serial_account_address_wrong_address_fails() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let account = AccountAddress(account_bytes.clone());
        let schema = Type::AccountAddress;
        let json = json!(format!("{}", &account).get(1..));
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(err, JsonError::FailedParsingAccountAddress))
    }

    /// Tests that attempting to serialize a non-[`AccountAddress`] value with
    /// [`Type::AccountAddress`] schema results in error of expected type.
    #[test]
    fn test_serial_account_wrong_type_fails() {
        let schema = Type::AccountAddress;
        let json = json!(123);
        let err = schema.serial_value(&json).expect_err("Serializing should fail");

        assert!(matches!(err, JsonError::WrongJsonType(_)))
    }

    /// Tests that attempting to serialize a malformed value wrapped in a
    /// [`Type::List`] results in a nested error with trace information in the
    /// wrapping layer.
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

    /// Tests that attempting to serialize a malformed value wrapped in a
    /// [`Type::Struct`] results in a nested error with trace information in the
    /// wrapping layer.
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

    /// Tests that attempting to serialize a malformed value wrapped in multiple
    /// layers results in a nested error with trace information in the
    /// wrapping layers.
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
                *error.clone(),
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

    /// Tests that attempting to deserialize a valid byte sequence using
    /// [`Type::AccountAddress`] succeeds and results in the expected JSON
    /// format.
    #[test]
    fn test_deserial_account_address() {
        let account_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
        let mut cursor = Cursor::new(&account_bytes);
        let schema = Type::AccountAddress;
        let value = schema.to_json(&mut cursor).expect("Deserializing should not fail");

        let expected = json!(format!("{}", AccountAddress(account_bytes)));
        assert_eq!(expected, value)
    }

    /// Tests that attempting to deserialize a non-[`AccountAddress`] value with
    /// [`Type::AccountAddress`] schema results in an error of expected format.
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

    /// Tests that attempting to deserialize a malformed value wrapped in a
    /// [`Type::List`] fails with a nested error.
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

    /// Tests that attempting to deserialize a malformed value wrapped in
    /// multiple layers fails with a nested error with wrapping layers
    /// corresponding to the layers wrapping the malformed value.
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
                *error.clone(),
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
    pub fn to_json<T: AsRef<[u8]>>(
        &self,
        source: &mut Cursor<T>,
    ) -> Result<serde_json::Value, ToJsonError> {
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
            Fields::None => Ok(Value::Array(Vec::new())),
        }
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(_: std::string::FromUtf8Error) -> Self { ParseError::default() }
}

/// Deserialize a list of values corresponding to the `item_to_json` function
/// from `source`
fn item_list_to_json<T: AsRef<[u8]>>(
    source: &mut Cursor<T>,
    size_len: SizeLength,
    item_to_json: impl Fn(&mut Cursor<T>) -> Result<serde_json::Value, ToJsonError>,
    schema: &Type,
) -> Result<Vec<serde_json::Value>, ToJsonError> {
    let data = source.data.as_ref().to_owned().into();
    let position = source.cursor_position();
    let len = deserial_length(source, size_len).map_err(|_| ToJsonError::DeserialError {
        data,
        position,
        reason: "Could not deserialize length of list".into(),
        schema: schema.clone(),
    })?;
    let mut values = Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));
    for _ in 0..len {
        let value = item_to_json(source)?;
        values.push(value);
    }
    Ok(values)
}

/// Deserialize a [`String`] of variable length from `source`.
fn deserial_string<R: Read>(
    source: &mut R,
    size_len: SizeLength,
) -> Result<String, ParseErrorWithReason> {
    let len = deserial_length(source, size_len)
        .map_err(|_| ParseErrorWithReason("Could not parse String length".into()))?;
    // we are doing this case analysis so that we have a fast path for safe,
    // most common, lengths, and a slower one longer ones.
    if len <= MAX_PREALLOCATED_CAPACITY {
        let mut bytes = vec![0u8; len];
        source.read_exact(&mut bytes).map_err(|_| {
            ParseErrorWithReason(format!(
                "Parsed length {} for String value, but failed to read {} bytes from value",
                len, len
            ))
        })?;
        Ok(String::from_utf8(bytes)
            .map_err(|_| ParseErrorWithReason("Failed to deserialize String from value".into()))?)
    } else {
        let mut bytes: Vec<u8> = Vec::with_capacity(MAX_PREALLOCATED_CAPACITY);
        let mut buf = [0u8; 64];
        let mut read = 0;
        while read < len {
            let new = source.read(&mut buf).map_err(|_| {
                let end = std::cmp::min(len - read, 64);
                ParseErrorWithReason(format!(
                    "Parsed length {} for String value, but failed to read bytes {}..{} from value",
                    len,
                    read,
                    read + end
                ))
            })?;
            if new == 0 {
                break;
            } else {
                read += new;
                bytes.extend_from_slice(&buf[..new]);
            }
        }
        if read == len {
            Ok(String::from_utf8(bytes).map_err(|_| {
                ParseErrorWithReason("Failed to deserialize String from value".into())
            })?)
        } else {
            Err(ParseErrorWithReason(format!(
                "Parsed length {} for String value, but unexpectedly read {} bytes",
                len, read
            )))
        }
    }
}

impl Type {
    /// Uses the schema to deserialize bytes into pretty json
    pub fn to_json_string_pretty(&self, bytes: &[u8]) -> Result<String, ToJsonError> {
        let source = &mut Cursor::new(bytes);
        let js = self.to_json(source)?;
        serde_json::to_string_pretty(&js).map_err(|_| ToJsonError::FormatError {})
    }

    /// Uses the schema to deserialize bytes into json
    pub fn to_json<T: AsRef<[u8]>>(
        &self,
        source: &mut Cursor<T>,
    ) -> Result<serde_json::Value, ToJsonError> {
        use serde_json::*;

        let data = source.data.as_ref().to_owned().into();
        let position = source.cursor_position();

        let deserial_error = |reason: String| ToJsonError::DeserialError {
            data,
            position,
            reason,
            schema: self.clone(),
        };

        match self {
            Type::Unit => Ok(Value::Null),
            Type::Bool => {
                let n = bool::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse bool from value, expected a byte containing the value 0 \
                         or 1"
                            .into(),
                    )
                })?;
                Ok(Value::Bool(n))
            }
            Type::U8 => {
                let n = u8::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse u8 from value as not enough data was available (needs 1 \
                         byte)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::U16 => {
                let n = u16::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse u16 from value as not enough data was available (needs 2 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::U32 => {
                let n = u32::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse u32 from value as not enough data was available (needs 4 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::U64 => {
                let n = u64::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse u64 from value as not enough data was available (needs 8 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::U128 => {
                let n = u128::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse u128 from value as not enough data was available (needs \
                         16 bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::String(n.to_string()))
            }
            Type::I8 => {
                let n = i8::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse i8 from value as not enough data was available (needs 1 \
                         byte)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::I16 => {
                let n = i16::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse i16 from value as not enough data was available (needs 2 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::I32 => {
                let n = i32::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse i32 from value as not enough data was available (needs 4 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::I64 => {
                let n = i64::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse i64 from value as not enough data was available (needs 8 \
                         bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::Number(n.into()))
            }
            Type::I128 => {
                let n = i128::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse i128 from value as not enough data was available (needs \
                         16 bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::String(n.to_string()))
            }
            Type::Amount => {
                let n = Amount::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse Amount from value as not enough data was available \
                         (needs 8 bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::String(n.micro_ccd().to_string()))
            }
            Type::AccountAddress => {
                let address = AccountAddress::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse AccountAddress from value as not enough data was \
                         available (needs 32 bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::String(address.to_string()))
            }
            Type::ContractAddress => {
                let address = ContractAddress::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse ContractAddress from value as not enough data was \
                         available (needs 16 bytes)"
                            .into(),
                    )
                })?;
                Ok(serde_json::to_value(address).map_err(|_| ToJsonError::FormatError {})?)
            }
            Type::Timestamp => {
                let timestamp = Timestamp::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse Timestamp from value as not enough data was available \
                         (needs 8 bytes)"
                            .into(),
                    )
                })?;
                Ok(Value::String(timestamp.to_string()))
            }
            Type::Duration => {
                let duration = Duration::deserial(source).map_err(|_| {
                    deserial_error(
                        "Could not parse Duration from value as not enough data was available \
                         (needs 8 bytes)"
                            .into(),
                    )
                })?;
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
                let len: usize = (*len).try_into().map_err(|_| {
                    deserial_error("Could not parse Array length from value".into())
                })?;
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
                    u8::deserial(source).map(|v| v as usize).map_err(|_| {
                        ParseErrorWithReason(
                            "Could not parse Enum id as u8 from value (needs 1 byte)".into(),
                        )
                    })
                } else {
                    u16::deserial(source).map(|v| v as usize).map_err(|_| {
                        ParseErrorWithReason(
                            "Could not parse Enum id as u16 from value (needs 2 bytes)".into(),
                        )
                    })
                };
                let variant = idx.and_then(|idx| {
                    variants.get(idx).ok_or_else(|| {
                        ParseErrorWithReason(format!("Could not find Enum variant with id {}", idx))
                    })
                });

                // Map all error cases into the same error.
                match variant {
                    Ok((name, fields_ty)) => {
                        let fields =
                            fields_ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                        Ok(json!({ name: fields }))
                    }
                    Err(e) => Err(deserial_error(e.0)),
                }
            }
            Type::TaggedEnum(variants) => {
                let idx = u8::deserial(source).map_err(|_| {
                    ParseErrorWithReason(
                        "Could not parse TaggedEnum id from value (needs 1 byte)".into(),
                    )
                });
                let variant = idx.and_then(|idx| {
                    variants.get(&idx).ok_or_else(|| {
                        ParseErrorWithReason(format!(
                            "Could not find TaggedEnum variant with id {}",
                            idx
                        ))
                    })
                });

                match variant {
                    Ok((name, fields_ty)) => {
                        let fields =
                            fields_ty.to_json(source).map_err(|e| e.add_trace(position, self))?;
                        Ok(json!({ name: fields }))
                    }
                    Err(e) => Err(deserial_error(e.0)),
                }
            }
            Type::String(size_len) => {
                let string = deserial_string(source, *size_len).map_err(|e| deserial_error(e.0))?;
                Ok(Value::String(string))
            }
            Type::ContractName(size_len) => {
                let name = deserial_string(source, *size_len).map_err(|e| {
                    ParseErrorWithReason(format!(
                        "Could not parse contract name from value ({})",
                        e
                    ))
                });
                let owned_contract_name = name.and_then(|n| {
                    OwnedContractName::new(n)
                        .map_err(|e| ParseErrorWithReason(format!("Invalid contract name ({})", e)))
                });

                owned_contract_name
                    .map(|ocn| {
                        let name_without_init = ocn.as_contract_name().contract_name();
                        json!({ "contract": name_without_init })
                    })
                    .map_err(|e| deserial_error(e.0))
            }
            Type::ReceiveName(size_len) => {
                let name = deserial_string(source, *size_len).map_err(|e| {
                    ParseErrorWithReason(format!("Could not parse receive name from value ({})", e))
                });
                let owned_receive_name = name.and_then(|n| {
                    OwnedReceiveName::new(n)
                        .map_err(|e| ParseErrorWithReason(format!("Invalid receive name ({})", e)))
                });

                owned_receive_name
                    .map(|orn| {
                        let receive_name = orn.as_receive_name();
                        let contract_name = receive_name.contract_name();
                        let func_name = receive_name.entrypoint_name();
                        json!({"contract": contract_name, "func": func_name})
                    })
                    .map_err(|e| deserial_error(e.0))
            }
            Type::ULeb128(constraint) => {
                let int = deserial_biguint(source, *constraint).map_err(|_| {
                    deserial_error("Could not parse unsigned integer (uleb128) from value".into())
                })?;
                Ok(Value::String(int.to_string()))
            }
            Type::ILeb128(constraint) => {
                let int = deserial_bigint(source, *constraint).map_err(|_| {
                    deserial_error("Could not parse signed integer (leb128) from value".into())
                })?;
                Ok(Value::String(int.to_string()))
            }
            Type::ByteList(size_len) => {
                let len = deserial_length(source, *size_len).map_err(|_| {
                    ParseErrorWithReason("Could not parse ByteList length from value".into())
                });
                let bytes: core::result::Result<Vec<_>, _> =
                    len.as_ref().map_err(|e| e.clone()).and_then(|len| {
                        let mut bytes =
                            Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, *len));

                        for i in 0..*len {
                            let byte = source.read_u8().map_err(|_| {
                                ParseErrorWithReason(format!(
                                    "Failed to read byte {} of ByteList value",
                                    i
                                ))
                            });
                            bytes.push(byte);
                        }

                        bytes.into_iter().collect()
                    });

                match (len, bytes) {
                    (Ok(len), Ok(bytes)) => {
                        let mut string = String::with_capacity(std::cmp::min(
                            MAX_PREALLOCATED_CAPACITY,
                            2 * len,
                        ));
                        string.push_str(&hex::encode(bytes));
                        Ok(Value::String(string))
                    }
                    (Err(e), _) => Err(deserial_error(e.0)),
                    (_, Err(e)) => Err(deserial_error(e.0)),
                }
            }
            Type::ByteArray(len) => {
                let len = usize::try_from(*len).map_err(|_| {
                    ParseErrorWithReason("Could not parse ByteArray length from value".into())
                });
                let bytes: core::result::Result<Vec<_>, _> =
                    len.as_ref().map_err(|e| e.clone()).and_then(|len| {
                        let mut bytes =
                            Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, *len));

                        for i in 0..*len {
                            let byte = source.read_u8().map_err(|_| {
                                ParseErrorWithReason(format!(
                                    "Failed to read byte {} of ByteArray value",
                                    i
                                ))
                            });
                            bytes.push(byte);
                        }

                        bytes.into_iter().collect()
                    });

                match (len, bytes) {
                    (Ok(len), Ok(bytes)) => {
                        let mut string = String::with_capacity(std::cmp::min(
                            MAX_PREALLOCATED_CAPACITY,
                            2 * len,
                        ));
                        string.push_str(&hex::encode(bytes));
                        Ok(Value::String(string))
                    }
                    (Err(e), _) => Err(deserial_error(e.0)),
                    (_, Err(e)) => Err(deserial_error(e.0)),
                }
            }
        }
    }
}

/// Deserialize a uleb128 encoded [`BigUint`] from `source`.
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

/// Deserialize a ileb128 encoded [`BigInt`] from `source`.
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
