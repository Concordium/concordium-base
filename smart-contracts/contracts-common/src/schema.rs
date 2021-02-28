//! Types related to contract schemas.
//! These are optional annotations in modules that allow
//! the users of smart contracts to interact with them in
//! a way that is better than constructing raw bytes as parameters.

use crate::{impls::*, traits::*, types::*};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{collections::*, string::String, vec::Vec};
/// Contract schema related types
#[cfg(feature = "std")]
use std::collections::*;
#[cfg(feature = "derive-serde")]
use std::convert::TryInto;

/// The `SchemaType` trait provides means to generate a schema for structures.
/// Schemas are used to make structures human readable and to avoid dealing
/// directly with bytes, such as the contract state or parameters for contract
/// interaction.
///
/// Can be derived using `#[derive(SchemaType)]` for most cases of structs and
/// enums.
pub trait SchemaType {
    fn get_type() -> crate::schema::Type;
}

/// Contains all the contract schemas for a module
#[derive(Debug, Clone)]
pub struct Module {
    pub contracts: BTreeMap<String, Contract>,
}

/// Describes all the schemas of a smart contract.
#[derive(Debug, Clone)]
pub struct Contract {
    pub state:   Option<Type>,
    pub init:    Option<Type>,
    pub receive: BTreeMap<String, Type>,
}

impl Contract {
    pub fn empty() -> Contract {
        Contract {
            state:   None,
            init:    None,
            receive: BTreeMap::new(),
        }
    }
}

/// Schema for the fields of a struct or some enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum Fields {
    /// Named fields, e.g., `struct Foo {x: u64, y: u32}`.
    Named(Vec<(String, Type)>),
    /// Unnamed fields, e.g., `struct Foo(u64, u32)`
    Unnamed(Vec<Type>),
    /// No fields. Note that this is distinct from an empty set of named or
    /// unnamed fields. That is, in Rust there is a (albeit trivial) difference
    /// between `struct Foo {}`, `struct Foo`, and `struct Foo()`, all of which
    /// are valid, but will have different representations.
    None,
}

// TODO: Extend with LEB128
/// Type of the variable used to encode the length of Sets, List, Maps
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum SizeLength {
    U8,
    U16,
    U32,
    U64,
}

/// Schema type used to describe the different types in a rust smart
/// contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum Type {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Amount,
    AccountAddress,
    ContractAddress,
    Timestamp,
    Duration,
    Pair(Box<Type>, Box<Type>),
    List(SizeLength, Box<Type>),
    Set(SizeLength, Box<Type>),
    Map(SizeLength, Box<Type>, Box<Type>),
    Array(u32, Box<Type>),
    Struct(Fields),
    Enum(Vec<(String, Fields)>),
    String(SizeLength),
}

impl Type {
    #[doc(hidden)]
    /// Sets the size_length of schema types, with variable size otherwise
    /// it is a noop. Used when deriving SchemaType.
    pub fn set_size_length(self, size_len: SizeLength) -> Type {
        match self {
            Type::List(_, ty) => Type::List(size_len, ty),
            Type::Set(_, ty) => Type::Set(size_len, ty),
            Type::Map(_, key_ty, val_ty) => Type::Map(size_len, key_ty, val_ty),
            Type::String(_) => Type::String(size_len),
            t => t,
        }
    }
}

impl SchemaType for () {
    fn get_type() -> Type { Type::Unit }
}
impl SchemaType for bool {
    fn get_type() -> Type { Type::Bool }
}
impl SchemaType for u8 {
    fn get_type() -> Type { Type::U8 }
}
impl SchemaType for u16 {
    fn get_type() -> Type { Type::U16 }
}
impl SchemaType for u32 {
    fn get_type() -> Type { Type::U32 }
}
impl SchemaType for u64 {
    fn get_type() -> Type { Type::U64 }
}
impl SchemaType for i8 {
    fn get_type() -> Type { Type::I8 }
}
impl SchemaType for i16 {
    fn get_type() -> Type { Type::I16 }
}
impl SchemaType for i32 {
    fn get_type() -> Type { Type::I32 }
}
impl SchemaType for i64 {
    fn get_type() -> Type { Type::I64 }
}
impl SchemaType for Amount {
    fn get_type() -> Type { Type::Amount }
}
impl SchemaType for AccountAddress {
    fn get_type() -> Type { Type::AccountAddress }
}
impl SchemaType for ContractAddress {
    fn get_type() -> Type { Type::ContractAddress }
}
impl SchemaType for Timestamp {
    fn get_type() -> Type { Type::Timestamp }
}
impl SchemaType for Duration {
    fn get_type() -> Type { Type::Duration }
}
impl<T: SchemaType> SchemaType for Option<T> {
    fn get_type() -> Type {
        Type::Enum(Vec::from([
            (String::from("None"), Fields::None),
            (String::from("Some"), Fields::Unnamed(Vec::from([T::get_type()]))),
        ]))
    }
}
impl<L: SchemaType, R: SchemaType> SchemaType for (L, R) {
    fn get_type() -> Type { Type::Pair(Box::new(L::get_type()), Box::new(R::get_type())) }
}
impl<T: SchemaType> SchemaType for Vec<T> {
    fn get_type() -> Type { Type::List(SizeLength::U32, Box::new(T::get_type())) }
}
impl<T: SchemaType> SchemaType for BTreeSet<T> {
    fn get_type() -> Type { Type::Set(SizeLength::U32, Box::new(T::get_type())) }
}
impl<K: SchemaType, V: SchemaType> SchemaType for BTreeMap<K, V> {
    fn get_type() -> Type {
        Type::Map(SizeLength::U32, Box::new(K::get_type()), Box::new(V::get_type()))
    }
}
impl SchemaType for [u8] {
    fn get_type() -> Type { Type::List(SizeLength::U32, Box::new(Type::U8)) }
}

impl SchemaType for String {
    fn get_type() -> Type { Type::String(SizeLength::U32) }
}

macro_rules! schema_type_array_x {
    ($x:expr) => {
        impl<A: SchemaType> SchemaType for [A; $x] {
            fn get_type() -> Type { Type::Array($x, Box::new(A::get_type())) }
        }
    };
}

repeat_macro!(
    schema_type_array_x,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32
);

impl Serial for Fields {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Fields::Named(fields) => {
                out.write_u8(0)?;
                fields.serial(out)?;
            }
            Fields::Unnamed(fields) => {
                out.write_u8(1)?;
                fields.serial(out)?;
            }
            Fields::None => {
                out.write_u8(2)?;
            }
        }
        Ok(())
    }
}

impl Deserial for Fields {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(Fields::Named(source.get()?)),
            1 => Ok(Fields::Unnamed(source.get()?)),
            2 => Ok(Fields::None),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for Module {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.contracts.serial(out)?;
        Ok(())
    }
}

impl Deserial for Module {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        let contracts = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(Module {
            contracts,
        })
    }
}

impl Serial for Contract {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.state.serial(out)?;
        self.init.serial(out)?;
        self.receive.serial(out)?;
        Ok(())
    }
}

impl Deserial for Contract {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let state = source.get()?;
        let init = source.get()?;
        let len: u32 = source.get()?;
        let receive = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(Contract {
            state,
            init,
            receive,
        })
    }
}

impl Serial for SizeLength {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            SizeLength::U8 => out.write_u8(0)?,
            SizeLength::U16 => out.write_u8(1)?,
            SizeLength::U32 => out.write_u8(2)?,
            SizeLength::U64 => out.write_u8(3)?,
        }
        Ok(())
    }
}

impl Deserial for SizeLength {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(SizeLength::U8),
            1 => Ok(SizeLength::U16),
            2 => Ok(SizeLength::U32),
            3 => Ok(SizeLength::U64),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for Type {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Type::Unit => {
                out.write_u8(0)?;
            }
            Type::Bool => {
                out.write_u8(1)?;
            }
            Type::U8 => {
                out.write_u8(2)?;
            }
            Type::U16 => {
                out.write_u8(3)?;
            }
            Type::U32 => {
                out.write_u8(4)?;
            }
            Type::U64 => {
                out.write_u8(5)?;
            }
            Type::I8 => {
                out.write_u8(6)?;
            }
            Type::I16 => {
                out.write_u8(7)?;
            }
            Type::I32 => {
                out.write_u8(8)?;
            }
            Type::I64 => {
                out.write_u8(9)?;
            }
            Type::Amount => {
                out.write_u8(10)?;
            }
            Type::AccountAddress => {
                out.write_u8(11)?;
            }
            Type::ContractAddress => {
                out.write_u8(12)?;
            }
            Type::Timestamp => {
                out.write_u8(13)?;
            }
            Type::Duration => {
                out.write_u8(14)?;
            }
            Type::Pair(left, right) => {
                out.write_u8(15)?;
                left.serial(out)?;
                right.serial(out)?;
            }
            Type::List(len_size, ty) => {
                out.write_u8(16)?;
                len_size.serial(out)?;
                ty.serial(out)?;
            }
            Type::Set(len_size, ty) => {
                out.write_u8(17)?;
                len_size.serial(out)?;
                ty.serial(out)?;
            }
            Type::Map(len_size, key, value) => {
                out.write_u8(18)?;
                len_size.serial(out)?;
                key.serial(out)?;
                value.serial(out)?;
            }
            Type::Array(len, ty) => {
                out.write_u8(19)?;
                len.serial(out)?;
                ty.serial(out)?;
            }
            Type::Struct(fields) => {
                out.write_u8(20)?;
                fields.serial(out)?;
            }
            Type::Enum(fields) => {
                out.write_u8(21)?;
                fields.serial(out)?;
            }
            Type::String(len) => {
                out.write_u8(22)?;
                len.serial(out)?;
            }
        }
        Ok(())
    }
}

impl Deserial for Type {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(Type::Unit),
            1 => Ok(Type::Bool),
            2 => Ok(Type::U8),
            3 => Ok(Type::U16),
            4 => Ok(Type::U32),
            5 => Ok(Type::U64),
            6 => Ok(Type::I8),
            7 => Ok(Type::I16),
            8 => Ok(Type::I32),
            9 => Ok(Type::I64),
            10 => Ok(Type::Amount),
            11 => Ok(Type::AccountAddress),
            12 => Ok(Type::ContractAddress),
            13 => Ok(Type::Timestamp),
            14 => Ok(Type::Duration),
            15 => {
                let left = Type::deserial(source)?;
                let right = Type::deserial(source)?;
                Ok(Type::Pair(Box::new(left), Box::new(right)))
            }
            16 => {
                let len_size = SizeLength::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::List(len_size, Box::new(ty)))
            }
            17 => {
                let len_size = SizeLength::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::Set(len_size, Box::new(ty)))
            }
            18 => {
                let len_size = SizeLength::deserial(source)?;
                let key = Type::deserial(source)?;
                let value = Type::deserial(source)?;
                Ok(Type::Map(len_size, Box::new(key), Box::new(value)))
            }
            19 => {
                let len = u32::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::Array(len, Box::new(ty)))
            }
            20 => {
                let fields = source.get()?;
                Ok(Type::Struct(fields))
            }
            21 => {
                let variants = source.get()?;
                Ok(Type::Enum(variants))
            }
            22 => {
                let size_len = SizeLength::deserial(source)?;
                Ok(Type::String(size_len))
            }
            _ => Err(ParseError::default()),
        }
    }
}

#[cfg(feature = "derive-serde")]
mod impls {
    use super::*;
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

    impl From<std::num::TryFromIntError> for ParseError {
        fn from(_: std::num::TryFromIntError) -> Self { ParseError::default() }
    }

    impl From<std::string::FromUtf8Error> for ParseError {
        fn from(_: std::string::FromUtf8Error) -> Self { ParseError::default() }
    }

    fn deserial_length(source: &mut impl Read, size_len: &SizeLength) -> ParseResult<usize> {
        let len: usize = match size_len {
            SizeLength::U8 => u8::deserial(source)?.into(),
            SizeLength::U16 => u16::deserial(source)?.into(),
            SizeLength::U32 => u32::deserial(source)?.try_into()?,
            SizeLength::U64 => u64::deserial(source)?.try_into()?,
        };
        Ok(len)
    }

    fn item_list_to_json<R: Read>(
        source: &mut R,
        size_len: &SizeLength,
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
                Type::Amount => {
                    let n = Amount::deserial(source)?;
                    Ok(Value::String(n.micro_gtu.to_string()))
                }
                Type::AccountAddress => {
                    let address = AccountAddress::deserial(source)?;
                    Ok(Value::String(address.to_string()))
                }
                Type::ContractAddress => {
                    let address = ContractAddress::deserial(source)?;
                    Ok(Value::String(address.to_string()))
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
                    let values = item_list_to_json(source, size_len, |s| ty.to_json(s))?;
                    Ok(Value::Array(values))
                }
                Type::Set(size_len, ty) => {
                    let values = item_list_to_json(source, size_len, |s| ty.to_json(s))?;
                    Ok(Value::Array(values))
                }
                Type::Map(size_len, key_type, value_type) => {
                    let values = item_list_to_json(source, size_len, |s| {
                        let key = key_type.to_json(s)?;
                        let value = value_type.to_json(s)?;
                        Ok(Value::Array(vec![key, value]))
                    })?;
                    Ok(Value::Array(values))
                }
                Type::Array(len, ty) => {
                    let len: usize = (*len).try_into()?;
                    let mut values =
                        Vec::with_capacity(std::cmp::min(MAX_PREALLOCATED_CAPACITY, len));
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
                        u32::deserial(source)? as usize
                    };
                    let (name, fields_ty) = variants.get(idx).ok_or_else(ParseError::default)?;
                    let fields = fields_ty.to_json(source)?;
                    Ok(json!({ name: fields }))
                }
                Type::String(size_len) => {
                    let len = deserial_length(source, size_len)?;
                    // we are doing this case analysis so that we have a fast path for safe,
                    // most common, lengths, and a slower one longer ones.
                    if len <= MAX_PREALLOCATED_CAPACITY {
                        let mut bytes = vec![0u8; len];
                        source.read_exact(&mut bytes)?;
                        let string = String::from_utf8(bytes)?;
                        Ok(Value::String(string))
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
                            let string = String::from_utf8(bytes)?;
                            Ok(Value::String(string))
                        } else {
                            Err(ParseError {})
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::*;

    #[test]
    fn test_schema_serial_deserial_is_id() {
        use rand::prelude::*;
        use rand_pcg::Pcg64;

        let seed: u64 = random();
        let mut rng = Pcg64::seed_from_u64(seed);
        println!("Seed {}", seed);
        let mut data = [0u8; 100000];
        rng.fill_bytes(&mut data);

        let mut unstructured = Unstructured::new(&data);

        for _ in 0..10000 {
            let schema = Type::arbitrary(&mut unstructured).unwrap();

            let res = from_bytes::<Type>(&to_bytes(&schema)).unwrap();
            assert_eq!(schema, res);
        }
    }
}
