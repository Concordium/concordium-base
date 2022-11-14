//! Types related to contract schemas.
//! These are optional annotations in modules that allow
//! the users of smart contracts to interact with them in
//! a way that is better than constructing raw bytes as parameters.

use crate::{impls::*, traits::*, types::*};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{collections, string::String, vec::Vec};
use collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use core::{
    convert::{TryFrom, TryInto},
    num::TryFromIntError,
};
/// Contract schema related types
#[cfg(feature = "std")]
use std::{
    collections,
    convert::{TryFrom, TryInto},
    num::TryFromIntError,
};

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

/// Contains all the contract schemas for a smart contract module V0.
///
/// Older versions of smart contracts might have this embedded in the custom
/// section labelled `concordium-schema-v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleV0 {
    pub contracts: BTreeMap<String, ContractV0>,
}

/// Contains all the contract schemas for a smart contract module V1.
///
/// Older versions of smart contracts might have this embedded in the custom
/// section labelled `concordium-schema-v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleV1 {
    pub contracts: BTreeMap<String, ContractV1>,
}

/// Contains all the contract schemas for a smart contract module V1 with a V2
/// schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleV2 {
    pub contracts: BTreeMap<String, ContractV2>,
}

/// Contains all the contract schemas for a smart contract module V1 with a V3
/// schema.
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleV3 {
    pub contracts: BTreeMap<String, ContractV3>,
}

/// Represents the different schema versions.
///
/// The serialization of this type includes the versioning information. The
/// serialization of this is always prefixed with two 255u8 in order to
/// distinguish this versioned schema from the unversioned.
///
/// When embedded into a smart contract module, name the custom section
/// `concordium-schema`.
#[derive(Debug, Clone)]
pub enum VersionedModuleSchema {
    /// Version 0 schema, only supported by V0 smart contracts.
    V0(ModuleV0),
    /// Version 1 schema, only supported by V1 smart contracts.
    V1(ModuleV1),
    /// Version 2 schema, only supported by V1 smart contracts.
    V2(ModuleV2),
    /// Version 3 schema, only supported by V1 smart contracts.
    V3(ModuleV3),
}

/// Describes all the schemas of a V0 smart contract.
/// The [`Default`] instance produces an empty schema.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ContractV0 {
    pub state:   Option<Type>,
    pub init:    Option<Type>,
    pub receive: BTreeMap<String, Type>,
}

/// Describes all the schemas of a V1 smart contract.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// The [`Default`] instance produces an empty schema.
pub struct ContractV1 {
    pub init:    Option<FunctionV1>,
    pub receive: BTreeMap<String, FunctionV1>,
}

/// Describes all the schemas of a V1 smart contract with a V2 schema.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// The [`Default`] instance produces an empty schema.
pub struct ContractV2 {
    pub init:    Option<FunctionV2>,
    pub receive: BTreeMap<String, FunctionV2>,
}

/// Describes all the schemas of a V1 smart contract with a V3 schema.
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// The [`Default`] instance produces an empty schema.
pub struct ContractV3 {
    pub init:    Option<FunctionV2>,
    pub receive: BTreeMap<String, FunctionV2>,
    pub event:   Option<Type>,
}

impl ContractV3 {
    /// Extract the event schema if it exists.
    pub fn event(&self) -> Option<&Type> { self.event.as_ref() }
}

/// Describes the schema of an init or a receive function for V1 contracts with
/// V1 schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionV1 {
    Parameter(Type),
    ReturnValue(Type),
    Both {
        parameter:    Type,
        return_value: Type,
    },
}

impl FunctionV1 {
    /// Extract the parameter schema if it exists.
    pub fn parameter(&self) -> Option<&Type> {
        match self {
            FunctionV1::Parameter(ty) => Some(ty),
            FunctionV1::ReturnValue(_) => None,
            FunctionV1::Both {
                parameter,
                ..
            } => Some(parameter),
        }
    }

    /// Extract the return value schema if it exists.
    pub fn return_value(&self) -> Option<&Type> {
        match self {
            FunctionV1::Parameter(_) => None,
            FunctionV1::ReturnValue(rv) => Some(rv),
            FunctionV1::Both {
                return_value,
                ..
            } => Some(return_value),
        }
    }
}

/// Describes the schema of an init or a receive function for V1 contracts with
/// V3 schemas. Differs from [`FunctionV1`] in that a schema for the error can
/// be included.
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionV2 {
    pub parameter:    Option<Type>,
    pub return_value: Option<Type>,
    pub error:        Option<Type>,
}

impl FunctionV2 {
    /// Extract the parameter schema if it exists.
    pub fn parameter(&self) -> Option<&Type> { self.parameter.as_ref() }

    /// Extract the return value schema if it exists.
    pub fn return_value(&self) -> Option<&Type> { self.return_value.as_ref() }

    /// Extract the error schema if it exists.
    pub fn error(&self) -> Option<&Type> { self.error.as_ref() }
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

/// Type of the variable used to encode the length of Sets, List, Maps
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum SizeLength {
    U8,
    U16,
    U32,
    U64,
}

/// Schema type used to describe the different types in a smart contract, their
/// serialization and how to represent the types in JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum Type {
    /// A type with no serialization.
    Unit,
    /// Boolean. Serialized as a byte, where the value 0 is false and 1 is true.
    Bool,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer. Serialized as little endian.
    U16,
    /// Unsigned 32-bit integer. Serialized as little endian.
    U32,
    /// Unsigned 64-bit integer. Serialized as little endian.
    U64,
    /// Unsigned 128-bit integer. Serialized as little endian.
    U128,
    /// Signed 8-bit integer. Serialized as little endian.
    I8,
    /// Signed 16-bit integer. Serialized as little endian.
    I16,
    /// Signed 32-bit integer. Serialized as little endian.
    I32,
    /// Signed 64-bit integer. Serialized as little endian.
    I64,
    /// Signed 128-bit integer. Serialized as little endian.
    I128,
    /// An amount of CCD. Serialized as 64-bit unsigned integer little endian.
    Amount,
    /// An account address.
    AccountAddress,
    /// A contract address.
    ContractAddress,
    /// A timestamp. Represented as milliseconds since Unix epoch. Serialized as
    /// a 64-bit unsigned integer little endian.
    Timestamp,
    /// A duration of milliseconds, cannot be negative. Serialized as a 64-bit
    /// unsigned integer little endian.
    Duration,
    /// A pair.
    Pair(Box<Type>, Box<Type>),
    /// A list. It is serialized with the length first followed by the list
    /// items.
    List(SizeLength, Box<Type>),
    /// A Set. It is serialized with the length first followed by the list
    /// items.
    Set(SizeLength, Box<Type>),
    /// A Map. It is serialized with the length first followed by key-value
    /// pairs of the entries.
    Map(SizeLength, Box<Type>, Box<Type>),
    /// A fixed sized list.
    Array(u32, Box<Type>),
    /// A structure type with fields.
    Struct(Fields),
    /// A sum type.
    Enum(Vec<(String, Fields)>),
    /// A UTF8 String. It is serialized with the length first followed by the
    /// encoding of the string.
    String(SizeLength),
    /// A smart contract name. It is serialized with the length first followed
    /// by the ASCII encoding of the name.
    ContractName(SizeLength),
    /// A smart contract receive function name. It is serialized with the length
    /// first followed by the ASCII encoding of the name.
    ReceiveName(SizeLength),
    /// An unsigned integer encoded using LEB128 with the addition of a
    /// constraint on the maximum number of bytes to use for an encoding.
    ULeb128(u32),
    /// A signed integer encoded using LEB128 with the addition of a constraint
    /// on the maximum number of bytes to use for an encoding.
    ILeb128(u32),
    /// A list of bytes. It is serialized with the length first followed by the
    /// bytes.
    ByteList(SizeLength),
    /// A fixed sized list of bytes.
    ByteArray(u32),
    /// An enum with a tag.
    TaggedEnum(BTreeMap<u8, (String, Fields)>),
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
            Type::ByteList(_) => Type::ByteList(size_len),
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
impl SchemaType for u128 {
    fn get_type() -> Type { Type::U128 }
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
impl SchemaType for i128 {
    fn get_type() -> Type { Type::I128 }
}
impl SchemaType for Amount {
    fn get_type() -> Type { Type::Amount }
}
impl SchemaType for ModuleReference {
    fn get_type() -> Type { Type::ByteArray(32) }
}
impl SchemaType for AccountAddress {
    fn get_type() -> Type { Type::AccountAddress }
}
impl SchemaType for ContractAddress {
    fn get_type() -> Type { Type::ContractAddress }
}
impl SchemaType for Address {
    fn get_type() -> Type {
        Type::Enum(Vec::from([
            (String::from("Account"), Fields::Unnamed(Vec::from([Type::AccountAddress]))),
            (String::from("Contract"), Fields::Unnamed(Vec::from([Type::ContractAddress]))),
        ]))
    }
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
impl<T: SchemaType> SchemaType for HashSet<T> {
    fn get_type() -> Type { Type::Set(SizeLength::U32, Box::new(T::get_type())) }
}
impl<K: SchemaType, V: SchemaType> SchemaType for HashMap<K, V> {
    fn get_type() -> Type {
        Type::Map(SizeLength::U32, Box::new(K::get_type()), Box::new(V::get_type()))
    }
}
impl SchemaType for [u8] {
    fn get_type() -> Type { Type::ByteList(SizeLength::U32) }
}

impl SchemaType for String {
    fn get_type() -> Type { Type::String(SizeLength::U32) }
}

impl SchemaType for OwnedContractName {
    fn get_type() -> Type { Type::ContractName(SizeLength::U16) }
}

impl SchemaType for OwnedReceiveName {
    fn get_type() -> Type { Type::ReceiveName(SizeLength::U16) }
}

impl SchemaType for OwnedEntrypointName {
    fn get_type() -> Type { Type::String(SizeLength::U16) }
}

impl SchemaType for OwnedParameter {
    fn get_type() -> Type { Type::ByteList(SizeLength::U16) }
}

impl<A: SchemaType, const N: usize> SchemaType for [A; N] {
    fn get_type() -> Type { Type::Array(N.try_into().unwrap(), Box::new(A::get_type())) }
}

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

impl Serial for ModuleV0 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.contracts.serial(out)?;
        Ok(())
    }
}

impl Serial for ModuleV1 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.contracts.serial(out)?;
        Ok(())
    }
}

impl Serial for ModuleV2 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.contracts.serial(out)?;
        Ok(())
    }
}

impl Serial for ModuleV3 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.contracts.serial(out)?;
        Ok(())
    }
}

impl Serial for VersionedModuleSchema {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        // Prefix for versioned module schema, used to distinquish from the unversioned.
        out.write_u16(u16::MAX)?;
        match self {
            VersionedModuleSchema::V0(module) => {
                out.write_u8(0)?;
                module.serial(out)?;
            }
            VersionedModuleSchema::V1(module) => {
                out.write_u8(1)?;
                module.serial(out)?;
            }
            VersionedModuleSchema::V2(module) => {
                out.write_u8(2)?;
                module.serial(out)?;
            }
            VersionedModuleSchema::V3(module) => {
                out.write_u8(3)?;
                module.serial(out)?;
            }
        }
        Ok(())
    }
}

impl Deserial for ModuleV0 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        let contracts = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ModuleV0 {
            contracts,
        })
    }
}

impl Deserial for ModuleV1 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        let contracts = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ModuleV1 {
            contracts,
        })
    }
}

impl Deserial for ModuleV2 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        let contracts = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ModuleV2 {
            contracts,
        })
    }
}

impl Deserial for ModuleV3 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        let contracts = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ModuleV3 {
            contracts,
        })
    }
}

impl Deserial for VersionedModuleSchema {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        // First we ensure the prefix is correct.
        let prefix = source.read_u16()?;
        if prefix != u16::MAX {
            return Err(ParseError {});
        }
        let version = source.read_u8()?;
        match version {
            0 => {
                let module = source.get()?;
                Ok(VersionedModuleSchema::V0(module))
            }
            1 => {
                let module = source.get()?;
                Ok(VersionedModuleSchema::V1(module))
            }
            2 => {
                let module = source.get()?;
                Ok(VersionedModuleSchema::V2(module))
            }
            3 => {
                let module = source.get()?;
                Ok(VersionedModuleSchema::V3(module))
            }
            _ => Err(ParseError {}),
        }
    }
}

impl Serial for ContractV0 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.state.serial(out)?;
        self.init.serial(out)?;
        self.receive.serial(out)?;
        Ok(())
    }
}

impl Serial for ContractV1 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.init.serial(out)?;
        self.receive.serial(out)?;
        Ok(())
    }
}

impl Serial for ContractV2 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.init.serial(out)?;
        self.receive.serial(out)?;
        Ok(())
    }
}

impl Serial for ContractV3 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.init.serial(out)?;
        self.receive.serial(out)?;
        self.event.serial(out)?;
        Ok(())
    }
}

impl Deserial for ContractV0 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let state = source.get()?;
        let init = source.get()?;
        let len: u32 = source.get()?;
        let receive = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ContractV0 {
            state,
            init,
            receive,
        })
    }
}

impl Deserial for ContractV1 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let init = source.get()?;
        let len: u32 = source.get()?;
        let receive = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ContractV1 {
            init,
            receive,
        })
    }
}

impl Deserial for ContractV2 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let init = source.get()?;
        let len: u32 = source.get()?;
        let receive = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(ContractV2 {
            init,
            receive,
        })
    }
}

impl Deserial for ContractV3 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let init = source.get()?;
        let len: u32 = source.get()?;
        let receive = deserial_map_no_length_no_order_check(source, len as usize)?;
        let event = source.get()?;
        Ok(ContractV3 {
            init,
            receive,
            event,
        })
    }
}

impl Serial for FunctionV1 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            FunctionV1::Parameter(parameter) => {
                out.write_u8(0)?;
                parameter.serial(out)
            }
            FunctionV1::ReturnValue(return_value) => {
                out.write_u8(1)?;
                return_value.serial(out)
            }
            FunctionV1::Both {
                parameter,
                return_value,
            } => {
                out.write_u8(2)?;
                parameter.serial(out)?;
                return_value.serial(out)
            }
        }
    }
}

impl Deserial for FunctionV1 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(FunctionV1::Parameter(source.get()?)),
            1 => Ok(FunctionV1::ReturnValue(source.get()?)),
            2 => Ok(FunctionV1::Both {
                parameter:    source.get()?,
                return_value: source.get()?,
            }),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for FunctionV2 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let parameter = self.parameter.is_some();
        let return_value = self.return_value.is_some();
        let error = self.error.is_some();
        let tag: u8 = match (parameter, return_value, error) {
            // parameter
            (true, false, false) => 0,
            // return_value
            (false, true, false) => 1,
            // parameter + return_value
            (true, true, false) => 2,
            // error
            (false, false, true) => 3,
            // parameter + error
            (true, false, true) => 4,
            // return_value + error
            (false, true, true) => 5,
            // parameter + return_value + error
            (true, true, true) => 6,
            // no schema
            (false, false, false) => 7,
        };
        out.write_u8(tag)?;
        if let Some(p) = self.parameter.as_ref() {
            p.serial(out)?;
        }
        if let Some(rv) = self.return_value.as_ref() {
            rv.serial(out)?;
        }
        if let Some(err) = self.error.as_ref() {
            err.serial(out)?;
        }
        Ok(())
    }
}

impl Deserial for FunctionV2 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        let mut r = FunctionV2 {
            parameter:    None,
            return_value: None,
            error:        None,
        };
        if idx > 7 {
            return Err(ParseError::default());
        }
        if matches!(idx, 0 | 2 | 4 | 6) {
            let _ = r.parameter.insert(source.get()?);
        }
        if matches!(idx, 1 | 2 | 5 | 6) {
            let _ = r.return_value.insert(source.get()?);
        }
        if matches!(idx, 3 | 4 | 5 | 6) {
            let _ = r.error.insert(source.get()?);
        }
        Ok(r)
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
            Type::Unit => out.write_u8(0),
            Type::Bool => out.write_u8(1),
            Type::U8 => out.write_u8(2),
            Type::U16 => out.write_u8(3),
            Type::U32 => out.write_u8(4),
            Type::U64 => out.write_u8(5),
            Type::I8 => out.write_u8(6),
            Type::I16 => out.write_u8(7),
            Type::I32 => out.write_u8(8),
            Type::I64 => out.write_u8(9),
            Type::Amount => out.write_u8(10),
            Type::AccountAddress => out.write_u8(11),
            Type::ContractAddress => out.write_u8(12),
            Type::Timestamp => out.write_u8(13),
            Type::Duration => out.write_u8(14),
            Type::Pair(left, right) => {
                out.write_u8(15)?;
                left.serial(out)?;
                right.serial(out)
            }
            Type::List(len_size, ty) => {
                out.write_u8(16)?;
                len_size.serial(out)?;
                ty.serial(out)
            }
            Type::Set(len_size, ty) => {
                out.write_u8(17)?;
                len_size.serial(out)?;
                ty.serial(out)
            }
            Type::Map(len_size, key, value) => {
                out.write_u8(18)?;
                len_size.serial(out)?;
                key.serial(out)?;
                value.serial(out)
            }
            Type::Array(len, ty) => {
                out.write_u8(19)?;
                len.serial(out)?;
                ty.serial(out)
            }
            Type::Struct(fields) => {
                out.write_u8(20)?;
                fields.serial(out)
            }
            Type::Enum(fields) => {
                out.write_u8(21)?;
                fields.serial(out)
            }
            Type::String(len) => {
                out.write_u8(22)?;
                len.serial(out)
            }
            Type::U128 => out.write_u8(23),
            Type::I128 => out.write_u8(24),
            Type::ContractName(len_size) => {
                out.write_u8(25)?;
                len_size.serial(out)
            }
            Type::ReceiveName(len_size) => {
                out.write_u8(26)?;
                len_size.serial(out)
            }
            Type::ULeb128(constraint) => {
                out.write_u8(27)?;
                constraint.serial(out)
            }
            Type::ILeb128(constraint) => {
                out.write_u8(28)?;
                constraint.serial(out)
            }
            Type::ByteList(len_size) => {
                out.write_u8(29)?;
                len_size.serial(out)
            }
            Type::ByteArray(len) => {
                out.write_u8(30)?;
                len.serial(out)
            }
            Type::TaggedEnum(fields) => {
                out.write_u8(31)?;
                fields.serial(out)
            }
        }
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
                let len_size = SizeLength::deserial(source)?;
                Ok(Type::String(len_size))
            }
            23 => Ok(Type::U128),
            24 => Ok(Type::I128),
            25 => {
                let len_size = SizeLength::deserial(source)?;
                Ok(Type::ContractName(len_size))
            }
            26 => {
                let len_size = SizeLength::deserial(source)?;
                Ok(Type::ReceiveName(len_size))
            }
            27 => {
                let constraint = u32::deserial(source)?;
                Ok(Type::ULeb128(constraint))
            }
            28 => {
                let constraint = u32::deserial(source)?;
                Ok(Type::ILeb128(constraint))
            }
            29 => {
                let len_size = SizeLength::deserial(source)?;
                Ok(Type::ByteList(len_size))
            }
            30 => {
                let len = u32::deserial(source)?;
                Ok(Type::ByteArray(len))
            }
            31 => {
                let variants = source.get()?;
                Ok(Type::TaggedEnum(variants))
            }

            _ => Err(ParseError::default()),
        }
    }
}

impl From<TryFromIntError> for ParseError {
    fn from(_: TryFromIntError) -> Self { ParseError::default() }
}

/// Try to convert the `len` to the provided size and serialize it.
pub fn serial_length<W: Write>(
    len: usize,
    size_len: SizeLength,
    out: &mut W,
) -> Result<(), W::Err> {
    let to_w_err = |_| W::Err::default();
    match size_len {
        SizeLength::U8 => u8::try_from(len).map_err(to_w_err)?.serial(out)?,
        SizeLength::U16 => u16::try_from(len).map_err(to_w_err)?.serial(out)?,
        SizeLength::U32 => u32::try_from(len).map_err(to_w_err)?.serial(out)?,
        SizeLength::U64 => u64::try_from(len).map_err(to_w_err)?.serial(out)?,
    }
    Ok(())
}

/// Deserialize a length of provided size.
pub fn deserial_length(source: &mut impl Read, size_len: SizeLength) -> ParseResult<usize> {
    let len: usize = match size_len {
        SizeLength::U8 => u8::deserial(source)?.into(),
        SizeLength::U16 => u16::deserial(source)?.into(),
        SizeLength::U32 => u32::deserial(source)?.try_into()?,
        SizeLength::U64 => u64::deserial(source)?.try_into()?,
    };
    Ok(len)
}

// Versioned schema helpers
#[cfg(feature = "derive-serde")]
mod impls {
    use crate::{from_bytes, schema::*};

    /// Useful for get_versioned_contract_schema(), but it's not currently used
    /// as input or output to any function, so it isn't public.
    enum VersionedContractSchema {
        V0(ContractV0),
        V1(ContractV1),
        V2(ContractV2),
        V3(ContractV3),
    }

    #[derive(Debug, thiserror::Error, Clone, Copy)]
    pub enum VersionedSchemaError {
        #[error("Parse error")]
        ParseError,
        #[error("Missing Schema Version")]
        MissingSchemaVersion,
        #[error("Invalid Schema Version")]
        InvalidSchemaVersion,
        #[error("Unable to find contract schema in module schema")]
        NoContractInModule,
        #[error("Receive function schema not found in contract schema")]
        NoReceiveInContract,
        #[error("Init function schema not found in contract schema")]
        NoInitInContract,
        #[error("Receive function schema does not contain a parameter schema")]
        NoParamsInReceive,
        #[error("Init function schema does not contain a parameter schema")]
        NoParamsInInit,
        #[error("Receive function schema not found in contract schema")]
        NoErrorInReceive,
        #[error("Init function schema does not contain an error schema")]
        NoErrorInInit,
        #[error("Errors not supported for this module version")]
        ErrorNotSupported,
        #[error("Receive function schema has no return value schema")]
        NoReturnValueInReceive,
        #[error("Return values not supported for this module version")]
        ReturnValueNotSupported,
    }

    impl From<ParseError> for VersionedSchemaError {
        fn from(_: ParseError) -> Self { VersionedSchemaError::ParseError }
    }

    /// Unpacks a versioned contract schema from a versioned module schema
    fn get_versioned_contract_schema(
        versioned_module_schema: &VersionedModuleSchema,
        contract_name: &str,
    ) -> Result<VersionedContractSchema, VersionedSchemaError> {
        let versioned_contract_schema: VersionedContractSchema = match versioned_module_schema {
            VersionedModuleSchema::V0(module_schema) => {
                let contract_schema = module_schema
                    .contracts
                    .get(contract_name)
                    .ok_or(VersionedSchemaError::NoContractInModule)?
                    .clone();
                VersionedContractSchema::V0(contract_schema)
            }
            VersionedModuleSchema::V1(module_schema) => {
                let contract_schema = module_schema
                    .contracts
                    .get(contract_name)
                    .ok_or(VersionedSchemaError::NoContractInModule)?
                    .clone();
                VersionedContractSchema::V1(contract_schema)
            }
            VersionedModuleSchema::V2(module_schema) => {
                let contract_schema = module_schema
                    .contracts
                    .get(contract_name)
                    .ok_or(VersionedSchemaError::NoContractInModule)?
                    .clone();
                VersionedContractSchema::V2(contract_schema)
            }
            VersionedModuleSchema::V3(module_schema) => {
                let contract_schema = module_schema
                    .contracts
                    .get(contract_name)
                    .ok_or(VersionedSchemaError::NoContractInModule)?
                    .clone();
                VersionedContractSchema::V3(contract_schema)
            }
        };

        Ok(versioned_contract_schema)
    }

    impl VersionedModuleSchema {
        /// Get a versioned module schema. First reads header to see if the
        /// version can be discerned, otherwise tries using provided
        /// schema_version.
        pub fn new(
            schema_bytes: &[u8],
            schema_version: &Option<u8>,
        ) -> Result<Self, VersionedSchemaError> {
            let versioned_module_schema = match from_bytes::<VersionedModuleSchema>(schema_bytes) {
                Ok(versioned) => versioned,
                Err(_) => match schema_version {
                    Some(0) => VersionedModuleSchema::V0(from_bytes(schema_bytes)?),
                    Some(1) => VersionedModuleSchema::V1(from_bytes(schema_bytes)?),
                    Some(2) => VersionedModuleSchema::V2(from_bytes(schema_bytes)?),
                    Some(3) => VersionedModuleSchema::V3(from_bytes(schema_bytes)?),
                    Some(_) => return Err(VersionedSchemaError::InvalidSchemaVersion),
                    None => return Err(VersionedSchemaError::MissingSchemaVersion),
                },
            };
            Ok(versioned_module_schema)
        }

        /// Returns a receive function's parameter schema from a versioned
        /// module schema
        pub fn get_receive_param_schema(
            &self,
            contract_name: &str,
            function_name: &str,
        ) -> Result<Type, VersionedSchemaError> {
            let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
            let param_schema = match versioned_contract_schema {
                VersionedContractSchema::V0(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .clone(),
                VersionedContractSchema::V1(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInReceive)?
                    .clone(),
                VersionedContractSchema::V2(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInReceive)?
                    .clone(),
                VersionedContractSchema::V3(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInReceive)?
                    .clone(),
            };
            Ok(param_schema)
        }

        /// Returns an init function's parameter schema from a versioned module
        /// schema
        pub fn get_init_param_schema(
            &self,
            contract_name: &str,
        ) -> Result<Type, VersionedSchemaError> {
            let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
            let param_schema = match versioned_contract_schema {
                VersionedContractSchema::V0(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .clone(),
                VersionedContractSchema::V1(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInInit)?
                    .clone(),
                VersionedContractSchema::V2(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInInit)?
                    .clone(),
                VersionedContractSchema::V3(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .parameter()
                    .ok_or(VersionedSchemaError::NoParamsInInit)?
                    .clone(),
            };
            Ok(param_schema)
        }

        /// Returns a receive function's error schema from a versioned module
        /// schema
        pub fn get_receive_error_schema(
            &self,
            contract_name: &str,
            function_name: &str,
        ) -> Result<Type, VersionedSchemaError> {
            let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
            let param_schema = match versioned_contract_schema {
                VersionedContractSchema::V0(_) => {
                    return Err(VersionedSchemaError::ErrorNotSupported)
                }
                VersionedContractSchema::V1(_) => {
                    return Err(VersionedSchemaError::ErrorNotSupported)
                }
                VersionedContractSchema::V2(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .error()
                    .ok_or(VersionedSchemaError::NoErrorInReceive)?
                    .clone(),
                VersionedContractSchema::V3(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .error()
                    .ok_or(VersionedSchemaError::NoErrorInReceive)?
                    .clone(),
            };
            Ok(param_schema)
        }

        /// Returns an init function's error schema from a versioned module
        /// schema
        pub fn get_init_error_schema(
            &self,
            contract_name: &str,
        ) -> Result<Type, VersionedSchemaError> {
            let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
            let param_schema = match versioned_contract_schema {
                VersionedContractSchema::V0(_) => {
                    return Err(VersionedSchemaError::ErrorNotSupported)
                }
                VersionedContractSchema::V1(_) => {
                    return Err(VersionedSchemaError::ErrorNotSupported)
                }
                VersionedContractSchema::V2(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .error()
                    .ok_or(VersionedSchemaError::NoErrorInInit)?
                    .clone(),
                VersionedContractSchema::V3(contract_schema) => contract_schema
                    .init
                    .as_ref()
                    .ok_or(VersionedSchemaError::NoInitInContract)?
                    .error()
                    .ok_or(VersionedSchemaError::NoErrorInInit)?
                    .clone(),
            };
            Ok(param_schema)
        }

        /// Returns the return value schema from a versioned module schema.
        pub fn get_receive_return_value_schema(
            &self,
            contract_name: &str,
            function_name: &str,
        ) -> Result<Type, VersionedSchemaError> {
            let versioned_contract_schema = get_versioned_contract_schema(self, contract_name)?;
            let return_value_schema = match versioned_contract_schema {
                VersionedContractSchema::V0(_) => {
                    return Err(VersionedSchemaError::ReturnValueNotSupported)
                }
                VersionedContractSchema::V1(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .return_value()
                    .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                    .clone(),
                VersionedContractSchema::V2(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .return_value()
                    .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                    .clone(),
                VersionedContractSchema::V3(contract_schema) => contract_schema
                    .receive
                    .get(function_name)
                    .ok_or(VersionedSchemaError::NoReceiveInContract)?
                    .return_value()
                    .ok_or(VersionedSchemaError::NoReturnValueInReceive)?
                    .clone(),
            };

            Ok(return_value_schema)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn module_schema() -> VersionedModuleSchema {
            let module_bytes = hex::decode(
                "ffff02010000000c00000054657374436f6e7472616374010402030100000010000000726563656976655f66756e6374696f6e06060807",
            )
            .unwrap();
            VersionedModuleSchema::new(&module_bytes, &None).unwrap()
        }

        #[test]
        fn test_getting_init_param_schema() {
            let extracted_type = module_schema().get_init_param_schema("TestContract").unwrap();
            assert_eq!(extracted_type, Type::U8)
        }

        #[test]
        fn test_getting_receive_param_schema() {
            let extracted_type = module_schema()
                .get_receive_param_schema("TestContract", "receive_function")
                .unwrap();
            assert_eq!(extracted_type, Type::I8)
        }

        #[test]
        fn test_getting_init_error_schema() {
            let extracted_type = module_schema().get_init_error_schema("TestContract").unwrap();
            assert_eq!(extracted_type, Type::U16)
        }

        #[test]
        fn test_getting_receive_error_schema() {
            let extracted_type = module_schema()
                .get_receive_error_schema("TestContract", "receive_function")
                .unwrap();
            assert_eq!(extracted_type, Type::I16)
        }

        #[test]
        fn test_getting_receive_return_value_schema() {
            let extracted_type = module_schema()
                .get_receive_return_value_schema("TestContract", "receive_function")
                .unwrap();
            assert_eq!(extracted_type, Type::I32)
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
        let mut data = [0u8; 100000];
        rng.fill_bytes(&mut data);

        let mut unstructured = Unstructured::new(&data);

        for _ in 0..10000 {
            let schema = Type::arbitrary(&mut unstructured).unwrap();

            let res = from_bytes::<Type>(&to_bytes(&schema)).unwrap();
            assert_eq!(schema, res);
        }
    }

    /// Serialize and then deserialize the input.
    fn serial_deserial<T: Serialize>(t: &T) -> ParseResult<T> { from_bytes::<T>(&to_bytes(t)) }

    #[test]
    fn test_function_v1_serial_deserial_is_id() {
        let f1 = FunctionV1::Parameter(Type::String(SizeLength::U32));
        let f2 = FunctionV1::ReturnValue(Type::U128);
        let f3 = FunctionV1::Both {
            parameter:    Type::Set(SizeLength::U8, Box::new(Type::ByteArray(10))),
            return_value: Type::ILeb128(3),
        };

        assert_eq!(serial_deserial(&f1), Ok(f1));
        assert_eq!(serial_deserial(&f2), Ok(f2));
        assert_eq!(serial_deserial(&f3), Ok(f3));
    }

    #[test]
    fn test_function_v2_serial_deserial_is_id() {
        let f1 = FunctionV2 {
            parameter:    Some(Type::String(SizeLength::U32)),
            return_value: Some(Type::String(SizeLength::U32)),
            error:        Some(Type::String(SizeLength::U32)),
        };

        assert_eq!(serial_deserial(&f1), Ok(f1));
    }

    #[test]
    fn test_module_v0_serial_deserial_is_id() {
        let m = ModuleV0 {
            contracts: BTreeMap::from([("a".into(), ContractV0 {
                init:    Some(Type::U8),
                receive: BTreeMap::from([
                    ("b".into(), Type::String(SizeLength::U32)),
                    ("c".into(), Type::Bool),
                ]),
                state:   Some(Type::String(SizeLength::U64)),
            })]),
        };

        assert_eq!(serial_deserial(&m), Ok(m));
    }

    #[test]
    fn test_module_v1_serial_deserial_is_id() {
        let m = ModuleV1 {
            contracts: BTreeMap::from([("a".into(), ContractV1 {
                init:    Some(FunctionV1::Parameter(Type::U8)),
                receive: BTreeMap::from([
                    ("b".into(), FunctionV1::ReturnValue(Type::String(SizeLength::U32))),
                    ("c".into(), FunctionV1::Both {
                        parameter:    Type::U8,
                        return_value: Type::Bool,
                    }),
                ]),
            })]),
        };

        assert_eq!(serial_deserial(&m), Ok(m));
    }

    #[test]
    fn test_module_v2_serial_deserial_is_id() {
        let m = ModuleV2 {
            contracts: BTreeMap::from([("a".into(), ContractV2 {
                init:    Some(FunctionV2 {
                    parameter:    Some(Type::String(SizeLength::U32)),
                    return_value: Some(Type::String(SizeLength::U32)),
                    error:        Some(Type::String(SizeLength::U32)),
                }),
                receive: BTreeMap::from([
                    ("b".into(), FunctionV2 {
                        parameter:    Some(Type::String(SizeLength::U32)),
                        return_value: Some(Type::String(SizeLength::U32)),
                        error:        Some(Type::String(SizeLength::U32)),
                    }),
                    ("c".into(), FunctionV2 {
                        parameter:    Some(Type::String(SizeLength::U32)),
                        return_value: Some(Type::String(SizeLength::U32)),
                        error:        Some(Type::String(SizeLength::U32)),
                    }),
                ]),
            })]),
        };

        assert_eq!(serial_deserial(&m), Ok(m));
    }

    #[test]
    fn test_module_v3_schema_serial_deserial_is_id() {
        use rand::prelude::*;
        use rand_pcg::Pcg64;

        let seed: u64 = random();
        let mut rng = Pcg64::seed_from_u64(seed);
        let mut data = [0u8; 100000];
        rng.fill_bytes(&mut data);

        let mut unstructured = Unstructured::new(&data);

        for _ in 0..10000 {
            let schema = ModuleV3::arbitrary(&mut unstructured).unwrap();

            let res = from_bytes::<ModuleV3>(&to_bytes(&schema)).unwrap();
            assert_eq!(schema, res);
        }
    }
}
