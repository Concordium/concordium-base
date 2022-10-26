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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// The [`Default`] instance produces an empty schema.
pub struct ContractV3 {
    pub init:    Option<FunctionV3>,
    pub receive: BTreeMap<String, FunctionV3>,
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
/// V2 schemas. Differs from [`FunctionV1`] in that a schema for the error can
/// be included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionV2 {
    Param(Type),
    /// Rv is short for Return value.
    Rv(Type),
    ParamRv {
        parameter:    Type,
        return_value: Type,
    },
    Error(Type),
    ParamError {
        parameter: Type,
        error:     Type,
    },
    RvError {
        return_value: Type,
        error:        Type,
    },
    ParamRvError {
        parameter:    Type,
        return_value: Type,
        error:        Type,
    },
}

impl FunctionV2 {
    /// Extract the parameter schema if it exists.
    pub fn parameter(&self) -> Option<&Type> {
        match self {
            FunctionV2::Param(ty) => Some(ty),
            FunctionV2::ParamRv {
                parameter,
                ..
            } => Some(parameter),
            FunctionV2::ParamError {
                parameter,
                ..
            } => Some(parameter),
            FunctionV2::ParamRvError {
                parameter,
                ..
            } => Some(parameter),
            _ => None,
        }
    }

    /// Extract the return value schema if it exists.
    pub fn return_value(&self) -> Option<&Type> {
        match self {
            FunctionV2::Rv(rv) => Some(rv),
            FunctionV2::ParamRv {
                return_value,
                ..
            } => Some(return_value),
            FunctionV2::RvError {
                return_value,
                ..
            } => Some(return_value),
            FunctionV2::ParamRvError {
                return_value,
                ..
            } => Some(return_value),
            _ => None,
        }
    }

    /// Extract the error schema if it exists.
    pub fn error(&self) -> Option<&Type> {
        match self {
            FunctionV2::Error(error) => Some(error),
            FunctionV2::ParamError {
                error,
                ..
            } => Some(error),
            FunctionV2::RvError {
                error,
                ..
            } => Some(error),
            FunctionV2::ParamRvError {
                error,
                ..
            } => Some(error),
            _ => None,
        }
    }
}

/// Describes the schema of an init or a receive function for V1 contracts with
/// V3 schemas. Differs from [`FunctionV2`] in that a schema for the events can
/// be included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionV3 {
    pub parameter:    Option<Type>,
    pub return_value: Option<Type>,
    pub error:        Option<Type>,
}

impl FunctionV3 {
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

// TODO: Extend with LEB128
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
    EnumTag(BTreeMap<u8, (String, Fields)>),
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
        match self {
            FunctionV2::Param(parameter) => {
                out.write_u8(0)?;
                parameter.serial(out)
            }
            FunctionV2::Rv(return_value) => {
                out.write_u8(1)?;
                return_value.serial(out)
            }
            FunctionV2::ParamRv {
                parameter,
                return_value,
            } => {
                out.write_u8(2)?;
                parameter.serial(out)?;
                return_value.serial(out)
            }
            FunctionV2::Error(error) => {
                out.write_u8(3)?;
                error.serial(out)
            }
            FunctionV2::ParamError {
                parameter,
                error,
            } => {
                out.write_u8(4)?;
                parameter.serial(out)?;
                error.serial(out)
            }
            FunctionV2::RvError {
                return_value,
                error,
            } => {
                out.write_u8(5)?;
                return_value.serial(out)?;
                error.serial(out)
            }
            FunctionV2::ParamRvError {
                parameter,
                return_value,
                error,
            } => {
                out.write_u8(6)?;
                parameter.serial(out)?;
                return_value.serial(out)?;
                error.serial(out)
            }
        }
    }
}

impl Deserial for FunctionV2 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(FunctionV2::Param(source.get()?)),
            1 => Ok(FunctionV2::Rv(source.get()?)),
            2 => Ok(FunctionV2::ParamRv {
                parameter:    source.get()?,
                return_value: source.get()?,
            }),
            3 => Ok(FunctionV2::Error(source.get()?)),
            4 => Ok(FunctionV2::ParamError {
                parameter: source.get()?,
                error:     source.get()?,
            }),
            5 => Ok(FunctionV2::RvError {
                return_value: source.get()?,
                error:        source.get()?,
            }),
            6 => Ok(FunctionV2::ParamRvError {
                parameter:    source.get()?,
                return_value: source.get()?,
                error:        source.get()?,
            }),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for FunctionV3 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        // This index encodes if each of the schemas is set or not.
        // If the fourth last bit is set to 1, the parameter schema is set.
        // If the third last bit is set to 1, the return_value schema is set.
        // If the second last bit is set to 1, the error schema is set.
        // If the last bit is set to 1, the event schema is set.

        let mut index: u8 = 0;

        if self.parameter.is_some() {
            index |= 0b100;
        }
        if self.return_value.is_some() {
            index |= 0b010;
        }
        if self.error.is_some() {
            index |= 0b001;
        }

        out.write_u8(index)?;

        if self.parameter.is_some() {
            self.parameter.serial(out)?;
        }
        if self.return_value.is_some() {
            self.return_value.serial(out)?;
        }
        if self.error.is_some() {
            self.error.serial(out)?;
        }

        Ok(())
    }
}

fn get_bit_at(input: u8, n: u8) -> bool {
    if n < 8 {
        input & (1 << n) != 0
    } else {
        false
    }
}

impl Deserial for FunctionV3 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let index: u8 = source.get()?;

        let mut parameter = None;
        let mut return_value = None;
        let mut error = None;

        if get_bit_at(index, 2) {
            parameter = source.get()?;
        }
        if get_bit_at(index, 1) {
            return_value = source.get()?;
        }
        if get_bit_at(index, 0) {
            error = source.get()?;
        }

        Ok(FunctionV3 {
            parameter,
            return_value,
            error,
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
            Type::EnumTag(fields) => {
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
                Ok(Type::EnumTag(variants))
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

#[cfg(feature = "derive-serde")]
mod impls {
    use super::*;
    use crate::constants::*;
    use num_bigint::{BigInt, BigUint};
    use num_traits::Zero;

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
                Type::EnumTag(variants) => {
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
                    let owned_receive_name =
                        OwnedReceiveName::new(deserial_string(source, *size_len)?)
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

    #[cfg(test)]
    mod tests {
        use super::*;

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
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
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
            let mut cursor =
                Cursor::new([128, 128, 128, 128, 128, 128, 128, 128, 128, 0b0111_1111]);
            let int = deserial_bigint(&mut cursor, 10).expect("Deserialising should not fail");
            assert_eq!(int, BigInt::from(i64::MIN))
        }

        #[test]
        fn test_deserial_bigint_constraint_fails() {
            let mut cursor =
                Cursor::new([128, 128, 128, 128, 128, 128, 128, 128, 128, 0b0111_1111]);
            deserial_bigint(&mut cursor, 9).expect_err("Deserialising should fail");
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
        let f1 = FunctionV2::Param(Type::String(SizeLength::U32));
        let f2 = FunctionV2::Rv(Type::U128);
        let f3 = FunctionV2::ParamRv {
            parameter:    Type::Set(SizeLength::U8, Box::new(Type::ByteArray(10))),
            return_value: Type::ILeb128(3),
        };
        let f4 = FunctionV2::Error(Type::ByteList(SizeLength::U32));
        let f5 = FunctionV2::ParamError {
            parameter: Type::U8,
            error:     Type::String(SizeLength::U8),
        };
        let f6 = FunctionV2::ParamRvError {
            parameter:    Type::Set(SizeLength::U8, Box::new(Type::ByteArray(10))),
            return_value: Type::ILeb128(3),
            error:        Type::Bool,
        };

        assert_eq!(serial_deserial(&f1), Ok(f1));
        assert_eq!(serial_deserial(&f2), Ok(f2));
        assert_eq!(serial_deserial(&f3), Ok(f3));
        assert_eq!(serial_deserial(&f4), Ok(f4));
        assert_eq!(serial_deserial(&f5), Ok(f5));
        assert_eq!(serial_deserial(&f6), Ok(f6));
    }

    #[test]
    fn test_function_v3_serial_deserial_is_id() {
        let mut event_map = BTreeMap::new();
        let tag: u8 = 1;
        event_map.insert(
            tag,
            (String::from("EventOne"), Fields::Named(vec![(String::from("value"), Type::U8)])),
        );

        let f1 = FunctionV3 {
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
                init:    Some(FunctionV2::Error(Type::U8)),
                receive: BTreeMap::from([
                    ("b".into(), FunctionV2::Rv(Type::String(SizeLength::U32))),
                    ("c".into(), FunctionV2::ParamError {
                        parameter: Type::U8,
                        error:     Type::Bool,
                    }),
                ]),
            })]),
        };

        assert_eq!(serial_deserial(&m), Ok(m));
    }

    #[test]
    fn test_module_v3_serial_deserial_is_id() {
        let mut event_map = BTreeMap::new();
        let tag: u8 = 1;
        event_map.insert(
            tag,
            (String::from("EventOne"), Fields::Named(vec![(String::from("value"), Type::U8)])),
        );

        let m = ModuleV3 {
            contracts: BTreeMap::from([("a".into(), ContractV3 {
                init:    Some(FunctionV3 {
                    parameter:    Some(Type::String(SizeLength::U32)),
                    return_value: Some(Type::String(SizeLength::U32)),
                    error:        Some(Type::String(SizeLength::U32)),
                }),
                receive: BTreeMap::from([
                    ("b".into(), FunctionV3 {
                        parameter:    Some(Type::String(SizeLength::U32)),
                        return_value: Some(Type::String(SizeLength::U32)),
                        error:        Some(Type::String(SizeLength::U32)),
                    }),
                    ("c".into(), FunctionV3 {
                        parameter:    Some(Type::String(SizeLength::U32)),
                        return_value: Some(Type::String(SizeLength::U32)),
                        error:        Some(Type::String(SizeLength::U32)),
                    }),
                ]),
                event:   Some(Type::EnumTag(event_map)),
            })]),
        };

        assert_eq!(serial_deserial(&m), Ok(m));
    }
}
