#[cfg(not(feature = "std"))]
use core::convert;
#[cfg(feature = "std")]
use std::convert;

#[cfg(not(feature = "std"))]
use core::ops::{Add, AddAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign};
#[cfg(feature = "std")]
use std::ops::{Add, AddAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign};

#[cfg(not(feature = "std"))]
use core::iter::Sum;
#[cfg(feature = "std")]
use std::iter::Sum;

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[cfg(feature = "derive-serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The type of amounts on the chain
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount {
    pub micro_gtu: u64,
}

impl Amount {
    /// Create amount from a number of microGTU
    #[inline(always)]
    pub fn from_micro_gtu(micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu,
        }
    }

    /// Create amount from a number of GTU
    #[inline(always)]
    pub fn from_gtu(gtu: u64) -> Amount {
        Amount {
            micro_gtu: gtu * 1000000,
        }
    }

    /// Create zero amount
    #[inline(always)]
    pub fn zero() -> Amount {
        Amount {
            micro_gtu: 0,
        }
    }

    /// Add a number of micro GTU to an amount
    #[inline(always)]
    pub fn add_micro_gtu(self, micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu + micro_gtu,
        }
    }

    /// Checked addition. Adds another amount and return None if overflow
    /// occurred
    #[inline(always)]
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.micro_gtu.checked_add(other.micro_gtu).map(Amount::from_micro_gtu)
    }

    /// Add a number of GTU to an amount
    #[inline(always)]
    pub fn add_gtu(self, gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu + gtu * 1000000,
        }
    }

    /// Subtract a number of micro GTU to an amount
    #[inline(always)]
    pub fn subtract_micro_gtu(self, micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu - micro_gtu,
        }
    }

    /// Subtract a number of GTU to an amount
    #[inline(always)]
    pub fn subtract_gtu(self, gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu - gtu * 1000000,
        }
    }

    /// Calculates the quotient and remainder of integer division
    #[inline(always)]
    pub fn quotient_remainder(self, denominator: u64) -> (Amount, Amount) {
        let div = Amount {
            micro_gtu: self.micro_gtu / denominator,
        };
        let rem = self % denominator;
        (div, rem)
    }
}

impl Mul<u64> for Amount {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: u64) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu * other,
        }
    }
}

impl Mul<Amount> for u64 {
    type Output = Amount;

    #[inline(always)]
    fn mul(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self * other.micro_gtu,
        }
    }
}

impl Add<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu + other.micro_gtu,
        }
    }
}

impl Sub<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu - other.micro_gtu,
        }
    }
}

impl Rem<u64> for Amount {
    type Output = Self;

    #[inline(always)]
    fn rem(self, other: u64) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu % other,
        }
    }
}

impl Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Amount::from_micro_gtu(0), Add::add)
    }
}

impl AddAssign for Amount {
    #[inline(always)]
    fn add_assign(&mut self, other: Amount) { *self = *self + other; }
}

impl SubAssign for Amount {
    #[inline(always)]
    fn sub_assign(&mut self, other: Amount) { *self = *self - other; }
}

impl MulAssign<u64> for Amount {
    #[inline(always)]
    fn mul_assign(&mut self, other: u64) { *self = *self * other; }
}

impl RemAssign<u64> for Amount {
    #[inline(always)]
    fn rem_assign(&mut self, other: u64) { *self = *self % other; }
}

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug)]
pub struct AccountAddress(pub [u8; ACCOUNT_ADDRESS_SIZE]);

impl convert::AsRef<[u8; 32]> for AccountAddress {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl convert::AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Address of a contract.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct ContractAddress {
    pub index:    u64,
    pub subindex: u64,
}

/// Chain context accessible to the init methods.
///
/// TODO: We could optimize this to be initialized lazily
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
pub struct InitContext {
    pub metadata:    ChainMetadata,
    pub init_origin: AccountAddress,
}

/// Either an address of an account, or contract.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(tag = "type", content = "address")
)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Address {
    Account(AccountAddress),
    Contract(ContractAddress),
}

/// Chain context accessible to the receive methods.
///
/// TODO: We could optimize this to be initialized lazily.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
pub struct ReceiveContext {
    pub metadata:     ChainMetadata,
    pub invoker:      AccountAddress,  //32 bytes
    pub self_address: ContractAddress, // 16 bytes
    pub self_balance: Amount,          // 8 bytes
    pub sender:       Address,         // 9 or 33 bytes
    pub owner:        AccountAddress,  // 32 bytes
}

/// Sequential slot number
pub type SlotNumber = u64;

/// Height of the block.
pub type BlockHeight = u64;

/// Finalized height. In the context of chain metadata this is the height of the
/// block which is explicitly recorded as the last finalized block in the block
/// under consideration.
pub type FinalizedHeight = u64;

/// Time at the beginning of the current slot, in miliseconds.
pub type SlotTime = u64;

/// Chain metadata accessible to both receive and init methods.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
pub struct ChainMetadata {
    pub slot_number:      SlotNumber,
    pub block_height:     BlockHeight,
    pub finalized_height: FinalizedHeight,
    pub slot_time:        SlotTime,
}

/// Add offset tracking inside a data structure.
pub struct Cursor<T> {
    pub offset: usize,
    pub data:   T,
}

/// Zero-sized type to represent an error when reading bytes and deserializing.
///
/// When using custom error types in your smart contract, it is convenient to
/// implement the trait `From<ParseError>` for you custom error type, to allow
/// using the `?` operator when deserializing bytes, such as the contract state
/// or parameters.
///
/// ```rust
/// enum MyCustomReceiveError {
///     Parsing
/// }
///
/// impl From<ParseError> for MyCustomReceiveError {
///     fn from(_: ParseError) -> Self { MyCustomReceiveError::ParseParams }
/// }
///
/// #[receive(contract = "mycontract", name="some_receive_name")]
/// fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
///     ctx: &R,
///     receive_amount: Amount,
///     logger: &mut L,
///     state: &mut State,
/// ) -> Result<A, MyCustomReceiveError> {
///     ...
///     let msg: MyParameterType = ctx.parameter_cursor().get()?;
///     ...
/// }
/// ```
#[derive(Debug, Default)]
pub struct ParseError {}

pub type ParseResult<A> = Result<A, ParseError>;

#[cfg(feature = "derive-serde")]
mod serde_impl {
    // FIXME: This is duplicated from crypto/id/types.
    use super::*;
    use base58check::*;
    use serde::{de, de::Visitor, Deserializer, Serializer};
    use std::fmt;

    // Parse from string assuming base58 check encoding.
    impl std::str::FromStr for AccountAddress {
        type Err = ();

        fn from_str(v: &str) -> Result<Self, Self::Err> {
            let (version, body) = v.from_base58check().map_err(|_| ())?;
            if version == 1 && body.len() == ACCOUNT_ADDRESS_SIZE {
                let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
                buf.copy_from_slice(&body);
                Ok(AccountAddress(buf))
            } else {
                Err(())
            }
        }
    }

    impl fmt::Display for AccountAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0.to_base58check(1))
        }
    }

    impl SerdeSerialize for AccountAddress {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let b58_str = self.to_string();
            ser.serialize_str(&b58_str)
        }
    }

    impl<'de> SerdeDeserialize<'de> for AccountAddress {
        fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
            des.deserialize_str(Base58Visitor)
        }
    }

    impl fmt::Display for ContractAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "<{},{}>", self.index, self.subindex)
        }
    }

    impl fmt::Display for Amount {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let q = self.micro_gtu / 1000000;
            let r = self.micro_gtu % 1000000;
            if r == 0 {
                write!(f, "{}.0", q)
            } else {
                write!(f, "{}.{:06}", q, r)
            }
        }
    }

    struct Base58Visitor;

    impl<'de> Visitor<'de> for Base58Visitor {
        type Value = AccountAddress;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "A base58 string, version 1.")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<AccountAddress>().map_err(|_| de::Error::custom("Wrong Base58 version."))
        }
    }
}

/// Contract schema related types
pub mod schema {
    use std::collections::BTreeMap;

    /// Describes all the schemas of a smart contract.
    #[derive(Debug, Clone)]
    pub struct Contract {
        pub state:            Option<Type>,
        pub method_parameter: BTreeMap<String, Type>,
    }

    /// Schema for the fields of a struct or some enum variant.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(test, derive(arbitrary::Arbitrary))]
    pub enum Fields {
        Named(Vec<(String, Type)>),
        Unnamed(Vec<Type>),
        /// No fields
        Unit,
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
        Option(Box<Type>),
        Pair(Box<Type>, Box<Type>),
        String(SizeLength),
        List(SizeLength, Box<Type>),
        Set(SizeLength, Box<Type>),
        Map(SizeLength, Box<Type>, Box<Type>),
        Array(u32, Box<Type>),
        Struct(Fields),
        Enum(Vec<(String, Fields)>),
    }

    impl Type {
        #[doc(hidden)]
        /// Sets the size_length of schema types, with variable size otherwise
        /// it is a noop. Used when deriving SchemaType.
        pub fn set_size_length(self, size_len: SizeLength) -> Type {
            match self {
                Type::String(_) => Type::String(size_len),
                Type::List(_, ty) => Type::List(size_len, ty),
                Type::Set(_, ty) => Type::Set(size_len, ty),
                Type::Map(_, key_ty, val_ty) => Type::Map(size_len, key_ty, val_ty),
                t => t,
            }
        }
    }
}
