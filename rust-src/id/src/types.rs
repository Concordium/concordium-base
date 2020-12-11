use crate::{
    secret_sharing::Threshold,
    sigma_protocols::{
        com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult,
        common::{ReplicateAdapter, ReplicateWitness},
        dlog,
    },
};
use base58check::*;
use bulletproofs::range_proof::{Generators, RangeProof};
use byteorder::ReadBytesExt;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use either::Either;
use elgamal::{ChunkSize, Cipher, Message, SecretKey as ElgamalSecretKey};
use ff::Field;
use hex::{decode, encode};
use pedersen_scheme::{
    commitment as pedersen, key::CommitmentKey as PedersenKey, Value as PedersenValue,
};
use ps_sig::{public as pssig, signature::*, unknown_message::SigRetrievalRandomness};
use random_oracle::Challenge;
use serde::{
    de, de::Visitor, ser::SerializeMap, Deserialize as SerdeDeserialize, Deserializer,
    Serialize as SerdeSerialize, Serializer,
};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{btree_map::BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
    io::{Cursor, Read},
    str::FromStr,
}; // only for account addresses

/// NB: This includes digits of PI (starting with 14...) as ASCII characters
/// this could be what is desired, but it is important to be aware of it.
pub static PI_DIGITS: &[u8] = include_bytes!("../data/pi-1000-digits.txt");

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

/// This is currently the number required, since the only
/// place these are used is for encrypted amounts.
pub const NUM_BULLETPROOF_GENERATORS: usize = 32 * 8;

/// Chunk size for encryption of prf key
pub const CHUNK_SIZE: ChunkSize = ChunkSize::ThirtyTwo;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct AccountAddress([u8; ACCOUNT_ADDRESS_SIZE]);

impl std::fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.to_base58check(1).fmt(f) }
}

// Parse from string assuming base58 check encoding.
impl std::str::FromStr for AccountAddress {
    type Err = &'static str;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let (version, body) = v
            .from_base58check()
            .map_err(|_| "The string is not valid base 58 check v1.")?;
        if version == 1 && body.len() == ACCOUNT_ADDRESS_SIZE {
            let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
            buf.copy_from_slice(&body);
            Ok(AccountAddress(buf))
        } else {
            Err("The string does not represent a valid Concordium address.")
        }
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

struct Base58Visitor;

impl<'de> Visitor<'de> for Base58Visitor {
    type Value = AccountAddress;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "A base58 string, version 1.")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        v.parse::<AccountAddress>()
            .map_err(|_| de::Error::custom("Wrong Base58 version."))
    }
}

impl Serial for AccountAddress {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        x.write_all(&self.0)
            .expect("Writing to buffer should succeed.")
    }
}

impl Deserial for AccountAddress {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
        source.read_exact(&mut buf)?;
        Ok(AccountAddress(buf))
    }
}

impl AccountAddress {
    /// Construct account address from the registration id.
    pub fn new<C: Curve>(reg_id: &C) -> Self {
        let mut out = [0; ACCOUNT_ADDRESS_SIZE];
        let hasher = Sha256::new().chain(&to_bytes(reg_id));
        out.copy_from_slice(&hasher.finalize());
        AccountAddress(out)
    }
}

/// Threshold for the number of signatures required.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serial)]
#[repr(transparent)]
/// The values of this type must maintain the property that they are not 0.
#[serde(transparent)]
#[derive(SerdeSerialize)]
pub struct SignatureThreshold(pub u8);

impl Deserial for SignatureThreshold {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let w = source.get()?;
        if w > 0 {
            Ok(SignatureThreshold(w))
        } else {
            bail!("0 is not a valid signature threshold.")
        }
    }
}

// Need to manually implement deserialize to maintain the property that it is
// non-zero.
impl<'de> SerdeDeserialize<'de> for SignatureThreshold {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        // expect a map, but also handle string
        des.deserialize_u8(SignatureThresholdVisitor)
    }
}

pub struct SignatureThresholdVisitor;

impl<'de> Visitor<'de> for SignatureThresholdVisitor {
    type Value = SignatureThreshold;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "A non-zero u8.")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        if v > 0 && v <= 255 {
            Ok(SignatureThreshold(v as u8))
        } else {
            Err(de::Error::custom(format!(
                "Signature threshold out of range {}",
                v
            )))
        }
    }
}

/// Index of an account key that is to be used.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct KeyIndex(pub u8);

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, SerdeBase16Serialize)]
pub struct IpCdiSignature(ed25519::Signature);

impl std::ops::Deref for IpCdiSignature {
    type Target = ed25519::Signature;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<ed25519::Signature> for IpCdiSignature {
    fn from(sig: ed25519::Signature) -> Self { IpCdiSignature(sig) }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, SerdeBase16Serialize)]
pub struct AccountOwnershipSignature(ed25519::Signature);

impl std::ops::Deref for AccountOwnershipSignature {
    type Target = ed25519::Signature;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<ed25519::Signature> for AccountOwnershipSignature {
    fn from(sig: ed25519::Signature) -> Self { AccountOwnershipSignature(sig) }
}

#[derive(Debug, PartialEq, Eq)]
/// A list of pairs of index of key and Ed25519 signatures on the challenge
/// of the proofs of the credential
/// The list should be non-empty and at most 255 elements long, and have no
/// duplicates. The current choice of data structure disallows duplicates by
/// design.
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct AccountOwnershipProof {
    pub sigs: BTreeMap<KeyIndex, AccountOwnershipSignature>,
}

// Manual implementation to be able to encode length as 1, as well as to
// make sure there is at least one proof.
impl Serial for AccountOwnershipProof {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.sigs.len() as u8;
        out.put(&len);
        serial_map_no_length(&self.sigs, out)
    }
}

impl Deserial for AccountOwnershipProof {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u8 = source.get()?;
        if len == 0 {
            bail!("Need at least one proof.")
        }
        let sigs = deserial_map_no_length(source, usize::from(len))?;
        Ok(AccountOwnershipProof { sigs })
    }
}

impl AccountOwnershipProof {
    /// Number of individual signatures in this proof.
    /// NB: This method relies on the invariant that signatures should not
    /// have more than 255 elements.
    pub fn num_proofs(&self) -> SignatureThreshold { SignatureThreshold(self.sigs.len() as u8) }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct IpIdentity(pub u32);

impl fmt::Display for IpIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Hash,
    Serial,
    SerdeSerialize,
    SerdeDeserialize,
)]
#[serde(into = "u32", try_from = "u32")]
/// Identity of the anonymity revoker on the chain. This defines their
/// evaluation point for secret sharing, and thus it cannot be 0.
pub struct ArIdentity(u32);

impl Deserial for ArIdentity {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let x = source.get()?;
        if x == 0 {
            bail!("ArIdentity must be non-zero.")
        } else {
            Ok(ArIdentity(x))
        }
    }
}

impl fmt::Display for ArIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl Into<u32> for ArIdentity {
    fn into(self) -> u32 { self.0 }
}

impl Into<u64> for ArIdentity {
    fn into(self) -> u64 { u64::from(self.0) }
}

impl TryFrom<u32> for ArIdentity {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err("Zero is not a valid ArIdentity.")
        } else {
            Ok(ArIdentity(value))
        }
    }
}

impl FromStr for ArIdentity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = u32::from_str(s).map_err(|_| "Could not read u32.")?;
        ArIdentity::try_from(x)
    }
}

impl ArIdentity {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)) }

    #[cfg(test)]
    // This is unchecked, and only used in tests.
    pub fn new(x: u32) -> Self {
        assert_ne!(x, 0, "Trying to construct ArIdentity 0.");
        ArIdentity(x)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(try_from = "AttributeStringTag", into = "AttributeStringTag")]
pub struct AttributeTag(pub u8);

/// Given two ordered iterators call the corresponding functions in the
/// increasing order of keys. That is, essentially merge the two iterators into
/// an ordered iterator and then map, but this is all done inline.
pub fn merge_iter<'a, K: Ord + 'a, V1: 'a, V2: 'a, I1, I2, F>(i1: I1, i2: I2, mut f: F)
where
    I1: std::iter::IntoIterator<Item = (&'a K, &'a V1)>,
    I2: std::iter::IntoIterator<Item = (&'a K, &'a V2)>,
    F: FnMut(Either<&'a V1, &'a V2>), {
    let mut iter_1 = i1.into_iter().peekable();
    let mut iter_2 = i2.into_iter().peekable();
    while let (Some(&(tag_1, v_1)), Some(&(tag_2, v_2))) = (iter_1.peek(), iter_2.peek()) {
        if tag_1 < tag_2 {
            f(Either::Left(v_1));
            // advance the first iterator
            let _ = iter_1.next().is_none();
        } else {
            f(Either::Right(v_2));
            // advance the second iterator
            let _ = iter_2.next();
        }
    }
    for (_, v) in iter_1 {
        f(Either::Left(v))
    }
    for (_, v) in iter_2 {
        f(Either::Right(v))
    }
}

/// NB: The length of this list must be less than 256.
/// This must be consistent with the value of attributeNames in
/// haskell-src/Concordium/ID/Types.hs
pub const ATTRIBUTE_NAMES: [&str; 13] = [
    "firstName",
    "lastName",
    "sex",
    "dob",
    "countryOfResidence",
    "nationality",
    "idDocType",
    "idDocNo",
    "idDocIssuer",
    "idDocIssuedAt",
    "idDocExpiresAt",
    "nationalIdNo",
    "taxIdNo",
];

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct AttributeStringTag(String);

impl<'a> fmt::Display for AttributeStringTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

// NB: This requires that the length of ATTRIBUTE_NAMES is no more than 256.
// FIXME: This method's complexity is linear in the size of the set of
// attributes.
impl<'a> TryFrom<AttributeStringTag> for AttributeTag {
    type Error = failure::Error;

    fn try_from(v: AttributeStringTag) -> Result<Self, Self::Error> {
        if let Some(idx) = ATTRIBUTE_NAMES.iter().position(|&x| x == v.0) {
            Ok(AttributeTag(idx as u8))
        } else {
            Err(format_err!("{} tag unknown.", v.0))
        }
    }
}

impl<'a> std::convert::From<AttributeTag> for AttributeStringTag {
    fn from(v: AttributeTag) -> Self {
        let v_usize: usize = v.into();
        if v_usize < ATTRIBUTE_NAMES.len() {
            AttributeStringTag(ATTRIBUTE_NAMES[v_usize].to_owned())
        } else {
            AttributeStringTag("UNKNOWN".to_owned())
        }
    }
}

impl fmt::Display for AttributeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        assert!(self.0 > 0);
        let l: usize = (*self).into();
        if l > 0 && l <= ATTRIBUTE_NAMES.len() {
            write!(f, "{}", ATTRIBUTE_NAMES[l - 1])
        } else {
            Err(fmt::Error)
        }
    }
}

impl std::str::FromStr for AttributeTag {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(idx) = ATTRIBUTE_NAMES.iter().position(|&x| x == s) {
            Ok(AttributeTag(idx as u8))
        } else {
            Err(format_err!("{} tag unknown.", s))
        }
    }
}

impl Into<usize> for AttributeTag {
    fn into(self) -> usize { self.0.into() }
}

impl From<u8> for AttributeTag {
    fn from(x: u8) -> Self { AttributeTag(x) }
}

pub trait Attribute<F: Field>: Clone + Sized + Send + Sync + fmt::Display + Serialize {
    // convert an attribute to a field element
    fn to_field_element(&self) -> F;
}

/// YearMonth in Gregorian calendar.
/// The year is in Gregorian calendar and months are numbered from 1, i.e.,
/// 1 is January, ..., 12 is December.
/// Year must be a 4 digit year, i.e., between 1000 and 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YearMonth {
    pub year:  u16,
    pub month: u8,
}

impl SerdeSerialize for YearMonth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let s = format!("{}{:0>2}", self.year, self.month);
        serializer.serialize_str(&s)
    }
}

impl<'de> SerdeDeserialize<'de> for YearMonth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>, {
        deserializer.deserialize_str(YearMonthVisitor)
    }
}

struct YearMonthVisitor;

impl<'de> Visitor<'de> for YearMonthVisitor {
    type Value = YearMonth;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a year and month in format YYYYMM")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error, {
        YearMonth::from_str(s).map_err(de::Error::custom)
    }
}

impl Serial for YearMonth {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.year);
        out.put(&self.month);
    }
}

impl Deserial for YearMonth {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let year = source.get()?;
        let month = source.get()?;
        YearMonth::new(year, month).ok_or_else(|| format_err!("Invalid year/month."))
    }
}

impl std::str::FromStr for YearMonth {
    type Err = failure::Error;

    fn from_str(s: &str) -> Fallible<Self> {
        if !s.chars().all(|c| c.is_ascii() && c.is_numeric()) {
            bail!("Unsupported date in format YYYYMM")
        }
        if s.len() != 6 {
            bail!("Invalid length of YYYYMM.")
        }
        let (s_year, s_month) = s.split_at(4);
        let year = s_year.parse::<u16>()?;
        let month = s_month.parse::<u8>()?;
        if let Some(ym) = YearMonth::new(year, month) {
            Ok(ym)
        } else {
            bail!("Year or month out of range.")
        }
    }
}

impl YearMonth {
    /// Construct a new YearMonth object.
    /// This method checks that year and month are in range.
    pub fn new(year: u16, month: u8) -> Option<Self> {
        if year >= 1000 && year < 10000 && month >= 1 && month <= 12 {
            Some(YearMonth { year, month })
        } else {
            None
        }
    }

    pub fn now() -> YearMonth {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        YearMonth {
            year:  now.year() as u16,
            month: now.month() as u8,
        }
    }
}

impl TryFrom<u64> for YearMonth {
    type Error = ();

    /// Try to convert unsigned 64-bit integer to year and month. Least
    /// significant byte is month, following two bytes is year in big endian
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        let month = (v & 0xFF) as u8;
        let year = ((v >> 8) & 0xFFFF) as u16;
        YearMonth::new(year, month).ok_or(())
    }
}

impl From<YearMonth> for u64 {
    /// Convert expiry (year and month) to unsigned 64-bit integer.
    /// Least significant byte is month, following two bytes are year
    fn from(v: YearMonth) -> Self { u64::from(v.month) | (u64::from(v.year) << 8) }
}

impl From<&YearMonth> for u64 {
    /// Convert expiry (year and month) to unsigned 64-bit integer.
    /// Least significant byte is month, following two bytes are year
    fn from(v: &YearMonth) -> Self { u64::from(v.month) | (u64::from(v.year) << 8) }
}

impl From<&YearMonth> for u32 {
    /// Convert expiry (year and month) to unsigned 32-bit integer.
    /// Least significant byte is month, following two bytes are year
    fn from(v: &YearMonth) -> Self { u32::from(v.month) | (u32::from(v.year) << 8) }
}

impl From<YearMonth> for u32 {
    /// Convert expiry (year and month) to unsigned 32-bit integer.
    /// Least significant byte is month, following two bytes are year
    fn from(v: YearMonth) -> Self { u32::from(v.month) | (u32::from(v.year) << 8) }
}

#[derive(Clone, Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "F: Field, AttributeType: Attribute<F> + SerdeSerialize",
    deserialize = "F: Field, AttributeType: Attribute<F> + SerdeDeserialize<'de>"
))]
pub struct AttributeList<F: Field, AttributeType: Attribute<F>> {
    #[serde(rename = "validTo")]
    pub valid_to: YearMonth,
    #[serde(rename = "createdAt")]
    pub created_at: YearMonth,
    /// Maximum number of accounts that can be created from the owning identity
    /// object.
    #[serde(rename = "maxAccounts")]
    pub max_accounts: u8,
    /// The attributes map. The map size can be at most k where k is the number
    /// of bits that fit into a field element.
    #[serde(rename = "chosenAttributes")]
    #[map_size_length = 2]
    pub alist: BTreeMap<AttributeTag, AttributeType>,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Serialize)]
/// In our case C: will be G1 and T will be G1 for now A secret credential is
/// a scalar raising a generator to this scalar gives a public credentials. If
/// two groups have the same scalar field we can have two different public
/// credentials from the same secret credentials.
#[derive(SerdeBase16Serialize)]
pub struct IdCredentials<C: Curve> {
    /// Secret id credentials.
    /// Since the use of this value is quite complex, we allocate
    /// it on the heap and retain a pointer to it for easy sharing.
    pub id_cred_sec: PedersenValue<C>,
}

impl<C: Curve> IdCredentials<C> {
    /// Use a cryptographically secure random number generator to
    /// generate a fresh secret credential.
    pub fn generate<R: rand::Rng>(csprng: &mut R) -> Self {
        IdCredentials {
            id_cred_sec: PedersenValue::generate(csprng),
        }
    }
}

/// Private credential holder information. A user maintaints these
/// through many different interactions with the identity provider and
/// the chain.
#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct CredentialHolderInfo<C: Curve> {
    /// Public and private keys of the credential holder. NB: These are distinct
    /// from the public/private keys of the account holders.
    #[serde(rename = "idCredSecret")]
    pub id_cred: IdCredentials<C>,
}

/// Private and public data chosen by the credential holder before the
/// interaction with the identity provider. The credential holder chooses a prf
/// key and an attribute list.
#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct AccCredentialInfo<C: Curve> {
    #[serde(rename = "credentialHolderInformation")]
    pub cred_holder_info: CredentialHolderInfo<C>,
    /// Chosen prf key of the credential holder.
    #[serde(rename = "prfKey")]
    pub prf_key: prf::SecretKey<C>,
}

/// The data relating to a single anonymity revoker
/// sent by the account holder to the identity provider
/// typically the account holder will send a vector of these
#[derive(Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct IpArData<C: Curve> {
    /// Encryption in chunks (in little endian) of the PRF key share
    #[serde(
        rename = "encPrfKeyShare",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub enc_prf_key_share: [Cipher<C>; 8],
    /// Witness to the proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    #[serde(rename = "proofComEncEq")]
    pub proof_com_enc_eq: com_enc_eq::Witness<C>,
}

/// Data structure for when a anonymity revoker decrypts its encrypted share
/// This is the decrypted counterpart of IpArData.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct IpArDecryptedData<C: Curve> {
    /// identity of the anonymity revoker
    #[serde(rename = "arIdentity")]
    pub ar_identity: ArIdentity,
    /// share of prf key
    #[serde(rename = "prfKeyShare")]
    pub prf_key_share: Value<C>,
}

/// Data relating to a single anonymity revoker sent by the account holder to
/// the chain.
/// Typically a vector of these will be sent to the chain.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct ChainArData<C: Curve> {
    /// encrypted share of id cred pub
    #[serde(rename = "encIdCredPubShare")]
    pub enc_id_cred_pub_share: Cipher<C>,
}

/// Data structure for when a anonymity revoker decrypts its encrypted share
/// This is the decrypted counterpart of ChainArData.
/// This structure contains an explicit ArIdentity in contrast to the
/// `ChainArData`. The reason for that is the use-case for this structure is
/// that an individual anonymity revoker decrypts its share and sends it, and we
/// need the context for that. In the other cases the data is always in the
/// context of a credential or pre-identity object, and as a result part of the
/// map.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct ChainArDecryptedData<C: Curve> {
    /// identity of the anonymity revoker
    #[serde(rename = "arIdentity")]
    pub ar_identity: ArIdentity,
    /// share of id cred pub
    #[serde(rename = "idCredPubShare")]
    pub id_cred_pub_share: Message<C>,
}

// NOTE: This struct is redundant, but we will
// will keep it for now for compatibility.
// We need to remove it in the future.
/// Choice of anonymity revocation parameters
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
pub struct ChoiceArParameters {
    #[serde(rename = "arIdentities")]
    #[set_size_length = 2]
    pub ar_identities: BTreeSet<ArIdentity>,
    #[serde(rename = "threshold")]
    pub threshold: Threshold,
}

/// Proof that the data sent to the identity provider
/// is well-formed.
#[derive(Serialize)]
pub struct PreIdentityProof<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Challenge for the combined proof. This includes the three proofs below,
    /// and additionally also the proofs in IpArData.
    pub challenge: Challenge,
    /// Witness to the proof of konwledge of IdCredSec.
    pub id_cred_sec_witness: dlog::Witness<C>,
    /// Witness to the proof that cmm_sc and id_cred_pub
    /// are hiding the same id_cred_sec.
    pub commitments_same_proof: com_eq::Witness<C>,
    /// Witness to the proof that cmm_prf and the
    /// second commitment to the prf key (hidden in cmm_prf_sharing_coeff)
    /// are hiding the same value.
    pub commitments_prf_same: com_eq_different_groups::Witness<P::G1, C>,
    /// Witness to the proof that reg_id = PRF(prf_key, 0)
    pub prf_regid_proof: com_eq::Witness<C>,
    /// Signature on the public information for the IP from the account holder
    pub proof_acc_sk: AccountOwnershipProof,
    /// Bulletproofs for showing that chunks are small so that encryption
    /// of the prf key can be decrypted
    pub bulletproofs: Vec<RangeProof<C>>,
}

/// A type alias for the combined proofs relating to the shared encryption of
/// IdCredPub.
pub type IdCredPubVerifiers<C> = (
    ReplicateAdapter<com_enc_eq::ComEncEq<C>>,
    ReplicateWitness<com_enc_eq::Witness<C>>,
);

/// Information sent from the account holder to the identity provider.
/// This includes only the cryptographic parts, the attribute list is
/// in a different object below.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>"
))]
pub struct PreIdentityObject<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    // TODO: consider renaming this struct
    /// Public credential of the account holder in the anonymity revoker's
    /// group.
    #[serde(rename = "pubInfoForIp")]
    pub pub_info_for_ip: PublicInformationForIP<C>,
    /// Anonymity revocation data for the chosen anonymity revokers.
    #[serde(rename = "ipArData")]
    #[map_size_length = 4]
    pub ip_ar_data: BTreeMap<ArIdentity, IpArData<C>>,
    /// Choice of anonyimity revocation parameters.
    /// NB:IP needs to check that they make sense in the context of the public
    /// keys they are allowed to use.
    #[serde(rename = "choiceArData")]
    pub choice_ar_parameters: ChoiceArParameters,
    /// Commitment to id cred sec using the commitment key of IP derived from
    /// the PS public key. This is used to compute the message that the IP
    /// signs.
    #[serde(rename = "idCredSecCommitment")]
    pub cmm_sc: pedersen::Commitment<P::G1>,
    /// Commitment to the prf key in group G1.
    #[serde(rename = "prfKeyCommitmentWithIP")]
    pub cmm_prf: pedersen::Commitment<P::G1>,
    /// commitments to the coefficients of the polynomial
    /// used to share the prf key
    /// K + b1 X + b2 X^2...
    /// where K is the prf key
    #[serde(rename = "prfKeySharingCoeffCommitments")]
    pub cmm_prf_sharing_coeff: Vec<pedersen::Commitment<C>>,
    /// Proofs of knowledge. See the documentation of PreIdentityProof for
    /// details.
    #[serde(
        rename = "proofsOfKnowledge",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub poks: PreIdentityProof<P, C>,
}

/// The data we get back from the identity provider.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>, AttributeType: Attribute<C::Scalar> \
                 + SerdeSerialize",
    deserialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>, AttributeType: \
                   Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct IdentityObject<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    #[serde(rename = "preIdentityObject")]
    pub pre_identity_object: PreIdentityObject<P, C>,
    /// Chosen attribute list.
    #[serde(rename = "attributeList")]
    pub alist: AttributeList<C::Scalar, AttributeType>,
    #[serde(
        rename = "signature",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub signature: Signature<P>,
}

/// Anonymity revokers associated with a single identity provider
#[derive(Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct IpAnonymityRevokers<C: Curve> {
    #[serde(rename = "anonymityRevokers")]
    pub ars: Vec<ArInfo<C>>,
    /// List of approved anonymity revokers along with a shared commitment key.
    /// TODO: How is this shared commitment key generated??
    #[serde(rename = "arCommitmentKey")]
    pub ar_cmm_key: PedersenKey<C>,
    /// Chosen generator of the group used by the anonymity revokers.
    /// NB: All public keys of anonymity revokers must be generated with respect
    /// to this generator.
    #[serde(serialize_with = "base16_encode")]
    #[serde(deserialize_with = "base16_decode")]
    #[serde(rename = "arBase")]
    pub ar_base: C,
}

/// Description either of an anonymity revoker or identity provider.
/// Metadata that should be visible on the chain.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
pub struct Description {
    #[string_size_length = 4]
    #[serde(rename = "name")]
    pub name: String,
    #[string_size_length = 4]
    #[serde(rename = "url")]
    pub url: String,
    #[string_size_length = 4]
    #[serde(rename = "description")]
    pub description: String,
}

/// Make a dummy description with a given name.
pub fn mk_dummy_description(name: String) -> Description {
    Description {
        name,
        url: "".to_owned(),
        description: "".to_owned(),
    }
}

/// Public information about an identity provider.
#[derive(Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "P: Pairing", deserialize = "P: Pairing"))]
pub struct IpInfo<P: Pairing> {
    /// Unique identifier of the identity provider.
    #[serde(rename = "ipIdentity")]
    pub ip_identity: IpIdentity,
    /// Free form description, e.g., how to contact them off-chain
    #[serde(rename = "ipDescription")]
    pub ip_description: Description,
    /// PS public key of the IP
    #[serde(rename = "ipVerifyKey")]
    pub ip_verify_key: pssig::PublicKey<P>,
    /// Ed public key of the IP
    #[serde(
        rename = "ipCdiVerifyKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub ip_cdi_verify_key: ed25519::PublicKey,
}

/// Collection of identity providers.
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "P: Pairing", deserialize = "P: Pairing"))]
#[serde(transparent)]
pub struct IpInfos<P: Pairing> {
    #[serde(rename = "idps")]
    pub identity_providers: BTreeMap<IpIdentity, IpInfo<P>>,
}

/// Public key of an anonymity revoker.
pub type ArPublicKey<C> = elgamal::PublicKey<C>;

/// Information on a single anonymity reovker held by the IP
/// typically an IP will hold a more than one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct ArInfo<C: Curve> {
    /// unique identifier of the anonymity revoker
    #[serde(rename = "arIdentity")]
    pub ar_identity: ArIdentity,
    /// description of the anonymity revoker (e.g. name, contact number)
    #[serde(rename = "arDescription")]
    pub ar_description: Description,
    /// elgamal encryption key of the anonymity revoker
    #[serde(rename = "arPublicKey")]
    pub ar_public_key: ArPublicKey<C>,
}

/// Collection of anonymity revokers.
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(transparent)]
pub struct ArInfos<C: Curve> {
    pub anonymity_revokers: BTreeMap<ArIdentity, ArInfo<C>>,
}

/// A helper trait to access only the public key of the ArInfo structure.
/// We use this to have functions work both on a map of public keys only, as
/// well as on maps of ArInfos, see verify_cdi.

pub trait HasArPublicKey<C: Curve> {
    fn get_public_key(&self) -> &ArPublicKey<C>;
}

impl<C: Curve> HasArPublicKey<C> for ArInfo<C> {
    fn get_public_key(&self) -> &ArPublicKey<C> { &self.ar_public_key }
}

impl<C: Curve> HasArPublicKey<C> for ArPublicKey<C> {
    fn get_public_key(&self) -> &ArPublicKey<C> { self }
}

/// The commitments sent by the account holder to the chain in order to
/// deploy credentials
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct CredentialDeploymentCommitments<C: Curve> {
    /// commitment to the prf key
    pub cmm_prf: pedersen::Commitment<C>,
    /// commitment to credential counter
    pub cmm_cred_counter: pedersen::Commitment<C>,
    /// commitment to the max account number.
    pub cmm_max_accounts: pedersen::Commitment<C>,
    /// List of commitments to the attributes that are not revealed.
    /// For the purposes of checking signatures, the commitments to those
    /// that are revealed as part of the policy are going to be computed by the
    /// verifier.
    #[map_size_length = 2]
    pub cmm_attributes: BTreeMap<AttributeTag, pedersen::Commitment<C>>,
    /// commitments to the coefficients of the polynomial
    /// used to share id_cred_sec
    /// S + b1 X + b2 X^2...
    /// where S is id_cred_sec
    pub cmm_id_cred_sec_sharing_coeff: Vec<pedersen::Commitment<C>>,
}

#[derive(Debug, SerdeBase16IgnoreLengthSerialize)]
pub struct CredDeploymentProofs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// (Blinded) Signature derived from the signature on the pre-identity
    /// object by the IP
    pub sig: BlindedSignature<P>,
    /// list of  commitments to the attributes .
    pub commitments: CredentialDeploymentCommitments<C>,
    /// Challenge used for all of the proofs.
    pub challenge: Challenge,
    /// Witnesses to the proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    pub proof_id_cred_pub: BTreeMap<ArIdentity, com_enc_eq::Witness<C>>,
    /// Witnesses for proof of knowledge of signature of Identity Provider on
    /// the list
    /// ```(idCredSec, prfKey, attributes[0], attributes[1],..., attributes[n],
    /// AR[1], ..., AR[m])```
    pub proof_ip_sig: com_eq_sig::Witness<P, C>,
    /// Proof that reg_id = prf_K(x). Also establishes that reg_id is computed
    /// from the prf key signed by the identity provider.
    pub proof_reg_id: com_mult::Witness<C>,
    /// Proof of knowledge of acc secret keys (signing keys corresponding to the
    /// verification keys either on the account already, or the ones which are
    /// part of this credential.
    /// TODO: This proof can be replaced by a signature if we only allow
    /// deploying proofs on own account.
    /// We could consider replacing this proof by just a list of signatures.
    pub proof_acc_sk: AccountOwnershipProof,
    /// Proof that cred_counter is less than or equal to max_accounts
    pub cred_counter_less_than_max_accounts: RangeProof<C>,
}

// This is an unfortunate situation, but we need to manually write a
// serialization instance for the proofs so that we can insert the length of the
// whole proof upfront. This is needed for easier interoperability with Haskell.
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Serial for CredDeploymentProofs<P, C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp_out = Vec::new();
        tmp_out.put(&self.sig);
        tmp_out.put(&self.commitments);
        tmp_out.put(&self.challenge);
        tmp_out.put(&(self.proof_id_cred_pub.len() as u32));
        serial_map_no_length(&self.proof_id_cred_pub, &mut tmp_out);
        tmp_out.put(&self.proof_ip_sig);
        tmp_out.put(&self.proof_reg_id);
        tmp_out.put(&self.proof_acc_sk);
        tmp_out.put(&self.cred_counter_less_than_max_accounts);
        let len: u32 = tmp_out.len() as u32; // safe
        out.put(&len);
        out.write_all(&tmp_out).expect("Writing to buffer is safe.");
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Deserial for CredDeploymentProofs<P, C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u32 = source.get()?;
        // Make sure to respect the length.
        let mut limited = source.take(u64::from(len));
        let sig = limited.get()?;
        let commitments = limited.get()?;
        let challenge = limited.get()?;
        let proof_id_cred_pub_len: u32 = limited.get()?;
        let proof_id_cred_pub =
            deserial_map_no_length(&mut limited, proof_id_cred_pub_len as usize)?;
        let proof_ip_sig = limited.get()?;
        let proof_reg_id = limited.get()?;
        let proof_acc_sk = limited.get()?;
        let cred_counter_less_than_max_accounts = limited.get()?;
        if limited.limit() == 0 {
            Ok(CredDeploymentProofs {
                sig,
                commitments,
                challenge,
                proof_id_cred_pub,
                proof_ip_sig,
                proof_reg_id,
                proof_acc_sk,
                cred_counter_less_than_max_accounts,
            })
        } else {
            bail!("Length information is inaccurate. Credential proofs not valid.")
        }
    }
}


#[derive(Debug, SerdeBase16IgnoreLengthSerialize)]
pub struct UnsignedCredDeploymentProofs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// (Blinded) Signature derived from the signature on the pre-identity
    /// object by the IP
    pub sig: BlindedSignature<P>,
    /// list of  commitments to the attributes .
    pub commitments: CredentialDeploymentCommitments<C>,
    /// Challenge used for all of the proofs.
    pub challenge: Challenge,
    /// Witnesses to the proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    pub proof_id_cred_pub: BTreeMap<ArIdentity, com_enc_eq::Witness<C>>,
    /// Witnesses for proof of knowledge of signature of Identity Provider on
    /// the list
    /// ```(idCredSec, prfKey, attributes[0], attributes[1],..., attributes[n],
    /// AR[1], ..., AR[m])```
    pub proof_ip_sig: com_eq_sig::Witness<P, C>,
    /// Proof that reg_id = prf_K(x). Also establishes that reg_id is computed
    /// from the prf key signed by the identity provider.
    pub proof_reg_id: com_mult::Witness<C>,
    /// Challenge from random oracle TODO: write out
    pub unsigned_challenge: Challenge,
    /// Proof that cred_counter is less than or equal to max_accounts
    pub cred_counter_less_than_max_accounts: RangeProof<C>,
}

/// TODO: Check if we cant avoid this duplication
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Serial for UnsignedCredDeploymentProofs<P, C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp_out = Vec::new();
        tmp_out.put(&self.sig);
        tmp_out.put(&self.commitments);
        tmp_out.put(&self.challenge);
        tmp_out.put(&(self.proof_id_cred_pub.len() as u32));
        serial_map_no_length(&self.proof_id_cred_pub, &mut tmp_out);
        tmp_out.put(&self.proof_ip_sig);
        tmp_out.put(&self.proof_reg_id);
        tmp_out.put(&self.unsigned_challenge);
        tmp_out.put(&self.cred_counter_less_than_max_accounts);
        let len: u32 = tmp_out.len() as u32; // safe
        out.put(&len);
        out.write_all(&tmp_out).expect("Writing to buffer is safe.");
    }
}

/// TODO: Check if we cant avoid this duplication
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Deserial for UnsignedCredDeploymentProofs<P, C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u32 = source.get()?;
        // Make sure to respect the length.
        let mut limited = source.take(u64::from(len));
        let sig = limited.get()?;
        let commitments = limited.get()?;
        let challenge = limited.get()?;
        let proof_id_cred_pub_len: u32 = limited.get()?;
        let proof_id_cred_pub =
            deserial_map_no_length(&mut limited, proof_id_cred_pub_len as usize)?;
        let proof_ip_sig = limited.get()?;
        let proof_reg_id = limited.get()?;
        let unsigned_challenge = limited.get()?;
        let cred_counter_less_than_max_accounts = limited.get()?;
        if limited.limit() == 0 {
            Ok(UnsignedCredDeploymentProofs {
                sig,
                commitments,
                challenge,
                proof_id_cred_pub,
                proof_ip_sig,
                proof_reg_id,
                unsigned_challenge,
                cred_counter_less_than_max_accounts,
            })
        } else {
            bail!("Length information is inaccurate. Credential proofs not valid.")
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct Policy<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "validTo")]
    pub valid_to: YearMonth,
    #[serde(rename = "createdAt")]
    pub created_at: YearMonth,
    /// Revealed attributes for now. In the future we might have
    /// additional items with (Tag, Property, Proof).
    #[serde(rename = "revealedAttributes")]
    pub policy_vec: BTreeMap<AttributeTag, AttributeType>,
    #[serde(skip)]
    pub _phantom: std::marker::PhantomData<C>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Serial for Policy<C, AttributeType> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.valid_to);
        out.put(&self.created_at);
        out.put(&(self.policy_vec.len() as u16));
        serial_map_no_length(&self.policy_vec, out)
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Deserial for Policy<C, AttributeType> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let valid_to = source.get()?;
        let created_at = source.get()?;
        let len: u16 = source.get()?;
        let policy_vec = deserial_map_no_length(source, usize::from(len))?;
        Ok(Policy {
            valid_to,
            created_at,
            policy_vec,
            _phantom: Default::default(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchemeId {
    Ed25519,
}

#[derive(Debug, Eq, Clone)]
pub enum VerifyKey {
    Ed25519VerifyKey(ed25519::PublicKey),
}

impl SerdeSerialize for VerifyKey {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut map = ser.serialize_map(Some(1))?;
        match self {
            VerifyKey::Ed25519VerifyKey(ref key) => {
                map.serialize_entry("schemeId", "Ed25519")?;
                map.serialize_entry("verifyKey", &encode(&to_bytes(key)))?;
            }
        }
        map.end()
    }
}

impl<'de> SerdeDeserialize<'de> for VerifyKey {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        // expect a map, but also handle string
        des.deserialize_map(VerifyKeyVisitor)
    }
}

pub struct VerifyKeyVisitor;

impl<'de> Visitor<'de> for VerifyKeyVisitor {
    type Value = VerifyKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Either a string or a map with verification key.")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let bytes = decode(v).map_err(de::Error::custom)?;
        let key = from_bytes(&mut Cursor::new(&bytes)).map_err(de::Error::custom)?;
        Ok(VerifyKey::Ed25519VerifyKey(key))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        let mut map = map;
        let mut tmp_map: BTreeMap<String, String> = BTreeMap::new();
        while tmp_map.len() < 2 {
            if let Some((k, v)) = map.next_entry()? {
                if k == "schemeId" {
                    if v != "Ed25519" {
                        return Err(de::Error::custom(format!(
                            "Unknown signature scheme type {}",
                            v
                        )));
                    }
                    if tmp_map.insert(k, v).is_some() {
                        return Err(de::Error::custom("Duplicate schemeId."));
                    }
                } else if k == "verifyKey" {
                    tmp_map.insert(k, v);
                }
            } else {
                return Err(de::Error::custom(
                    "At least the two keys 'schemeId' and 'verifyKey' are expected.",
                ));
            }
        }
        let vf_key_str = tmp_map
            .get("verifyKey")
            .ok_or_else(|| de::Error::custom("Could not find verifyKey, should not happen."))?;
        let bytes = decode(vf_key_str).map_err(de::Error::custom)?;
        let key = from_bytes(&mut Cursor::new(&bytes)).map_err(de::Error::custom)?;
        Ok(VerifyKey::Ed25519VerifyKey(key))
    }
}

impl From<ed25519::PublicKey> for VerifyKey {
    fn from(pk: ed25519::PublicKey) -> Self { VerifyKey::Ed25519VerifyKey(pk) }
}

impl From<&ed25519::Keypair> for VerifyKey {
    fn from(kp: &ed25519::Keypair) -> Self { VerifyKey::Ed25519VerifyKey(kp.public) }
}

/// Compare byte representation.
impl Ord for VerifyKey {
    fn cmp(&self, other: &VerifyKey) -> Ordering {
        let VerifyKey::Ed25519VerifyKey(ref self_key) = self;
        let VerifyKey::Ed25519VerifyKey(ref other_key) = other;
        self_key.as_ref().cmp(other_key.as_ref())
    }
}

impl PartialOrd for VerifyKey {
    fn partial_cmp(&self, other: &VerifyKey) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PartialEq for VerifyKey {
    fn eq(&self, other: &VerifyKey) -> bool { self.cmp(other) == Ordering::Equal }
}

impl Serial for VerifyKey {
    fn serial<B: Buffer>(&self, out: &mut B) {
        use VerifyKey::*;
        match self {
            Ed25519VerifyKey(ref key) => {
                out.put(&SchemeId::Ed25519);
                out.put(key);
            }
        }
    }
}

impl Deserial for VerifyKey {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        use VerifyKey::*;
        match source.get()? {
            SchemeId::Ed25519 => {
                let key = source.get()?;
                Ok(Ed25519VerifyKey(key))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize, Clone)]
pub struct NewAccount {
    #[size_length = 1]
    pub keys: Vec<VerifyKey>,
    pub threshold: SignatureThreshold,
}

/// What account should this credential be deployed to, or the keys of the new
/// account.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialAccount {
    ExistingAccount(AccountAddress),
    NewAccount(Vec<VerifyKey>, SignatureThreshold),
}

impl SerdeSerialize for CredentialAccount {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use CredentialAccount::*;
        match self {
            ExistingAccount(addr) => addr.serialize(ser),
            NewAccount(ref keys, threshold) => {
                let mut map = ser.serialize_map(Some(2))?;
                map.serialize_entry("keys", keys)?;
                map.serialize_entry("threshold", threshold)?;
                map.end()
            }
        }
    }
}

impl<'de> SerdeDeserialize<'de> for CredentialAccount {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        // expect a map, but also handle string
        des.deserialize_any(CredentialAccountVisitor)
    }
}

pub struct CredentialAccountVisitor;

impl<'de> Visitor<'de> for CredentialAccountVisitor {
    type Value = CredentialAccount;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "Either a string with account address or a map with keys and threshold."
        )
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let bytes = decode(v).map_err(de::Error::custom)?;
        let addr = from_bytes(&mut Cursor::new(&bytes)).map_err(de::Error::custom)?;
        Ok(CredentialAccount::ExistingAccount(addr))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        let mut map = map;
        let mut keys = None;
        let mut threshold = None;
        while keys.is_none() || threshold.is_none() {
            if let Some(k) = map.next_key::<String>()? {
                if k == "keys" {
                    if keys.is_none() {
                        keys = Some(map.next_value()?);
                    } else {
                        return Err(de::Error::custom("Duplicate key 'keys'."));
                    }
                } else if k == "threshold" {
                    if threshold.is_none() {
                        threshold = Some(map.next_value()?)
                    } else {
                        return Err(de::Error::custom("Duplicate key 'threshold'."));
                    }
                }
            } else {
                return Err(de::Error::custom(
                    "At least the two keys 'keys' and 'threshold' are expected.",
                ));
            }
        }
        Ok(CredentialAccount::NewAccount(
            keys.unwrap(),
            threshold.unwrap(),
        ))
    }
}

impl Serial for CredentialAccount {
    fn serial<B: Buffer>(&self, out: &mut B) {
        use CredentialAccount::*;
        match self {
            ExistingAccount(ref addr) => {
                out.write_u8(0).expect("Writing to buffer should succeed.");
                addr.serial(out);
            }
            NewAccount(ref keys, threshold) => {
                out.write_u8(1).expect("Writing to buffer should succeed.");
                let len = keys.len() as u8;
                len.serial(out);
                for key in keys.iter() {
                    key.serial(out);
                }
                threshold.serial(out);
            }
        }
    }
}

impl Deserial for CredentialAccount {
    fn deserial<R: ReadBytesExt>(cur: &mut R) -> Fallible<Self> {
        use CredentialAccount::*;
        let c = cur.read_u8()?;
        match c {
            0 => Ok(ExistingAccount(cur.get()?)),
            1 => {
                let len = cur.read_u8()?;
                if len == 0 {
                    bail!("Need at least one key.")
                }
                let mut keys = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    keys.push(cur.get()?);
                }
                let threshold = cur.get()?;
                Ok(NewAccount(keys, threshold))
            }
            _ => bail!("Only two variants of this type exist."),
        }
    }
}

/// What account should this credential be deployed to, or the keys of the new
/// account.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(transparent)]
pub struct InitialCredentialAccount {
    pub account: NewAccount,
}

/// Values (as opposed to proofs) in credential deployment.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredentialDeploymentValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Account this credential belongs to.
    #[serde(rename = "account")]
    pub cred_account: CredentialAccount,
    /// Credential registration id of the credential.
    #[serde(
        rename = "regId",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub reg_id: C,
    /// Identity of the identity provider who signed the identity object from
    /// which this credential is derived.
    #[serde(rename = "ipIdentity")]
    pub ip_identity: IpIdentity,
    /// Anonymity revocation threshold. Must be <= length of ar_data.
    #[serde(rename = "revocationThreshold")]
    pub threshold: Threshold,
    /// Anonymity revocation data. List of anonymity revokers which can revoke
    /// identity. NB: The order is important since it is the same order as that
    /// signed by the identity provider, and permuting the list will invalidate
    /// the signature from the identity provider.
    #[map_size_length = 2]
    #[serde(rename = "arData", deserialize_with = "deserialize_ar_data")]
    pub ar_data: BTreeMap<ArIdentity, ChainArData<C>>,
    /// Policy of this credential object.
    #[serde(rename = "policy")]
    pub policy: Policy<C, AttributeType>,
}

/// Values in initial credential deployment.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct InitialCredentialDeploymentValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Account this credential belongs to.
    #[serde(rename = "account")]
    pub cred_account: InitialCredentialAccount,
    /// Credential registration id of the credential.
    #[serde(
        rename = "regId",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub reg_id: C,
    /// Identity of the identity provider who signed the identity object from
    /// which this credential is derived.
    #[serde(rename = "ipIdentity")]
    pub ip_identity: IpIdentity,
    /// Policy of this credential object.
    #[serde(rename = "policy")]
    pub policy: Policy<C, AttributeType>,
}

fn deserialize_ar_data<'de, D: de::Deserializer<'de>, C: Curve>(
    des: D,
) -> Result<BTreeMap<ArIdentity, ChainArData<C>>, D::Error> {
    #[derive(Default)]
    struct ArIdentityVisitor<C>(std::marker::PhantomData<C>);

    impl<'de, C: Curve> Visitor<'de> for ArIdentityVisitor<C> {
        type Value = BTreeMap<ArIdentity, ChainArData<C>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "An object with integer keys and ChainArData values."
            )
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>, {
            let mut map = map;
            let mut res = BTreeMap::new();
            while let Some((k, v)) = map.next_entry::<String, _>()? {
                let k = ArIdentity::from_str(&k)
                    .map_err(|_| de::Error::custom("Cannot read ArIdentity key."))?;
                res.insert(k, v);
            }
            Ok(res)
        }
    }

    des.deserialize_map(ArIdentityVisitor(std::default::Default::default()))
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                 Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                   Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredentialDeploymentInfo<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    #[serde(flatten)]
    pub values: CredentialDeploymentValues<C, AttributeType>,
    #[serde(rename = "proofs")] // FIXME: This should remove the first 4 bytes
    pub proofs: CredDeploymentProofs<P, C>,
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                 Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                   Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct UnsignedCredentialDeploymentInfo<
        P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    > {
    #[serde(flatten)]
    pub values: CredentialDeploymentValues<C, AttributeType>,
    #[serde(rename = "proofs")] // FIXME: This should remove the first 4 bytes
    pub proofs: UnsignedCredDeploymentProofs<P, C>,
}

#[derive(Debug, Serialize, SerdeSerialize, SerdeDeserialize)]
// #[serde(bound(
//     serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
//                  Attribute<C::Scalar> + SerdeSerialize",
//     deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
//                    Attribute<C::Scalar> + SerdeDeserialize<'de>"
// ))]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct InitialCredentialDeploymentInfo<
    // P: Pairing,
    C: Curve, //<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    #[serde(flatten)]
    pub values: InitialCredentialDeploymentValues<C, AttributeType>,
    #[serde(rename = "sig")]
    pub sig: IpCdiSignature,
}

/// This struct contains information from the account holder that the identity
/// provider needs in order to create the initial credential for the account
/// hoder. It contains idCredPub, regId and the account keys.
/// It is part of the preidentity object.
#[derive(Debug, Serialize, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct PublicInformationForIP<C: Curve> {
    #[serde(
        rename = "idCredPub",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub id_cred_pub: C,
    #[serde(
        rename = "regId",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub reg_id: C,
    #[serde(rename = "publicKeys")]
    pub vk_acc: InitialCredentialAccount,
}

/// Context needed to generate pre-identity object as well as to check it.
/// This context is derived from the public information of the identity
/// provider, as well as some other global parameters which can be found in the
/// struct 'GlobalContext'.
#[derive(Clone)]
pub struct IPContext<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Public information on the chosen identity provider.
    pub ip_info: &'a IpInfo<P>,
    /// Public information on the __supported__ anonymity revokers.
    /// This is used by the identity provider and the chain to
    /// validate the identity object requests, to validate credentials,
    /// as well as by the account holder to create a credential.
    pub ars_infos: &'a BTreeMap<ArIdentity, ArInfo<C>>,
    pub global_context: &'a GlobalContext<C>,
}

impl<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>> Copy for IPContext<'a, P, C> {}

#[derive(Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct GlobalContext<C: Curve> {
    /// A shared commitment key known to the chain and the account holder (and
    /// therefore it is public). The account holder uses this commitment key to
    /// generate commitments to values in the attribute list.
    #[serde(rename = "onChainCommitmentKey")]
    pub on_chain_commitment_key: PedersenKey<C>,
    /// Generators for the bulletproofs.
    /// It is unclear what length we will require here, or whether we'll allow
    /// dynamic generation.
    #[serde(rename = "bulletproofGenerators")]
    bulletproof_generators: Generators<C>,
    #[string_size_length = 4]
    #[serde(rename = "genesisString")]
    /// A free-form string used to distinguish between different chains.
    pub genesis_string: String,
}

impl<C: Curve> GlobalContext<C> {
    /// Generate a new global context.
    pub fn generate(genesis_string: String) -> Self {
        Self::generate_size(genesis_string, NUM_BULLETPROOF_GENERATORS)
    }

    /// Generate a new global context with the given number of
    /// bulletproof generators.
    ///
    /// This is intended mostly for testing, on-chain there will be a fixed
    /// amount.
    pub fn generate_size(genesis_string: String, n: usize) -> Self {
        // initialize the first generator from pi digits.
        let g = C::hash_to_group(&PI_DIGITS[0..1000]);

        // generate next generator by hashing the previous one
        let h = C::hash_to_group(&to_bytes(&g));

        let cmm_key = PedersenKey { g, h };

        let mut generators = Vec::with_capacity(n);
        let mut generator = h;
        for _ in 0..n {
            generator = C::hash_to_group(&to_bytes(&generator));
            let g = generator;
            generator = C::hash_to_group(&to_bytes(&generator));
            let h = generator;
            generators.push((g, h));
        }

        GlobalContext {
            on_chain_commitment_key: cmm_key,
            bulletproof_generators: Generators { G_H: generators },
            genesis_string,
        }
    }

    /// The generator for encryption in the exponent is the second component of
    /// the commitment key, the 'h'.
    pub fn encryption_in_exponent_generator(&self) -> &C { &self.on_chain_commitment_key.h }

    /// The generator used as the base for elgamal public keys.
    pub fn elgamal_generator(&self) -> &C { &self.on_chain_commitment_key.g }

    /// A wrapper function to support changes in internal structure of the
    /// context in the future, e.g., lazy generation of generators.
    pub fn bulletproof_generators(&self) -> &Generators<C> { &self.bulletproof_generators }
}

/// Make a context in which the account holder can produce a pre-identity object
/// to send to the identity provider. Also requires access to the global context
/// of parameters, e.g., dlog-proof base point.
impl<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>> IPContext<'a, P, C> {
    pub fn new(
        ip_info: &'a IpInfo<P>,                         // identity provider keys
        ars_infos: &'a BTreeMap<ArIdentity, ArInfo<C>>, // keys of anonymity revokers.
        global_context: &'a GlobalContext<C>,
    ) -> Self {
        IPContext {
            ip_info,
            ars_infos,
            global_context,
        }
    }
}

/// A helper trait to access the public parts of the InitialAccountData
/// structure. We use this to allow implementations that does not give or have
/// access to the secret keys.
/// NB: the threshold should be atmost the number of keypairs.
pub trait PublicInitialAccountData {
    /// Get the number of keys required to sign a message from the account.
    fn get_threshold(&self) -> SignatureThreshold;
    /// Get the public keys of the account
    fn get_public_keys(&self) -> Vec<VerifyKey>;
}

/// A helper trait to allow signing PublicInformationForIP in an implementation
/// that does not give access to the secret keys.
pub trait InitialAccountDataWithSigning: PublicInitialAccountData {
    /// Sign a PublicInformationForIP structure with the secret keys that
    /// matches the public keys, which the structure provides.
    /// NB: the Function should, for each secret key,
    /// sign the sha256 hash of the structure's serialization.
    fn sign_public_information_for_ip<C: Curve>(
        &self,
        info: &PublicInformationForIP<C>,
    ) -> BTreeMap<KeyIndex, AccountOwnershipSignature>;
}

/// A helper trait to access the public parts of the AccountData
/// structure. We use this to allow implementations that does not give or have
/// access to the secret keys.
/// NB: the threshold should be atmost the number of keypairs.
pub trait PublicAccountData {
    /// Get the public keys of the account
    fn get_public_keys(&self) -> Vec<VerifyKey>;
    /// if its an existing account, get the address, otherwise
    /// get the signature threshold of the account.
    fn get_existing(&self) -> Either<SignatureThreshold, AccountAddress>;
}

/// A helper trait to allow signing PublicInformationForIP in an implementation
/// that does not give access to the secret keys.
pub trait AccountDataWithSigning: PublicAccountData {
    /// Sign a challenge with the secret keys of the account.
    fn sign_challenge(
        &self,
        challenge: &Challenge,
    ) -> BTreeMap<KeyIndex, AccountOwnershipSignature>;
}

/// Account data needed by the account holder to generate proofs to deploy the
/// credential object. This contains all the keys on the account at the moment
/// of credential deployment.
pub struct AccountData {
    pub keys: BTreeMap<KeyIndex, ed25519::Keypair>,
    /// If it is an existing account, its address, otherwise the signature
    /// threshold of the new account.
    pub existing: Either<SignatureThreshold, AccountAddress>,
}

/// This contains all the keys on the account of the initial credential
/// deployment.
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct InitialAccountData {
    #[serde(rename = "keys")]
    pub keys: BTreeMap<KeyIndex, crypto_common::serde_impls::KeyPairDef>,
    #[serde(rename = "threshold")]
    pub threshold: SignatureThreshold,
}

impl SerdeSerialize for AccountData {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut map = ser.serialize_map(Some(2))?;
        match self.existing {
            Either::Left(ref threshold) => map.serialize_entry("threshold", threshold)?,
            Either::Right(ref address) => map.serialize_entry("address", address)?,
        };

        let mut key_map = BTreeMap::new();
        for (idx, kp) in self.keys.iter() {
            let mut kp_map: BTreeMap<&str, String> = BTreeMap::new();
            kp_map.insert("verifyKey", base16_encode_string(&kp.public));
            kp_map.insert("signKey", base16_encode_string(&kp.secret));
            key_map.insert(idx, kp_map);
        }
        map.serialize_entry("keys", &key_map)?;
        map.end()
    }
}

impl<'de> SerdeDeserialize<'de> for AccountData {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        des.deserialize_map(AccountDataVisitor)
    }
}

impl PublicAccountData for AccountData {
    fn get_existing(&self) ->  Either<SignatureThreshold, AccountAddress> { self.existing }

    fn get_public_keys(&self) -> Vec<VerifyKey> {
        self.keys
            .values()
            .map(|kp| VerifyKey::Ed25519VerifyKey(kp.public))
            .collect::<Vec<_>>()
    }
}

impl AccountDataWithSigning for AccountData {
    fn sign_challenge(
        &self,
        challenge: &Challenge,
    ) -> BTreeMap<KeyIndex, AccountOwnershipSignature> {
        self.keys
            .iter()
            .map(|(&idx, kp)| {
                let expanded_sk = ed25519::ExpandedSecretKey::from(&kp.secret);
                (idx, expanded_sk.sign(challenge.as_ref(), &kp.public).into())
            })
            .collect()
    }
}


impl PublicInitialAccountData for InitialAccountData {
    fn get_threshold(&self) -> SignatureThreshold { self.threshold }

    fn get_public_keys(&self) -> Vec<VerifyKey> {
        self.keys
            .values()
            .map(|kp| VerifyKey::Ed25519VerifyKey(kp.public))
            .collect::<Vec<_>>()
    }
}

impl InitialAccountDataWithSigning for InitialAccountData {
    fn sign_public_information_for_ip<C: Curve>(
        &self,
        pub_info_for_ip: &PublicInformationForIP<C>,
    ) -> BTreeMap<KeyIndex, AccountOwnershipSignature> {
        let to_sign = Sha256::digest(&to_bytes(pub_info_for_ip));
        self.keys
            .iter()
            .map(|(&idx, kp)| {
                let expanded_sk = ed25519::ExpandedSecretKey::from(&kp.secret);
                (idx, expanded_sk.sign(&to_sign, &kp.public).into())
            })
            .collect()
    }
}

pub struct AccountDataVisitor;

impl<'de> Visitor<'de> for AccountDataVisitor {
    type Value = AccountData;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Account data structure.")
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        let mut map = map;
        let mut keys: Option<BTreeMap<KeyIndex, BTreeMap<String, String>>> = None;
        let mut existing = None;
        while keys.is_none() || existing.is_none() {
            if let Some(k) = map.next_key::<String>()? {
                if k == "keys" {
                    if keys.is_none() {
                        keys = Some(map.next_value()?);
                    } else {
                        return Err(de::Error::custom("Duplicate key 'keys'."));
                    }
                } else if k == "threshold" {
                    if existing.is_none() {
                        existing = Some(Either::Left(map.next_value()?))
                    } else {
                        return Err(de::Error::custom("Duplicate key 'threshold'."));
                    }
                } else if k == "address" {
                    if existing.is_none() {
                        existing = Some(Either::Right(map.next_value()?))
                    } else {
                        return Err(de::Error::custom("Duplicate key 'address'."));
                    }
                }
            } else {
                return Err(de::Error::custom(
                    "At least the two keys 'keys' and 'threshold'/'address' are expected.",
                ));
            }
        }
        let mut out_keys = BTreeMap::new();
        for (&idx, kp) in keys.unwrap().iter() {
            let vf_key = kp
                .get("verifyKey")
                .ok_or_else(|| de::Error::custom("verifyKey not present."))?;
            let public = base16_decode_string(vf_key).map_err(de::Error::custom)?;
            let sign_key = kp
                .get("signKey")
                .ok_or_else(|| de::Error::custom("signKey not present."))?;
            let secret = base16_decode_string(sign_key).map_err(de::Error::custom)?;
            if out_keys
                .insert(idx, ed25519::Keypair { secret, public })
                .is_some()
            {
                return Err(de::Error::custom("duplicate key index."));
            }
        }
        Ok(AccountData {
            keys:     out_keys,
            existing: existing.unwrap(),
        })
    }
}

// Manual implementation to be able to encode length as 1.
impl Serial for AccountData {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.keys.len() as u8;
        out.put(&len);
        serial_map_no_length(&self.keys, out);
        out.put(&self.existing);
    }
}

impl Deserial for AccountData {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u8 = source.get()?;
        if len == 0 {
            bail!("Need at least one key.")
        }
        let keys = deserial_map_no_length(source, usize::from(len))?;
        let existing = source.get()?;
        Ok(AccountData { keys, existing })
    }
}

/// Public account keys currently on the account, together with the threshold
/// needed for a valid signature on a transaction.
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct AccountKeys {
    #[serde(rename = "keys")]
    pub keys: BTreeMap<KeyIndex, VerifyKey>,
    #[serde(rename = "threshold")]
    pub threshold: SignatureThreshold,
}

impl Serial for AccountKeys {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.keys.len() as u8;
        out.put(&len);
        serial_map_no_length(&self.keys, out);
        out.put(&self.threshold);
    }
}

impl Deserial for AccountKeys {
    fn deserial<R: ReadBytesExt>(cur: &mut R) -> Fallible<Self> {
        let len = cur.read_u8()?;
        if len == 0 {
            bail!(format_err!("At least one key must be present."));
        }
        let keys = deserial_map_no_length(cur, usize::from(len))?;
        let threshold = cur.get()?;
        Ok(AccountKeys { keys, threshold })
    }
}

impl AccountKeys {
    pub fn get(&self, idx: KeyIndex) -> Option<&VerifyKey> { self.keys.get(&idx) }
}

/// Serialization of relevant types.
impl Serial for SchemeId {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            SchemeId::Ed25519 => out.write_u8(0).expect("Writing to buffer is safe."),
        }
    }
}

impl Deserial for SchemeId {
    fn deserial<R: ReadBytesExt>(cur: &mut R) -> Fallible<Self> {
        match cur.read_u8()? {
            0 => Ok(SchemeId::Ed25519),
            _ => bail!("Only Ed25519 signature scheme supported."),
        }
    }
}

/// Metadata that we need off-chain for various purposes, but should not go on
/// the chain.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize, Default)]
pub struct IpMetadata {
    #[string_size_length = 4]
    #[serde(rename = "issuanceStart")]
    pub issuance_start: String,
    #[string_size_length = 4]
    #[serde(rename = "icon")]
    pub icon: String,
}

/// Private and public data on an identity provider.
/// This is used purely off-chain.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(bound(serialize = "P: Pairing", deserialize = "P: Pairing"))]
pub struct IpData<P: Pairing> {
    #[serde(rename = "ipInfo")]
    pub public_ip_info: IpInfo<P>,
    #[serde(
        rename = "ipSecretKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub ip_secret_key: ps_sig::SecretKey<P>,
    #[serde(
        rename = "ipCdiSecretKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub ip_cdi_secret_key: ed25519::SecretKey,
}

/// Private and public data on an anonymity revoker.
/// This is used purely off-chain.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct ArData<C: Curve> {
    #[serde(rename = "arInfo")]
    pub public_ar_info: ArInfo<C>,
    #[serde(
        rename = "arSecretKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub ar_secret_key: ElgamalSecretKey<C>,
}

/// Data needed to use the retrieved identity object to generate credentials.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>"
))]
pub struct IdObjectUseData<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    #[serde(rename = "aci")]
    pub aci: AccCredentialInfo<C>,
    /// Randomness needed to retrieve the signature on the attribute list.
    #[serde(
        rename = "randomness",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub randomness: SigRetrievalRandomness<P>,
}

/// Data that needs to be stored by the identity provider to support anonymity
/// revocation.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct AnonymityRevocationRecord<C: Curve> {
    /// The number that identifies the identity object to the identity provider.
    #[serde(
        rename = "idCredPub",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub id_cred_pub: C,
    /// Data that contains encryptions of the prf key that supports additional
    /// anonymity revocation.
    #[serde(rename = "arData")]
    pub ar_data: BTreeMap<ArIdentity, IpArData<C>>,
    #[serde(rename = "maxAccounts")]
    pub max_accounts: u8,
}

/// A type encapsulating both types of credentials.
/// Serialization must match the one in Haskell.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "type", content = "contents")]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                 Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                   Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub enum AccountCredential<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    #[serde(rename = "initial")]
    Initial {
        #[serde(flatten)]
        icdi: InitialCredentialDeploymentInfo<C, AttributeType>,
    },
    #[serde(rename = "normal")]
    Normal {
        #[serde(flatten)]
        cdi: CredentialDeploymentInfo<P, C, AttributeType>,
    },
}

/// A type encapsulating both types of credential values, analogous to
/// AccountCredential.
/// Serialization must match the one in Haskell.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "type", content = "contents")]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub enum AccountCredentialValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "initial")]
    Initial {
        #[serde(flatten)]
        icdi: InitialCredentialDeploymentValues<C, AttributeType>,
    },
    #[serde(rename = "normal")]
    Normal {
        #[serde(flatten)]
        cdi: CredentialDeploymentValues<C, AttributeType>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::Signer;

    #[test]
    fn test_serde_sig() {
        use rand::thread_rng;

        let mut csprng = thread_rng();
        let keypair = ed25519::Keypair::generate(&mut csprng);
        for _ in 0..1000 {
            let message: &[u8] = b"test";
            let signature: AccountOwnershipSignature = keypair.sign(message).into();
            let serialized = serde_json::to_string(&signature).unwrap();
            let deserialized: AccountOwnershipSignature =
                serde_json::from_str(&serialized).unwrap();
            assert_eq!(signature, deserialized);
        }
    }

    #[test]
    fn test_yearmonth_serialization() {
        // Test equality
        let ym1 = YearMonth::new(2020, 02).unwrap();
        let ym2 = YearMonth::new(2020, 02).unwrap();
        assert_eq!(ym1, ym2);

        // Test serialization
        let mut buf = Vec::new();
        buf.put(&ym1);
        let mut cursor = std::io::Cursor::new(buf);
        let ym1_parsed = cursor.get().unwrap();
        assert_eq!(ym1, ym1_parsed);

        // Test JSON serialization
        let json = serde_json::to_string(&ym1).unwrap();
        assert_eq!("\"202002\"", json);
        let ym1_parsed = serde_json::from_str(&json).unwrap();
        assert_eq!(ym1, ym1_parsed);

        // Test u64 serialization
        // 202002 => hex: 00000111 11100100 00000010 = dec: 7 228 2 = u64: 517122
        let num: u64 = u64::from(ym1);
        assert_eq!(num, 517122);
        let ym1_parsed = YearMonth::try_from(num).unwrap();
        assert_eq!(ym1, ym1_parsed);
    }
}
