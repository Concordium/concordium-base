use crate::secret_sharing::{ShareNumber, Threshold};
use crypto_common::*;
use curve_arithmetic::curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as acc_sig_scheme;
use ed25519_dalek as ed25519;
use eddsa_ed25519::dlog_ed25519::Ed25519DlogProof;
use elgamal::{cipher::Cipher, secret::SecretKey as ElgamalSecretKey};
use ff::{Field, PrimeField};
use hex::{decode, encode};
use pedersen_scheme::{
    commitment as pedersen, key::CommitmentKey as PedersenKey, Randomness as PedersenRandomness,
    Value as PedersenValue,
};
use ps_sig::{public as pssig, signature::*, unknown_message::SigRetrievalRandomness};
use std::{collections::btree_map::BTreeMap, str::FromStr};

use crate::sigma_protocols::{
    com_enc_eq::ComEncEqProof, com_eq::ComEqProof, com_eq_different_groups::ComEqDiffGrpsProof,
    com_eq_sig::ComEqSigProof, com_mult::ComMultProof, dlog::DlogProof,
};

use serde::{
    de, de::Visitor, ser::SerializeMap, Deserialize as SerdeDeserialize, Deserializer,
    Serialize as SerdeSerialize, Serializer,
};

use byteorder::{BigEndian, ReadBytesExt};
use either::Either;
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt,
    io::{Cursor, Read},
};

use failure;

use sha2::{Digest, Sha256};

// only for account addresses
use base58check::*;

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct AccountAddress([u8; ACCOUNT_ADDRESS_SIZE]);

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

impl SerdeSerialize for AccountAddress {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let b58_str = self.0.to_base58check(1);
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
        out.copy_from_slice(&hasher.result());
        AccountAddress(out)
    }
}

/// Threshold for the number of signatures required.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
/// The values of this type must maintain the property that they are not 0.
#[serde(transparent)]
#[derive(SerdeSerialize)]
pub struct SignatureThreshold(pub u8);

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
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct KeyIndex(pub u8);

#[derive(Debug, PartialEq, Eq)]
/// List of pairs of index of key and proof.
/// The list should be non-empty and at most 255 elements long, and have no
/// duplicates. The current choice of data structure disallows duplicates by
/// design.
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct AccountOwnershipProof {
    pub proofs: BTreeMap<KeyIndex, Ed25519DlogProof>,
}

// Manual implementation to be able to encode length as 1, as well as to
// make sure there is at least one proof.
impl Serial for AccountOwnershipProof {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.proofs.len() as u8;
        out.put(&len);
        serial_map_no_length(&self.proofs, out)
    }
}

impl Deserial for AccountOwnershipProof {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u8 = source.get()?;
        if len == 0 {
            bail!("Need at least one proof.")
        }
        let proofs = deserial_map_no_length(source, usize::from(len))?;
        Ok(AccountOwnershipProof { proofs })
    }
}

impl AccountOwnershipProof {
    /// Number of individual proofs in this proof.
    /// NB: This method relies on the invariant that proofs should not
    /// have more than 255 elements.
    pub fn num_proofs(&self) -> SignatureThreshold {
        SignatureThreshold(self.proofs.len() as u8)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct IpIdentity(pub u32);

impl fmt::Display for IpIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct ArIdentity(pub u32);

impl fmt::Display for ArIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(try_from = "AttributeStringTag", into = "AttributeStringTag")]
pub struct AttributeTag(pub u8);

/// Encode attribute tags into a big-integer bits. The tags are encoded from
/// least significant bit up, i.e., LSB of the result is set IFF tag0 is in the
/// list. This function will fail if
/// - there are repeated attributes in the list
/// - there are tags in the list which do not fit into the field capacity
pub fn encode_tags<'a, F: PrimeField, I: std::iter::IntoIterator<Item = &'a AttributeTag>>(
    i: I,
) -> Fallible<F> {
    // Since F is supposed to be a field, its capacity must be at least 1, hence the
    // next line is safe. Maximum tag that can be stored.
    let max_tag = F::CAPACITY - 1;
    let mut f = F::zero().into_repr();
    let limbs = f.as_mut(); // this is an array of 64 bit limbs, with least significant digit first
    for &AttributeTag(tag) in i.into_iter() {
        let idx = tag / 64;
        let place = tag % 64;
        if u32::from(tag) > max_tag || usize::from(idx) > limbs.len() {
            bail!("Tag out of range: {}", tag)
        }
        let mask: u64 = 1 << place;
        if limbs[usize::from(idx)] & mask != 0 {
            bail!("Duplicate tag {}", tag)
        } else {
            limbs[usize::from(idx)] |= mask;
        }
    }
    // This should not fail (since we check capacity), but in case it does we just
    // propagate the error.
    Ok(F::from_repr(f)?)
}

/// Given two ordered iterators call the corresponding functions in the
/// increasing order of keys. That is, essentially merge the two iterators into
/// an ordered iterator and then map, but this is all done inline.
pub fn merge_iter<'a, K: Ord + 'a, V1: 'a, V2: 'a, I1, I2, F>(i1: I1, i2: I2, mut f: F)
where
    I1: std::iter::IntoIterator<Item = (&'a K, &'a V1)>,
    I2: std::iter::IntoIterator<Item = (&'a K, &'a V2)>,
    F: FnMut(Either<&'a V1, &'a V2>),
{
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
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
    fn into(self) -> usize {
        self.0.into()
    }
}

impl From<u8> for AttributeTag {
    fn from(x: u8) -> Self {
        AttributeTag(x)
    }
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
    pub year: u16,
    pub month: u8,
}

impl SerdeSerialize for YearMonth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}{:0>2}", self.year, self.month);
        serializer.serialize_str(&s)
    }
}

impl<'de> SerdeDeserialize<'de> for YearMonth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
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
        E: de::Error,
    {
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
        Ok(YearMonth { year, month })
    }
}

impl std::str::FromStr for YearMonth {
    type Err = failure::Error;

    fn from_str(s: &str) -> Fallible<Self> {
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
            year: now.year() as u16,
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
        if year < 1000 || year >= 10000 || month < 1 || month > 12 {
            return Err(());
        }
        Ok(YearMonth { year, month })
    }
}

impl From<YearMonth> for u64 {
    /// Convert expiry (year and month) to unsigned 64-bit integer.
    /// Least significant byte is month, following two bytes are year
    fn from(v: YearMonth) -> Self {
        u64::from(v.month) | (u64::from(v.year) << 8)
    }
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
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct IdCredentials<C: Curve> {
    /// secret id credentials
    pub id_cred_sec: PedersenValue<C>,
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
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct IpArData<C: Curve> {
    /// identity of the anonymity revoker (for now this needs to be unique per
    /// IP) if stored in the chain it needs to be unique in general
    #[serde(rename = "arIdentity")]
    pub ar_identity: ArIdentity,
    #[serde(rename = "encPrfKeyShare")]
    pub enc_prf_key_share: Cipher<C>,
    /// the number of the share
    #[serde(rename = "prfKeyShareNumber")]
    pub prf_key_share_number: ShareNumber,
    /// proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    #[serde(rename = "proofComEncEq")]
    pub proof_com_enc_eq: ComEncEqProof<C>,
}

/// Data relating to a single anonymity revoker sent by the account holder to
/// the chain.
/// Typically a vector of these will be sent to the chain.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct ChainArData<C: Curve> {
    /// identity of the anonymity revoker
    #[serde(rename = "arIdentity")]
    pub ar_identity: ArIdentity,
    /// encrypted share of id cred pub
    #[serde(rename = "encIdCredPubShare")]
    pub enc_id_cred_pub_share: Cipher<C>,
    /// the number of the share
    #[serde(rename = "idCredPubShareNumber")]
    pub id_cred_pub_share_number: ShareNumber,
}

/// Choice of anonymity revocation parameters
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
pub struct ChoiceArParameters {
    #[serde(rename = "arIdentities")]
    #[size_length = 4]
    pub ar_identities: Vec<ArIdentity>,
    #[serde(rename = "threshold")]
    pub threshold: Threshold,
}

/// Information sent from the account holder to the identity provider.
/// This includes only the cryptographic parts, the attribute list is
/// in a different object below.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar=P::ScalarField>"
))]
pub struct PreIdentityObject<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Public credential of the account holder in the anonymity revoker's
    /// group.
    #[serde(
        rename = "idCredPub",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub id_cred_pub: C,
    /// Anonymity revocation data for the chosen anonymity revokers.
    #[serde(rename = "ipArData")]
    pub ip_ar_data: Vec<IpArData<C>>,
    /// choice of anonyimity revocation parameters
    /// the vec is a vector of ar identities
    /// the second element of the pair is the threshold for revocation.
    /// must be less than or equal the length of the vector.
    /// NB:IP needs to check this
    #[serde(rename = "choiceArData")]
    pub choice_ar_parameters: ChoiceArParameters,
    /// Proof of knowledge of secret credentials corresponding to id_cred_pub
    #[serde(rename = "pokSecCred")]
    pub pok_sc: DlogProof<C>,
    /// Commitment to id cred sec using the commitment key of IP derived from
    /// the PS public key. This is used to compute the message that the IP
    /// signs.
    #[serde(rename = "idCredSecCommitment")]
    pub cmm_sc: pedersen::Commitment<P::G1>,
    /// Proof that cmm_sc and id_cred_pub are hiding the same value.
    #[serde(rename = "proofCommitmentsToIdCredSecSame")]
    pub proof_com_eq_sc: ComEqProof<P::G1>,
    /// Commitment to the prf key in group G1.
    #[serde(rename = "prfKeyCommitmentWithIP")]
    pub cmm_prf: pedersen::Commitment<P::G1>,
    /// commitments to the coefficients of the polynomial
    /// used to share the prf key
    /// K + b1 X + b2 X^2...
    /// where K is the prf key
    #[serde(rename = "prfKeySharingCoeffCommitments")]
    pub cmm_prf_sharing_coeff: Vec<pedersen::Commitment<C>>,
    /// Proof that the first and snd commitments to the prf are hiding the same
    /// value. The first commitment is cmm_prf and the second is the first in
    /// the vec cmm_prf_sharing_coeff
    #[serde(rename = "proofCommitmentsSame")]
    pub proof_com_eq: ComEqDiffGrpsProof<P::G1, C>,
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
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>"
))]
pub struct IpInfo<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Unique identifier of the identity provider.
    #[serde(rename = "ipIdentity")]
    pub ip_identity: IpIdentity,
    /// Free form description, e.g., how to contact them off-chain
    #[serde(rename = "ipDescription")]
    pub ip_description: Description,
    /// PS public key of the IP
    #[serde(rename = "ipVerifyKey")]
    pub ip_verify_key: pssig::PublicKey<P>,
    #[serde(rename = "ipAnonymityRevokers")]
    pub ip_ars: IpAnonymityRevokers<C>,
}

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
    pub ar_public_key: elgamal::PublicKey<C>,
}

/// The commitments sent by the account holder to the chain in order to
/// deploy credentials
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct CredDeploymentCommitments<C: Curve> {
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

// FIXME: The sig should be part of the values so that it is part of the
// challenge computation.
#[derive(Debug, PartialEq, Eq, SerdeBase16IgnoreLengthSerialize)]
pub struct CredDeploymentProofs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// (Blinded) Signature derived from the signature on the pre-identity
    /// object by the IP
    pub sig: BlindedSignature<P>,
    /// list of  commitments to the attributes .
    pub commitments: CredDeploymentCommitments<C>,
    /// Proofs that the encrypted shares of id_cred_pub and
    /// commitments (in chain_ar_data) hide the same values.
    /// each proof is indexed by the share number.
    pub proof_id_cred_pub: Vec<(ShareNumber, ComEncEqProof<C>)>,
    /// Proof of knowledge of signature of Identity Provider on the list
    /// (idCredSec, prfKey, attributes[0], attributes[1],..., attributes[n],
    /// AR[1], ..., AR[m])
    pub proof_ip_sig: ComEqSigProof<P, C>,
    /// Proof that reg_id = prf_K(x). Also establishes that reg_id is computed
    /// from the prf key signed by the identity provider.
    pub proof_reg_id: ComMultProof<C>,
    /// Proof of knowledge of acc secret keys (signing keys corresponding to the
    /// verification keys either on the account already, or the ones which are
    /// part of this credential.
    /// TODO: This proof can be replaced by a signature if we only allow
    /// deploying proofs on own account.
    /// We could consider replacing this proof by just a list of signatures.
    pub proof_acc_sk: AccountOwnershipProof,
    /* Proof that the attribute list in commitments.cmm_attributes satisfy the
     * policy for now this is mainly achieved by opening the corresponding
     * commitments.
     * pub proof_policy: PolicyProof<C>, */
}

// This is an unfortunate situation, but we need to manually write a
// serialization instance for the proofs so that we can insert the length of the
// whole proof upfront. This is needed for easier interoperability with Haskell.
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Serial for CredDeploymentProofs<P, C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let mut tmp_out = Vec::new();
        tmp_out.put(&self.sig);
        tmp_out.put(&self.commitments);
        tmp_out.put(&self.proof_id_cred_pub);
        tmp_out.put(&self.proof_ip_sig);
        tmp_out.put(&self.proof_reg_id);
        tmp_out.put(&self.proof_acc_sk);
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
        let proof_id_cred_pub = limited.get()?;
        let proof_ip_sig = limited.get()?;
        let proof_reg_id = limited.get()?;
        let proof_acc_sk = limited.get()?;
        if limited.limit() == 0 {
            Ok(CredDeploymentProofs {
                sig,
                commitments,
                proof_id_cred_pub,
                proof_ip_sig,
                proof_reg_id,
                proof_acc_sk,
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

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PolicyProof<C: Curve> {
    /// Randomness to open the variant commitment.
    pub variant_rand: PedersenRandomness<C>,
    /// Randomness to open the expiry commitment.
    pub expiry_rand: PedersenRandomness<C>,
    /// The u16 is the index of the attribute
    /// The Scalar is the witness (technically the randomness in the commitment)
    /// i.e. to open.
    pub cmm_opening_map: Vec<(u16, PedersenRandomness<C>)>,
}

#[derive(Debug, Eq)]
pub enum VerifyKey {
    Ed25519VerifyKey(acc_sig_scheme::PublicKey),
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
        let mut tmp_map: BTreeMap<&str, &str> = BTreeMap::new();
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
        Ok(key)
    }
}

impl From<acc_sig_scheme::PublicKey> for VerifyKey {
    fn from(pk: acc_sig_scheme::PublicKey) -> Self {
        VerifyKey::Ed25519VerifyKey(pk)
    }
}

impl From<&ed25519::Keypair> for VerifyKey {
    fn from(kp: &ed25519::Keypair) -> Self {
        VerifyKey::Ed25519VerifyKey(kp.public)
    }
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
    fn partial_cmp(&self, other: &VerifyKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VerifyKey {
    fn eq(&self, other: &VerifyKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
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
        des.deserialize_map(CredentialAccountVisitor)
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
            if let Some(k) = map.next_key::<&str>()? {
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

/// Values (as opposed to proofs) in credential deployment.
#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredentialDeploymentValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Account this credential belongs to. Either an existing account, or keys
    /// of a new account.
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
    #[size_length = 2]
    #[serde(rename = "arData")]
    pub ar_data: Vec<ChainArData<C>>,
    /// Policy of this credential object.
    #[serde(rename = "policy")]
    pub policy: Policy<C, AttributeType>,
}

#[derive(Debug, PartialEq, Eq, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                 Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: \
                   Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredDeploymentInfo<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    #[serde(flatten)]
    pub values: CredentialDeploymentValues<C, AttributeType>,
    #[serde(rename = "proofs")] // FIXME: This should remove the first 4 bytes
    pub proofs: CredDeploymentProofs<P, C>,
}

/// Context needed to generate pre-identity object.
/// This context is derived from the public information of the identity
/// provider, as well as some other global parameters which can be found in the
/// struct 'GlobalContext'.
/// FIXME: This is a remnant from how things were at some point, and probably
/// needs to be updated.
#[derive(Serialize)]
pub struct Context<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Public information on the chosen identity provider and anonymity
    /// revoker(s).
    pub ip_info: IpInfo<P, C>,
    /// choice of anonyimity revocation parameters
    /// that is a choice of subset of anonymity revokers
    /// and a threshold parameter.
    pub choice_ar_parameters: (Vec<ArInfo<C>>, Threshold),
}

#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
pub struct GlobalContext<C: Curve> {
    /// A shared commitment key known to the chain and the account holder (and
    /// therefore it is public). The account holder uses this commitment key to
    /// generate commitments to values in the attribute list.
    /// This key should presumably be generated at genesis time via some shared
    /// multi-party computation since none of the parties should know anything
    /// special about it (so that commitment is binding, and that the commitment
    /// cannot be broken).
    #[serde(rename = "onChainCommitmentKey")]
    pub on_chain_commitment_key: PedersenKey<C>,
}

/// Make a context in which the account holder can produce a pre-identity object
/// to send to the identity provider. Also requires access to the global context
/// of parameters, e.g., dlog-proof base point.
pub fn make_context_from_ip_info<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    ip_info: IpInfo<P, C>,
    choice_ar_handles: ChoiceArParameters,
) -> Option<Context<P, C>> {
    let mut choice_ars = Vec::with_capacity(choice_ar_handles.ar_identities.len());
    let ip_ar_parameters = &ip_info.ip_ars.ars.clone();
    for ar in choice_ar_handles.ar_identities.into_iter() {
        match ip_ar_parameters.iter().find(|&x| x.ar_identity == ar) {
            None => return None,
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }

    Some(Context {
        ip_info,
        choice_ar_parameters: (choice_ars, choice_ar_handles.threshold),
    })
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
            keys: out_keys,
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
    pub fn get(&self, idx: KeyIndex) -> Option<&VerifyKey> {
        self.keys.get(&idx)
    }
}

/// Serialization of relevant types.

/// Serialize a string by putting the length first as 2 bytes, big endian.
pub fn short_string_to_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let l = bytes.len();
    assert!(l < 65536);
    let mut out = crypto_common::safe_with_capacity(l + 2);
    out.extend_from_slice(&(l as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
/// TODO: We really should not be using Strings.
pub fn bytes_to_short_string(cur: &mut Cursor<&[u8]>) -> Option<String> {
    let l = cur.read_u16::<BigEndian>().ok()?;
    let mut svec = vec![0; l as usize];
    cur.read_exact(&mut svec).ok()?;
    String::from_utf8(svec).ok()
}

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

impl ArIdentity {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar {
        C::scalar_from_u64(u64::from(self.0))
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
#[derive(SerdeSerialize, SerdeDeserialize, Serialize)]
#[serde(bound(
    serialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>",
    deserialize = "P: Pairing, C: Curve<Scalar = P::ScalarField>"
))]
pub struct IpData<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Off-chain metadata about the identity provider
    #[serde(rename = "metadata")]
    pub metadata: IpMetadata,
    #[serde(rename = "ipInfo")]
    pub public_ip_info: IpInfo<P, C>,
    #[serde(
        rename = "ipSecretKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub ip_secret_key: ps_sig::SecretKey<P>,
}

/// Private and public data on an anonymity revoker.
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

#[cfg(test)]
mod tests {
    use super::*;

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
