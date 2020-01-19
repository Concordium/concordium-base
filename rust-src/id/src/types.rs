use crate::secret_sharing::{ShareNumber, Threshold};
use common;
use curve_arithmetic::{curve_arithmetic::*, serialization as curve_serialization};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as acc_sig_scheme;
use ed25519_dalek as ed25519;
use eddsa_ed25519::dlog_ed25519::Ed25519DlogProof;
use elgamal::cipher::Cipher;
use ff::Field;
use hex::{decode, encode};
use pedersen_scheme::{
    commitment as pedersen, key::CommitmentKey as PedersenKey, Randomness as PedersenRandomness,
    Value as PedersenValue,
};
use ps_sig::{public as pssig, signature::*};
use std::collections::btree_map::BTreeMap;

use crate::sigma_protocols::{
    com_enc_eq::ComEncEqProof, com_eq::ComEqProof, com_eq_different_groups::ComEqDiffGrpsProof,
    com_eq_sig::ComEqSigProof, com_mult::ComMultProof, dlog::DlogProof,
};

use serde_json::{json, Number, Value};

use byteorder::{BigEndian, ReadBytesExt};
use either::{
    Either,
    Either::{Left, Right},
};
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt,
    io::{Cursor, Read},
};

use sha2::{Digest, Sha256};

macro_rules! m_json_decode {
    ($val:expr, $key:expr) => {
        &mut Cursor::new(&json_base16_decode($val.get($key)?)?)
    };
}

// only for account addresses
use base58check::*;

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct AccountAddress([u8; ACCOUNT_ADDRESS_SIZE]);

impl AccountAddress {
    pub fn to_json(&self) -> Value {
        let body = self.0.to_base58check(1);
        Value::String(body)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let (version, body) = v.as_str()?.from_base58check().ok()?;
        if version == 1 && body.len() == ACCOUNT_ADDRESS_SIZE {
            let mut addr = [0; ACCOUNT_ADDRESS_SIZE];
            addr.copy_from_slice(&body);
            Some(AccountAddress(addr))
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> Box<[u8]> { self.0.to_vec().into_boxed_slice() }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let mut buf = [0; ACCOUNT_ADDRESS_SIZE];
        cur.read_exact(&mut buf).ok()?;
        Some(AccountAddress(buf))
    }

    /// Construct account address from the registration id.
    pub fn new<C: Curve>(reg_id: &C) -> Self {
        let mut out = [0; ACCOUNT_ADDRESS_SIZE];
        let hasher = Sha256::new().chain(&reg_id.curve_to_bytes());
        out.copy_from_slice(&hasher.result());
        AccountAddress(out)
    }
}

/// Threshold for the number of signatures required.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[repr(transparent)]
/// The values of this type must maintain the property that they are not 0.
pub struct SignatureThreshold(pub u8);

impl SignatureThreshold {
    pub fn to_json(self) -> Value { Value::Number(Number::from(self.0)) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = v.as_u64()?;
        if v < 256 && v > 0 {
            Some(SignatureThreshold(v as u8))
        } else {
            None
        }
    }

    pub fn to_bytes(self) -> Box<[u8]> { vec![self.0].into_boxed_slice() }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let x = cur.read_u8().ok()?;
        if x != 0 {
            Some(SignatureThreshold(x))
        } else {
            None
        }
    }
}

/// Index of an account key that is to be used.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[repr(transparent)]
pub struct KeyIndex(pub u8);

impl KeyIndex {
    pub fn to_json(self) -> Value { Value::Number(Number::from(self.0)) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = v.as_u64()?;
        if v < 256 {
            Some(KeyIndex(v as u8))
        } else {
            None
        }
    }

    pub fn to_bytes(self) -> Box<[u8]> { vec![self.0].into_boxed_slice() }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let x = cur.read_u8().ok()?;
        Some(KeyIndex(x))
    }
}

#[derive(Debug, PartialEq, Eq)]
/// List of pairs of index of key and proof.
/// The list should be non-empty and at most 255 elements long, and have no
/// duplicates. The current choice of data structure disallows duplicates by
/// design.
pub struct AccountOwnershipProof {
    pub proofs: BTreeMap<KeyIndex, Ed25519DlogProof>,
}

impl AccountOwnershipProof {
    /// Number of individual proofs in this proof.
    /// NB: This method relies on the invariant that proofs should not
    /// have more than 255 elements.
    pub fn num_proofs(&self) -> SignatureThreshold { SignatureThreshold(self.proofs.len() as u8) }

    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut out = Vec::new();
        // relies on invariant about the length
        let len = self.proofs.len() as u8;
        out.push(len);
        for (idx, proof) in self.proofs.iter() {
            out.extend_from_slice(&idx.to_bytes());
            out.extend_from_slice(&proof.to_bytes());
        }
        out.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let len = cur.read_u8().ok()?;
        if len == 0 {
            return None;
        }
        let mut proofs = BTreeMap::new();
        for _ in 0..len {
            let idx = KeyIndex::from_bytes(cur)?;
            let proof = Ed25519DlogProof::from_bytes(cur).ok()?;
            // insert and check for duplicates at the same time
            if proofs.insert(idx, proof).is_some() {
                // cannot have duplicates
                return None;
            }
        }
        Some(AccountOwnershipProof { proofs })
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[repr(transparent)]
pub struct IpIdentity(pub u32);

impl fmt::Display for IpIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct ArIdentity(pub u32);

impl fmt::Display for ArIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

pub trait Attribute<F: Field>: Copy + Clone + Sized + Send + Sync + fmt::Display {
    // convert an attribute to a field element
    fn to_field_element(&self) -> F;
    fn to_bytes(&self) -> Box<[u8]>;
    fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self>;
}

#[derive(Clone, Debug)]
pub struct AttributeList<F: Field, AttributeType: Attribute<F>> {
    pub variant:  u16,
    pub expiry:   u64,
    pub alist:    Vec<AttributeType>,
    pub _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug)]
/// In our case C: will be G_1 and T will be G_1 for now A secret credential is
/// a scalar raising a generator to this scalar gives a public credentials. If
/// two groups have the same scalar field we can have two different public
/// credentials from the same secret credentials.
pub struct IdCredentials<C: Curve> {
    /// secret id credentials
    pub id_cred_sec: PedersenValue<C>,
}

/// Private credential holder information. A user maintaints these
/// through many different interactions with the identity provider and
/// the chain.
#[derive(Debug)]
pub struct CredentialHolderInfo<C: Curve> {
    /// Name of the credential holder.
    pub id_ah: String,
    /// Public and private keys of the credential holder. NB: These are distinct
    /// from the public/private keys of the account holders.
    pub id_cred: IdCredentials<C>,
}

/// Private and public data chosen by the credential holder before the
/// interaction with the identity provider. The credential holder chooses a prf
/// key and an attribute list.
#[derive(Debug)]
pub struct AccCredentialInfo<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub acc_holder_info: CredentialHolderInfo<C>,
    /// Chosen prf key of the credential holder.
    pub prf_key: prf::SecretKey<C>,
    /// Chosen attribute list.
    pub attributes: AttributeList<C::Scalar, AttributeType>,
}

/// The data relating to a single anonymity revoker
/// sent by the account holder to the identity provider
/// typically the account holder will send a vector of these
pub struct IpArData<C: Curve> {
    /// identity of the anonymity revoker (for now this needs to be unique per
    /// IP) if stored in the chain it needs to be unique in general
    pub ar_identity: ArIdentity,
    /// encrypted share of the prf key
    pub enc_prf_key_share: Cipher<C>,
    /// the number of the share
    pub prf_key_share_number: ShareNumber,
    /// proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    pub proof_com_enc_eq: ComEncEqProof<C>,
}

/// Data relating to a single anonymity revoker sent by the account holder to
/// the chain.
/// Typically a vector of these will be sent to the chain.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainArData<C: Curve> {
    /// identity of the anonymity revoker
    pub ar_identity: ArIdentity,
    /// encrypted share of id cred pub
    pub enc_id_cred_pub_share: Cipher<C>,
    /// the number of the share
    pub id_cred_pub_share_number: ShareNumber,
}

/// Information sent from the account holder to the identity provider.
pub struct PreIdentityObject<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Name of the account holder.
    pub id_ah: String,
    /// Public credential of the account holder in the anonymity revoker's
    /// group.
    pub id_cred_pub: C,
    /// Anonymity revocation data for the chosen anonymity revokers.
    pub ip_ar_data: Vec<IpArData<C>>,
    /// choice of anonyimity revocation parameters
    /// the vec is a vector of ar identities
    /// the second element of the pair is the threshold for revocation.
    /// must be less than or equal the length of the vector.
    /// NB:IP needs to check this
    pub choice_ar_parameters: (Vec<ArIdentity>, Threshold),
    /// Chosen attribute list.
    pub alist: AttributeList<C::Scalar, AttributeType>,
    /// Proof of knowledge of secret credentials corresponding to id_cred_pub
    pub pok_sc: DlogProof<C>,
    /// proof of knowledge of secret credential corresponding to snd_cmm_sc
    pub snd_pok_sc: ComEqProof<C>,
    /// Commitment to id cred sec using the commitment key of IP derived from
    /// the PS public key. This is used to compute the message that the IP
    /// signs.
    pub cmm_sc: pedersen::Commitment<P::G_1>,
    /// Proof that cmm_sc and id_cred_pub are hiding the same value.
    pub proof_com_eq_sc: ComEqProof<P::G_1>,
    /// Commitment to the prf key in group G_1.
    pub cmm_prf: pedersen::Commitment<P::G_1>,
    /// commitments to the coefficients of the polynomial
    /// used to share the prf key
    /// K + b1 X + b2 X^2...
    /// where K is the prf key
    pub cmm_prf_sharing_coeff: Vec<pedersen::Commitment<C>>,
    /// Proof that the first and snd commitments to the prf are hiding the same
    /// value. The first commitment is cmm_prf and the second is the first in
    /// the vec cmm_prf_sharing_coeff
    pub proof_com_eq: ComEqDiffGrpsProof<P::G_1, C>,
}

/// Public information about an identity provider.
#[derive(Debug, Clone)]
pub struct IpInfo<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Unique identifier of the identity provider.
    pub ip_identity: IpIdentity,
    /// Free form description, e.g., how to contact them off-chain
    pub ip_description: String,
    /// PS publice signature key of the IP
    pub ip_verify_key: pssig::PublicKey<P>,
    /// list of approved anonymity revokers along with
    /// a shared commitment key
    /// TODO: How is this shared commitment key generated??
    pub ar_info: (Vec<ArInfo<C>>, PedersenKey<C>),
    /// Chosen generator of the group used by the anonymity revokers.
    pub ar_base: C,
}

/// Information on a single anonymity reovker held by the IP
/// typically an IP will hold a more than one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArInfo<C: Curve> {
    /// unique identifier of the anonymity revoker
    pub ar_identity: ArIdentity,
    /// description of the anonymity revoker (e.g. name, contact number)
    pub ar_description: String,
    /// elgamal encryption key of the anonymity revoker
    pub ar_public_key: elgamal::PublicKey<C>,
}

/// The commitments sent by the account holder to the chain in order to
/// deploy credentials
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CredDeploymentCommitments<C: Curve> {
    /// commitment to the prf key
    pub cmm_prf: pedersen::Commitment<C>,
    /// commitment to credential counter
    pub cmm_cred_counter: pedersen::Commitment<C>,
    /// List of commitments to the attributes that are not revealed.
    /// For the purposes of checking signatures, the commitments to those
    /// that are revealed as part of the policy are going to be computed by the
    /// verifier.
    pub cmm_attributes: BTreeMap<u16, pedersen::Commitment<C>>,
    /// commitments to the coefficients of the polynomial
    /// used to share id_cred_sec
    /// S + b1 X + b2 X^2...
    /// where S is id_cred_sec
    pub cmm_id_cred_sec_sharing_coeff: Vec<pedersen::Commitment<C>>,
}

// FIXME: The sig should be part of the values so that it is part of the
// challenge computation.
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Policy<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub variant: u16,
    /// Expiry time, in seconds since the unix epoch, ignoring leap seconds.
    pub expiry: u64,
    /// Revealed attributes, index in the attribute list together with the
    /// value. The proof part of the credential contains the proof that
    /// the revealed value is the same as that commited to and signed by the
    /// identity provider.
    /// INVARIANT: The indices must all have to be less than size
    /// of the attribute list this policy applies to.
    pub policy_vec: BTreeMap<u16, AttributeType>,
    pub _phantom: std::marker::PhantomData<C>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchemeId {
    Ed25519,
}

#[derive(Debug, PartialEq, Eq)]
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

impl From<acc_sig_scheme::PublicKey> for VerifyKey {
    fn from(pk: acc_sig_scheme::PublicKey) -> Self { VerifyKey::Ed25519VerifyKey(pk) }
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

impl VerifyKey {
    pub fn to_bytes(&self) -> Box<[u8]> {
        use VerifyKey::*;
        match self {
            Ed25519VerifyKey(ref key) => {
                let mut out = Vec::with_capacity(1 + acc_sig_scheme::PUBLIC_KEY_LENGTH);
                out.extend_from_slice(&SchemeId::Ed25519.to_bytes());
                out.extend_from_slice(key.as_bytes());
                out.into_boxed_slice()
            }
        }
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        use VerifyKey::*;
        match SchemeId::from_bytes(cur)? {
            SchemeId::Ed25519 => {
                let mut buf = [0; acc_sig_scheme::PUBLIC_KEY_LENGTH];
                cur.read_exact(&mut buf).ok()?;
                let key = acc_sig_scheme::PublicKey::from_bytes(&buf).ok()?;
                Some(Ed25519VerifyKey(key))
            }
        }
    }

    pub fn to_json(&self) -> Value {
        // ignore the first byte because it encodes the scheme.
        json_base16_encode(&self.to_bytes()[1..])
    }
}

/// What account should this credential be deployed to, or the keys of the new
/// account.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialAccount {
    ExistingAccount(AccountAddress),
    NewAccount(Vec<VerifyKey>, SignatureThreshold),
}

impl CredentialAccount {
    pub fn to_json(&self) -> Value {
        use CredentialAccount::*;
        match self {
            ExistingAccount(ref addr) => addr.to_json(),
            NewAccount(ref keys, threshold) => json!({
                "keys": keys.iter().map(VerifyKey::to_json).collect::<Vec<_>>(),
                "threshold": threshold.to_json()
            }),
        }
    }

    pub fn to_bytes(&self) -> Box<[u8]> {
        use CredentialAccount::*;
        match self {
            ExistingAccount(ref addr) => {
                let mut out = Vec::with_capacity(1 + ACCOUNT_ADDRESS_SIZE);
                out.push(0);
                out.extend_from_slice(&addr.to_bytes());
                out.into_boxed_slice()
            }
            NewAccount(ref keys, threshold) => {
                let mut out = Vec::with_capacity(3);
                let len = keys.len() as u8;
                out.push(1);
                out.push(len);
                for key in keys.iter() {
                    out.extend_from_slice(&key.to_bytes());
                }
                out.extend_from_slice(&threshold.to_bytes());
                out.into_boxed_slice()
            }
        }
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        use CredentialAccount::*;
        let c = cur.read_u8().ok()?;
        match c {
            0 => Some(ExistingAccount(AccountAddress::from_bytes(cur)?)),
            1 => {
                let len = cur.read_u8().ok()?;
                if len == 0 {
                    return None;
                }
                let mut keys = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    keys.push(VerifyKey::from_bytes(cur)?);
                }
                let threshold = SignatureThreshold::from_bytes(cur)?;
                Some(NewAccount(keys, threshold))
            }
            _ => None,
        }
    }
}

/// Values (as opposed to proofs) in credential deployment.
#[derive(Debug, PartialEq, Eq)]
pub struct CredentialDeploymentValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Account this credential belongs to. Either an existing account, or keys
    /// of a new account.
    pub cred_account: CredentialAccount,
    /// Credential registration id of the credential.
    pub reg_id: C,
    /// Identity of the identity provider who signed the identity object from
    /// which this credential is derived.
    pub ip_identity: IpIdentity,
    /// Anonymity revocation threshold. Must be <= length of ar_data.
    pub threshold: Threshold,
    /// Anonymity revocation data. List of anonymity revokers which can revoke
    /// identity. NB: The order is important since it is the same order as that
    /// signed by the identity provider, and permuting the list will invalidate
    /// the signature from the identity provider.
    pub ar_data: Vec<ChainArData<C>>,
    /// Policy of this credential object.
    pub policy: Policy<C, AttributeType>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredDeploymentInfo<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub values: CredentialDeploymentValues<C, AttributeType>,
    pub proofs: CredDeploymentProofs<P, C>,
}

/// Context needed to generate pre-identity object.
/// This context is derived from the public information of the identity
/// provider, as well as some other global parameters which can be found in the
/// struct 'GlobalContext'.
pub struct Context<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Public information on the chosen identity provider and anonymity
    /// revoker(s).
    pub ip_info: IpInfo<P, C>,
    /// choice of anonyimity revocation parameters
    /// that is a choice of subset of anonymity revokers
    /// threshold  parameter
    pub choice_ar_parameters: (Vec<ArInfo<C>>, Threshold),
}

pub struct GlobalContext<C: Curve> {
    /// A shared commitment key known to the chain and the account holder (and
    /// therefore it is public). The account holder uses this commitment key to
    /// generate commitments to values in the attribute list.
    /// This key should presumably be generated at genesis time via some shared
    /// multi-party computation since none of the parties should know anything
    /// special about it (so that commitment is binding, and that the commitment
    /// cannot be broken).
    pub on_chain_commitment_key: PedersenKey<C>,
}

/// Make a context in which the account holder can produce a pre-identity object
/// to send to the identity provider. Also requires access to the global context
/// of parameters, e.g., dlog-proof base point.
pub fn make_context_from_ip_info<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    ip_info: IpInfo<P, C>,
    choice_ar_handles: (Vec<ArIdentity>, Threshold),
) -> Context<P, C> {
    let mut choice_ars = Vec::with_capacity(choice_ar_handles.0.len());
    let ip_ar_parameters = &ip_info.ar_info.0.clone();
    for ar in choice_ar_handles.0.into_iter() {
        match ip_ar_parameters.iter().find(|&x| x.ar_identity == ar) {
            None => panic!("AR handle not in the IP list"),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }

    Context {
        ip_info,
        choice_ar_parameters: (choice_ars, choice_ar_handles.1),
    }
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

impl AccountData {
    pub fn from_json(v: &Value) -> Option<AccountData> {
        let mut keys = BTreeMap::new();
        for obj in v.get("keys")?.as_array()?.iter() {
            let obj = obj.as_object()?;
            let idx = obj.get("index").and_then(KeyIndex::from_json)?;
            let public =
                ed25519::PublicKey::from_bytes(&v.get("verifyKey").and_then(json_base16_decode)?)
                    .ok()?;
            let secret =
                ed25519::SecretKey::from_bytes(&v.get("signKey").and_then(json_base16_decode)?)
                    .ok()?;
            keys.insert(idx, ed25519::Keypair { public, secret });
        }
        // if threshold field is present we assume it is a new account
        if let Some(thr) = v.get("threshold") {
            let threshold = SignatureThreshold::from_json(thr)?;
            Some(AccountData {
                keys,
                existing: Left(threshold),
            })
        } else if let Some(addr) = v.get("address") {
            let address = AccountAddress::from_json(&addr)?;
            Some(AccountData {
                keys,
                existing: Right(address),
            })
        } else {
            None
        }
    }

    pub fn to_json(&self) -> Value {
        let mut out = Vec::with_capacity(self.keys.len());
        for (idx, kp) in self.keys.iter() {
            out.push(json!({
                "index": idx.to_json(),
                "verifyKey": json_base16_encode(kp.public.as_bytes()),
                "signKey": json_base16_encode(kp.public.as_bytes()),
            }));
        }
        match self.existing {
            Left(thr) => json!({
                "keys": out,
                "threshold": thr.to_json()
            }),
            Right(addr) => json!({
                "keys": out,
                "address": addr.to_json()
            }),
        }
    }
}

/// Public account keys currently on the account, together with the threshold
/// needed for a valid signature on a transaction.
pub struct AccountKeys {
    pub keys:      BTreeMap<KeyIndex, VerifyKey>,
    pub threshold: SignatureThreshold,
}

impl AccountKeys {
    pub fn get(&self, idx: KeyIndex) -> Option<&VerifyKey> { self.keys.get(&idx) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let len = cur.read_u8().ok()?;
        if len == 0 {
            return None;
        }
        let mut keys = BTreeMap::new();
        for _ in 0..len {
            let idx = KeyIndex::from_bytes(cur)?;
            let key = VerifyKey::from_bytes(cur)?;
            if keys.insert(idx, key).is_some() {
                return None;
            }
        }
        let threshold = SignatureThreshold::from_bytes(cur)?;
        Some(AccountKeys { keys, threshold })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.keys.len() as u8;
        let mut out = vec![len];
        for (idx, k) in self.keys.iter() {
            out.extend_from_slice(&idx.to_bytes());
            out.extend_from_slice(&k.to_bytes());
        }
        out.extend_from_slice(&self.threshold.to_bytes());
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "threshold": self.threshold.to_json(),
            "keys": self.keys.iter().map(|(idx, v)| json!({
                "index": idx.to_json(),
                "verifyKey": v.to_json(),
            })).collect::<Vec<_>>()
        })
    }
}

/// Serialization of relevant types.

/// Serialize a string by putting the length first as 2 bytes, big endian.
pub fn short_string_to_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let l = bytes.len();
    assert!(l < 65536);
    let mut out = common::safe_with_capacity(l + 2);
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

impl<C: Curve> IpArData<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut out = Vec::from(self.ar_identity.to_bytes());
        out.extend_from_slice(&self.enc_prf_key_share.to_bytes());
        out.extend_from_slice(&self.prf_key_share_number.to_bytes());
        out.extend_from_slice(&self.proof_com_enc_eq.to_bytes());
        out.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = ArIdentity::from_bytes(cur)?;
        let enc_prf_key_share = Cipher::from_bytes(cur).ok()?;
        let prf_key_share_number = ShareNumber::from_bytes(cur)?;
        let proof_com_enc_eq = ComEncEqProof::from_bytes(cur).ok()?;
        Some(IpArData {
            ar_identity,
            enc_prf_key_share,
            prf_key_share_number,
            proof_com_enc_eq,
        })
    }
}

impl<C: Curve> ChainArData<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut out = Vec::from(self.ar_identity.to_bytes());
        out.extend_from_slice(&self.enc_id_cred_pub_share.to_bytes());
        out.extend_from_slice(&self.id_cred_pub_share_number.to_bytes());
        out.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = ArIdentity::from_bytes(cur)?;
        let enc_id_cred_pub_share = Cipher::from_bytes(cur).ok()?;
        let id_cred_pub_share_number = ShareNumber::from_bytes(cur)?;
        Some(ChainArData {
            ar_identity,
            enc_id_cred_pub_share,
            id_cred_pub_share_number,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "arIdentity": self.ar_identity.to_json(),
            "encIdCredPubShare": json_base16_encode(&self.enc_id_cred_pub_share.to_bytes()),
            "idCredPubShareNumber": self.id_cred_pub_share_number.to_json()
        })
    }

    pub fn from_json(v: &Value) -> Option<ChainArData<C>> {
        let ar_identity = ArIdentity::from_json(v.get("arIdentity")?)?;
        let enc_id_cred_pub_share =
            Cipher::from_bytes(m_json_decode!(v, "encIdCredPubShare")).ok()?;
        let id_cred_pub_share_number = ShareNumber::from_json(v.get("idCredPubShareNumber")?)?;
        Some(ChainArData {
            ar_identity,
            enc_id_cred_pub_share,
            id_cred_pub_share_number,
        })
    }
}

impl<C: Curve> CredDeploymentCommitments<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut out = Vec::from(self.cmm_prf.to_bytes());
        out.extend_from_slice(&self.cmm_cred_counter.to_bytes());
        let atts = &self.cmm_attributes;
        out.extend_from_slice(&(atts.len() as u16).to_be_bytes());
        // NB: It is important that the iterator is over ordered keys.
        // This ensures consistent serialization.
        for (v, a) in atts {
            out.extend_from_slice(&v.to_be_bytes());
            out.extend_from_slice(&a.to_bytes());
        }
        let cmm_id_cred_sec_sharing_coeff = &self.cmm_id_cred_sec_sharing_coeff;
        out.extend_from_slice(&(cmm_id_cred_sec_sharing_coeff.len() as u16).to_be_bytes());
        for cmm in cmm_id_cred_sec_sharing_coeff.iter() {
            out.extend_from_slice(&cmm.to_bytes());
        }
        out.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let cmm_prf = pedersen::Commitment::from_bytes(cur).ok()?;
        let cmm_cred_counter = pedersen::Commitment::from_bytes(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_attributes = BTreeMap::new();
        for _ in 0..l {
            let v = cur.read_u16::<BigEndian>().ok()?;
            let cmm = pedersen::Commitment::from_bytes(cur).ok()?;
            cmm_attributes.insert(v, cmm);
        }
        let len = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_id_cred_sec_sharing_coeff = Vec::with_capacity(len as usize);
        for _ in 0..len {
            cmm_id_cred_sec_sharing_coeff.push(pedersen::Commitment::from_bytes(cur).ok()?);
        }
        Some(CredDeploymentCommitments {
            cmm_prf,
            cmm_cred_counter,
            cmm_attributes,
            cmm_id_cred_sec_sharing_coeff,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> CredDeploymentProofs<P, C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        // we use the first 4 bytes to encode the final length of the serialization.
        // This is unnecessary because proofs are structured and subparts have their
        // length, but having the extra 4 bytes (which is negligible compared to
        // the rest of the data) allows us to treat the proofs as a binary blob
        // in many other places.
        let mut out = vec![0, 0, 0, 0];
        out.extend_from_slice(&self.sig.to_bytes());
        out.extend_from_slice(&self.commitments.to_bytes());
        out.extend_from_slice(&(self.proof_id_cred_pub.len() as u16).to_be_bytes());
        for (i, p) in self.proof_id_cred_pub.iter() {
            out.extend_from_slice(&i.to_bytes());
            out.extend_from_slice(&p.to_bytes());
        }
        out.extend_from_slice(&self.proof_ip_sig.to_bytes());
        out.extend_from_slice(&self.proof_reg_id.to_bytes());
        out.extend_from_slice(&self.proof_acc_sk.to_bytes());
        // out.extend_from_slice(&self.proof_policy.to_bytes());
        let len = (out.len() - 4) as u32;
        out[0..4].copy_from_slice(&len.to_be_bytes());
        out.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let _redundant = cur.read_u32::<BigEndian>().ok()?;
        let sig = BlindedSignature::from_bytes(cur).ok()?;
        let commitments = CredDeploymentCommitments::from_bytes(cur)?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut proof_id_cred_pub = Vec::with_capacity(l as usize);
        for _ in 0..l {
            proof_id_cred_pub.push((
                ShareNumber::from_bytes(cur)?,
                ComEncEqProof::from_bytes(cur).ok()?,
            ));
        }
        let proof_ip_sig = ComEqSigProof::from_bytes(cur).ok()?;
        let proof_reg_id = ComMultProof::from_bytes(cur).ok()?;
        let proof_acc_sk = AccountOwnershipProof::from_bytes(cur)?;
        // let proof_policy = PolicyProof::from_bytes(cur)?;
        Some(CredDeploymentProofs {
            sig,
            commitments,
            proof_id_cred_pub,
            proof_ip_sig,
            proof_reg_id,
            proof_acc_sk,
            // proof_policy,
        })
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Policy<C, AttributeType> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut vec = Vec::from(&self.variant.to_be_bytes()[..]);
        // vec.extend_from_slice(&self.variant.to_be_bytes());
        vec.extend_from_slice(&self.expiry.to_be_bytes());
        let l = self.policy_vec.len();
        vec.extend_from_slice(&(l as u16).to_be_bytes());
        // NB: It is important that iter produces keys in order.
        for (idx, v) in self.policy_vec.iter() {
            vec.extend_from_slice(&idx.to_be_bytes());
            vec.extend_from_slice(&v.to_bytes());
        }
        vec.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let variant = cur.read_u16::<BigEndian>().ok()?;
        let expiry = cur.read_u64::<BigEndian>().ok()?;
        let len = cur.read_u16::<BigEndian>().ok()?;
        let mut policy_vec = BTreeMap::new();
        for _ in 0..len {
            let idx = cur.read_u16::<BigEndian>().ok()?;
            let att = AttributeType::from_bytes(cur)?;
            if policy_vec.insert(idx, att).is_some() {
                return None; // cannot have duplicates
            } // else continue parsing
        }
        Some(Policy {
            variant,
            expiry,
            policy_vec,
            _phantom: Default::default(),
        })
    }

    pub fn to_json(&self) -> Value {
        let revealed: Vec<Value> = self
            .policy_vec
            .iter()
            .map(|(idx, value)| json!({"index": idx, "value": format!("{}", value)}))
            .collect();
        json!({
            "variant": self.variant,
            "expiry": self.expiry,
            "revealedItems": revealed
        })
    }
}

impl SchemeId {
    pub fn to_bytes(&self) -> [u8; 1] {
        match self {
            SchemeId::Ed25519 => [0],
        }
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<SchemeId> {
        match cur.read_u8().ok()? {
            0 => Some(SchemeId::Ed25519),
            _ => None,
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialDeploymentValues<C, AttributeType> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut v = self.cred_account.to_bytes().to_vec();
        v.extend_from_slice(&self.reg_id.curve_to_bytes());
        v.extend_from_slice(&self.ip_identity.to_bytes());
        v.extend_from_slice(&self.threshold.to_bytes());
        v.extend_from_slice(&(self.ar_data.len() as u16).to_be_bytes());
        for ar in self.ar_data.iter() {
            v.extend_from_slice(&ar.to_bytes());
        }
        v.extend_from_slice(&self.policy.to_bytes());
        v.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let cred_account = CredentialAccount::from_bytes(cur)?;
        let reg_id = curve_serialization::read_curve::<C>(cur).ok()?;
        let ip_identity = IpIdentity::from_bytes(cur)?;
        let threshold = Threshold::from_bytes(cur)?;
        let number_of_ars = cur.read_u16::<BigEndian>().ok()?;
        let mut ar_data = Vec::with_capacity(number_of_ars as usize);
        for _ in 0..number_of_ars {
            ar_data.push(ChainArData::from_bytes(cur)?);
        }
        let policy = Policy::from_bytes(cur)?;
        Some(CredentialDeploymentValues {
            cred_account,
            reg_id,
            ip_identity,
            threshold,
            ar_data,
            policy,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredDeploymentInfo<P, C, AttributeType>
{
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut v = self.values.to_bytes().to_vec();
        let proof_bytes = self.proofs.to_bytes().to_vec();
        v.extend_from_slice(&proof_bytes);
        v.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let values = CredentialDeploymentValues::from_bytes(cur);

        let proofs = CredDeploymentProofs::<P, C>::from_bytes(cur);
        Some(CredDeploymentInfo {
            values: values?,
            proofs: proofs?,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "account": self.values.cred_account.to_json(),
            "regId": json_base16_encode(&self.values.reg_id.curve_to_bytes()),
            "ipIdentity": self.values.ip_identity.to_json(),
            "revocationThreshold": self.values.threshold.to_json(),
            "arData": self.values.ar_data.iter().map(ChainArData::to_json).collect::<Vec<_>>(),
            "policy": self.values.policy.to_json(),
            // NOTE: Since proofs encode their own length we do not output those first 4 bytes
            "proofs": json_base16_encode(&self.proofs.to_bytes()[4..]),
        })
    }
}

impl<C: Curve> PolicyProof<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut v = Vec::with_capacity(2 * C::SCALAR_LENGTH);
        v.extend_from_slice(&self.variant_rand.to_bytes());
        v.extend_from_slice(&self.expiry_rand.to_bytes());
        v.extend_from_slice(&(self.cmm_opening_map.len() as u16).to_be_bytes());
        for (idx, r) in self.cmm_opening_map.iter() {
            v.extend_from_slice(&idx.to_be_bytes());
            v.extend_from_slice(&r.to_bytes());
        }
        v.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let variant_rand = PedersenRandomness::from_bytes(cur).ok()?;
        let expiry_rand = PedersenRandomness::from_bytes(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_opening_map = common::safe_with_capacity(l as usize);
        for _ in 0..l {
            let idx = cur.read_u16::<BigEndian>().ok()?;
            let scalar = PedersenRandomness::from_bytes(cur).ok()?;
            cmm_opening_map.push((idx, scalar));
        }
        Some(PolicyProof {
            variant_rand,
            expiry_rand,
            cmm_opening_map,
        })
    }
}

impl IpIdentity {
    pub fn to_bytes(self) -> Box<[u8]> { Box::from(self.0.to_be_bytes()) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let r = cur.read_u32::<BigEndian>().ok()?;
        Some(IpIdentity(r))
    }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(IpIdentity(v))
    }
}

impl ArIdentity {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)).unwrap() }

    pub fn to_bytes(self) -> Box<[u8]> { Box::from(self.0.to_be_bytes()) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let r = cur.read_u32::<BigEndian>().ok()?;
        Some(ArIdentity(r))
    }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(ArIdentity(v))
    }
}

impl<C: Curve> ArInfo<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r: Vec<u8> = Vec::from(self.ar_identity.to_bytes());
        r.extend_from_slice(&short_string_to_bytes(&self.ar_description));
        r.extend_from_slice(&self.ar_public_key.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = ArIdentity::from_bytes(cur)?;
        let ar_description = bytes_to_short_string(cur)?;
        let ar_public_key = elgamal::PublicKey::from_bytes(cur).ok()?;
        Some(ArInfo {
            ar_identity,
            ar_description,
            ar_public_key,
        })
    }

    pub fn from_json(ar_val: &Value) -> Option<Self> {
        let ar_val = ar_val.as_object()?;
        let ar_identity = ArIdentity::from_json(ar_val.get("arIdentity")?)?;
        let ar_description = ar_val.get("arDescription")?.as_str()?;
        let ar_public_key =
            elgamal::PublicKey::from_bytes(m_json_decode!(ar_val, "arPublicKey")).ok()?;
        Some(ArInfo {
            ar_identity,
            ar_description: ar_description.to_owned(),
            ar_public_key,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "arIdentity": self.ar_identity.to_json(),
            "arDescription": self.ar_description,
            "arPublicKey": json_base16_encode(&self.ar_public_key.to_bytes()),
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> IpInfo<P, C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = Vec::with_capacity(4);
        r.extend_from_slice(&self.ip_identity.to_bytes());
        r.extend_from_slice(&short_string_to_bytes(&self.ip_description));
        r.extend_from_slice(&self.ip_verify_key.to_bytes());
        let l = self.ar_info.0.len();
        r.extend_from_slice(&(l as u16).to_be_bytes());
        for item in &self.ar_info.0 {
            r.extend_from_slice(&item.to_bytes());
        }
        r.extend_from_slice(&self.ar_info.1.to_bytes());
        r.extend_from_slice(&self.ar_base.curve_to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ip_identity = IpIdentity::from_bytes(cur)?;
        let ip_description = bytes_to_short_string(cur)?;
        let ip_verify_key = pssig::PublicKey::from_bytes(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut ar_list = Vec::with_capacity(l as usize);
        for _ in 0..l {
            ar_list.push(ArInfo::from_bytes(cur)?);
        }
        let ar_info = (ar_list, PedersenKey::from_bytes(cur).ok()?);
        let ar_base = C::bytes_to_curve(cur).ok()?;
        Some(IpInfo {
            ip_identity,
            ip_description,
            ip_verify_key,
            ar_info,
            ar_base,
        })
    }

    pub fn from_json(ip_val: &Value) -> Option<Self> {
        let ip_val = ip_val.as_object()?;
        let ip_identity = IpIdentity::from_json(ip_val.get("ipIdentity")?)?;
        let ip_description = ip_val.get("ipDescription")?.as_str()?;
        let ip_verify_key = pssig::PublicKey::from_bytes(&mut Cursor::new(&json_base16_decode(
            ip_val.get("ipVerifyKey")?,
        )?))
        .ok()?;
        let ck_bytes = ip_val.get("arCommitmentKey").and_then(json_base16_decode)?;
        let ck = PedersenKey::from_bytes(&mut Cursor::new(&ck_bytes)).ok()?;

        let ar_arr_items: &Vec<Value> = ip_val.get("anonymityRevokers")?.as_array()?;
        let m_ar_arry: Option<Vec<ArInfo<C>>> =
            ar_arr_items.iter().map(ArInfo::from_json).collect();
        let ar_arry = m_ar_arry?;
        let ar_base = C::bytes_to_curve(&mut Cursor::new(
            &ip_val.get("arBase").and_then(json_base16_decode)?,
        ))
        .ok()?;
        Some(IpInfo {
            ip_identity,
            ip_description: ip_description.to_owned(),
            ip_verify_key,
            ar_info: (ar_arry, ck),
            ar_base,
        })
    }

    pub fn to_json(&self) -> Value {
        let ars: Vec<Value> = self.ar_info.0.iter().map(ArInfo::to_json).collect();
        json!({
            "ipIdentity": self.ip_identity.to_json(),
            "ipDescription": self.ip_description,
            "ipVerifyKey": json_base16_encode(&self.ip_verify_key.to_bytes()),
            "arCommitmentKey": json_base16_encode(&self.ar_info.1.to_bytes()),
            "anonymityRevokers": ars,
            "arBase": json_base16_encode(&self.ar_base.curve_to_bytes()),
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Context<P, C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        r.extend_from_slice(&self.ip_info.to_bytes());
        let l: u32 = self.choice_ar_parameters.0.len() as u32; // no more than u32 parameters supported.
        r.extend_from_slice(&l.to_be_bytes());
        for item in &self.choice_ar_parameters.0 {
            r.extend_from_slice(&item.to_bytes());
        }
        r.extend_from_slice(&self.choice_ar_parameters.1.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ip_info = IpInfo::from_bytes(cur)?;
        let l = cur.read_u32::<BigEndian>().ok()?;
        let mut ar_list = common::safe_with_capacity(l as usize);
        for _ in 0..l {
            ar_list.push(ArInfo::from_bytes(cur)?);
        }
        let choice_ar_parameters = (ar_list, Threshold::from_bytes(cur)?);
        Some(Context {
            ip_info,
            choice_ar_parameters,
        })
    }
}

fn json_base16_encode(v: &[u8]) -> Value { json!(encode(v)) }

fn json_base16_decode(v: &Value) -> Option<Vec<u8>> { decode(v.as_str()?).ok() }

impl<C: Curve> GlobalContext<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        r.extend_from_slice(&self.on_chain_commitment_key.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let on_chain_commitment_key = PedersenKey::from_bytes(cur).ok()?;
        Some(GlobalContext {
            on_chain_commitment_key,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let cmk_bytes = obj
            .get("onChainCommitmentKey")
            .and_then(json_base16_decode)?;
        let cmk = PedersenKey::from_bytes(&mut Cursor::new(&cmk_bytes)).ok()?;
        let gc = GlobalContext {
            on_chain_commitment_key: cmk,
        };
        Some(gc)
    }

    pub fn to_json(&self) -> Value {
        json!({
               "onChainCommitmentKey": json_base16_encode(&self.on_chain_commitment_key.to_bytes()),
        })
    }
}
