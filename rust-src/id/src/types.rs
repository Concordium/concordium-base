use crate::secret_sharing::{ShareNumber, Threshold};
use crypto_common::*;
use curve_arithmetic::curve_arithmetic::*;
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

use serde_json::{json, Map, Number, Value};

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

// only for account addresses
use base58check::*;

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct AccountAddress([u8; ACCOUNT_ADDRESS_SIZE]);

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
}

/// Index of an account key that is to be used.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
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
}

#[derive(Debug, PartialEq, Eq)]
/// List of pairs of index of key and proof.
/// The list should be non-empty and at most 255 elements long, and have no
/// duplicates. The current choice of data structure disallows duplicates by
/// design.
pub struct AccountOwnershipProof {
    pub proofs: BTreeMap<KeyIndex, Ed25519DlogProof>,
}

// Manual implementation to be able to encode length as 1.
impl Serial for AccountOwnershipProof {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.proofs.len() as u8;
        out.put(&len);
        serial_map_no_length(self.proofs.iter(), out)
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
    pub fn num_proofs(&self) -> SignatureThreshold { SignatureThreshold(self.proofs.len() as u8) }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
pub struct IpIdentity(pub u32);

impl fmt::Display for IpIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
pub struct ArIdentity(pub u32);

impl fmt::Display for ArIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

pub trait Attribute<F: Field>:
    Copy + Clone + Sized + Send + Sync + fmt::Display + Serialize {
    // convert an attribute to a field element
    fn to_field_element(&self) -> F;
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributeList<F: Field, AttributeType: Attribute<F>> {
    pub variant:  u16,
    pub expiry:   u64,
    pub alist:    Vec<AttributeType>,
    pub _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Serialize)]
/// In our case C: will be G1 and T will be G1 for now A secret credential is
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
#[derive(Debug, Serialize)]
pub struct CredentialHolderInfo<C: Curve> {
    /// Name of the credential holder.
    #[string_size_length = 4] // only use four bytes for encoding length.
    pub id_ah: String,
    /// Public and private keys of the credential holder. NB: These are distinct
    /// from the public/private keys of the account holders.
    pub id_cred: IdCredentials<C>,
}

/// Private and public data chosen by the credential holder before the
/// interaction with the identity provider. The credential holder chooses a prf
/// key and an attribute list.
#[derive(Debug, Serialize)]
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
#[derive(Serialize)]
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
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct ChainArData<C: Curve> {
    /// identity of the anonymity revoker
    pub ar_identity: ArIdentity,
    /// encrypted share of id cred pub
    pub enc_id_cred_pub_share: Cipher<C>,
    /// the number of the share
    pub id_cred_pub_share_number: ShareNumber,
}

/// Information sent from the account holder to the identity provider.
#[derive(Serialize)]
pub struct PreIdentityObject<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Name of the account holder.
    #[string_size_length = 2] // only use two bytes for encoding length.
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
    pub cmm_sc: pedersen::Commitment<P::G1>,
    /// Proof that cmm_sc and id_cred_pub are hiding the same value.
    pub proof_com_eq_sc: ComEqProof<P::G1>,
    /// Commitment to the prf key in group G1.
    pub cmm_prf: pedersen::Commitment<P::G1>,
    /// commitments to the coefficients of the polynomial
    /// used to share the prf key
    /// K + b1 X + b2 X^2...
    /// where K is the prf key
    pub cmm_prf_sharing_coeff: Vec<pedersen::Commitment<C>>,
    /// Proof that the first and snd commitments to the prf are hiding the same
    /// value. The first commitment is cmm_prf and the second is the first in
    /// the vec cmm_prf_sharing_coeff
    pub proof_com_eq: ComEqDiffGrpsProof<P::G1, C>,
}

/// Public information about an identity provider.
#[derive(Debug, Clone, Serialize)]
pub struct IpInfo<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Unique identifier of the identity provider.
    pub ip_identity: IpIdentity,
    /// Free form description, e.g., how to contact them off-chain
    #[string_size_length = 4]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArInfo<C: Curve> {
    /// unique identifier of the anonymity revoker
    pub ar_identity: ArIdentity,
    /// description of the anonymity revoker (e.g. name, contact number)
    #[string_size_length = 4]
    pub ar_description: String,
    /// elgamal encryption key of the anonymity revoker
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
    /// List of commitments to the attributes that are not revealed.
    /// For the purposes of checking signatures, the commitments to those
    /// that are revealed as part of the policy are going to be computed by the
    /// verifier.
    #[map_size_length = 2]
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

// This is an unfortunate situation, but we need to manually write a
// serialization instance for the proofs so that we can insert the length of the
// whole proof upfront. This is needed for easier interoperability with Haskell.
// It means
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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Serial for Policy<C, AttributeType> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.variant);
        out.put(&self.expiry);
        out.put(&(self.policy_vec.len() as u16));
        serial_map_no_length(self.policy_vec.iter(), out)
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Deserial for Policy<C, AttributeType> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let variant = source.get()?;
        let expiry = source.get()?;
        let len: u16 = source.get()?;
        let policy_vec = deserial_map_no_length(source, usize::from(len))?;
        Ok(Policy {
            variant,
            expiry,
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

impl VerifyKey {
    pub fn to_json(&self) -> Value {
        // ignore the scheme for the Ed, since it is default
        match self {
            VerifyKey::Ed25519VerifyKey(ref key) => json_base16_encode(key),
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
}

/// Values (as opposed to proofs) in credential deployment.
#[derive(Debug, PartialEq, Eq, Serialize)]
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

#[derive(Debug, PartialEq, Eq, Serialize)]
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

#[derive(Serialize)]
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

// Manual implementation to be able to encode length as 1.
impl Serial for AccountData {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.keys.len() as u8;
        out.put(&len);
        serial_map_no_length(self.keys.iter(), out);
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

impl AccountData {
    pub fn from_json(v: &Value) -> Option<AccountData> {
        let mut keys = BTreeMap::new();
        let obj = v.get("keys")?.as_object()?;
        for (k, v) in obj.iter() {
            if let Ok(k) = k.parse::<u8>() {
                let public = v.get("verifyKey").and_then(json_base16_decode)?;
                let secret = v.get("signKey").and_then(json_base16_decode)?;
                keys.insert(KeyIndex(k), ed25519::Keypair { public, secret });
            }
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
        let mut out = Map::with_capacity(self.keys.len());
        for (idx, kp) in self.keys.iter() {
            out.insert(
                format!("{}", idx.0),
                json!({
                    "verifyKey": json_base16_encode(&kp.public),
                    "signKey": json_base16_encode(&kp.secret),
                }),
            );
        }
        match self.existing {
            Left(thr) => json!({
                "keys": Value::Object(out),
                "threshold": thr.to_json()
            }),
            Right(addr) => json!({
                "keys": Value::Object(out),
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

impl Serial for AccountKeys {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let len = self.keys.len() as u8;
        out.put(&len);
        serial_map_no_length(self.keys.iter(), out);
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

    pub fn to_json(&self) -> Value {
        let mut out = Map::with_capacity(self.keys.len());
        for (idx, v) in self.keys.iter() {
            out.insert(format!("{}", idx.0).to_owned(), v.to_json());
        }
        json!({
            "threshold": self.threshold.to_json(),
            "keys": Value::Object(out)
        })
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

impl<C: Curve> ChainArData<C> {
    pub fn to_json(&self) -> Value {
        json!({
            "arIdentity": self.ar_identity.to_json(),
            "encIdCredPubShare": json_base16_encode(&self.enc_id_cred_pub_share),
            "idCredPubShareNumber": self.id_cred_pub_share_number.to_json()
        })
    }

    pub fn from_json(v: &Value) -> Option<ChainArData<C>> {
        let ar_identity = ArIdentity::from_json(v.get("arIdentity")?)?;
        let enc_id_cred_pub_share = v.get("encIdCredPubShare").and_then(json_base16_decode)?;
        let id_cred_pub_share_number = ShareNumber::from_json(v.get("idCredPubShareNumber")?)?;
        Some(ChainArData {
            ar_identity,
            enc_id_cred_pub_share,
            id_cred_pub_share_number,
        })
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Policy<C, AttributeType> {
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

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredDeploymentInfo<P, C, AttributeType>
{
    pub fn to_json(&self) -> Value {
        json!({
            "account": self.values.cred_account.to_json(),
            "regId": json_base16_encode(&self.values.reg_id),
            "ipIdentity": self.values.ip_identity.to_json(),
            "revocationThreshold": self.values.threshold.to_json(),
            "arData": self.values.ar_data.iter().map(ChainArData::to_json).collect::<Vec<_>>(),
            "policy": self.values.policy.to_json(),
            // NOTE: Since proofs encode their own length we do not output those first 4 bytes
            "proofs": encode(&to_bytes(&self.proofs)),
        })
    }
}

impl IpIdentity {
    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(IpIdentity(v))
    }
}

impl ArIdentity {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)) }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(ArIdentity(v))
    }
}

impl<C: Curve> ArInfo<C> {
    pub fn from_json(ar_val: &Value) -> Option<Self> {
        let ar_val = ar_val.as_object()?;
        let ar_identity = ArIdentity::from_json(ar_val.get("arIdentity")?)?;
        let ar_description = ar_val.get("arDescription")?.as_str()?;
        let ar_public_key = ar_val.get("arPublicKey").and_then(json_base16_decode)?;
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
            "arPublicKey": json_base16_encode(&self.ar_public_key),
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> IpInfo<P, C> {
    pub fn from_json(ip_val: &Value) -> Option<Self> {
        let ip_val = ip_val.as_object()?;
        let ip_identity = IpIdentity::from_json(ip_val.get("ipIdentity")?)?;
        let ip_description = ip_val.get("ipDescription")?.as_str()?;
        let ip_verify_key = ip_val.get("ipVerifyKey").and_then(json_base16_decode)?;
        let ck = ip_val.get("arCommitmentKey").and_then(json_base16_decode)?;

        let ar_arr_items: &Vec<Value> = ip_val.get("anonymityRevokers")?.as_array()?;
        let m_ar_arry: Option<Vec<ArInfo<C>>> =
            ar_arr_items.iter().map(ArInfo::from_json).collect();
        let ar_arry = m_ar_arry?;
        let ar_base = ip_val.get("arBase").and_then(json_base16_decode)?;
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
            "ipVerifyKey": json_base16_encode(&self.ip_verify_key),
            "arCommitmentKey": json_base16_encode(&self.ar_info.1),
            "anonymityRevokers": ars,
            "arBase": json_base16_encode(&self.ar_base),
        })
    }
}

fn json_base16_encode<V: Serial>(v: &V) -> Value { json!(encode(&to_bytes(v))) }

fn json_base16_decode<V: Deserial>(v: &Value) -> Option<V> {
    V::deserial(&mut Cursor::new(decode(v.as_str()?).ok()?)).ok()
}

impl<C: Curve> GlobalContext<C> {
    pub fn from_json(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let cmk = obj
            .get("onChainCommitmentKey")
            .and_then(json_base16_decode)?;
        let gc = GlobalContext {
            on_chain_commitment_key: cmk,
        };
        Some(gc)
    }

    pub fn to_json(&self) -> Value {
        json!({
               "onChainCommitmentKey": json_base16_encode(&self.on_chain_commitment_key),
        })
    }
}
