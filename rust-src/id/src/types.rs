use common;
use curve_arithmetic::{curve_arithmetic::*, serialization as curve_serialization};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as acc_sig_scheme;
use ed25519_dalek as ed25519;
use eddsa_ed25519::dlog_ed25519::Ed25519DlogProof;
use elgamal::cipher::Cipher;
use ff::Field;
use pedersen_scheme::{commitment as pedersen, key::CommitmentKey as PedersenKey};
use ps_sig::{public as pssig, signature::*};

use sigma_protocols::{
    com_enc_eq::ComEncEqProof, com_eq::ComEqProof, com_eq_different_groups::ComEqDiffGrpsProof,
    com_eq_sig::ComEqSigProof, com_mult::ComMultProof,
};

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub trait Attribute<F: Field>: Copy + Clone + Sized + Send + Sync {
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
/// In our case C: will be G_1 and T will be G_1 for now
/// A secret credential is a scalar
/// raising a generator to this scalar
/// gives a public credentials
/// if two groups have the same scalar field
/// we can have two different public credentials from the same secret
/// credentials
pub struct IdCredentials<C: Curve> {
    /// secret id credentials
    pub id_cred_sec: C::Scalar,
    /// public id credential in the curve C
    pub id_cred_pub: C,
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
    pub ar_identity: u64,
    /// encrypted share of the prf key
    pub enc_prf_key_share: Cipher<C>,
    /// the number of the share
    pub prf_key_share_number: u64,
    /// proof that the computed commitment to the share
    /// contains the same value as the encryption
    /// the commitment to the share is not sent but computed from
    /// the commitments to the sharing coefficients
    pub proof_com_enc_eq: ComEncEqProof<C>,
}
/// data relating to a single anonymity revoker sent by the account holder to
/// the chain typicall a vector of these will be sent to the chain
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainArData<C: Curve> {
    /// identity of the anonymity revoker
    pub ar_identity: u64,
    /// encrypted share of id cred pub
    pub enc_id_cred_pub_share: Cipher<C>,
    /// the number of the share
    pub id_cred_pub_share_number: u64,
}

/// Information sent from the account holder to the identity provider.
pub struct PreIdentityObject<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Name of the account holder.
    pub id_ah: String,
    /// Public credential of the account holder only.
    pub id_cred_pub_ip: P::G_1,
    pub id_cred_pub: C,
    /// Anonymity revocation data for the chosen anonymity revokers.
    pub ip_ar_data: Vec<IpArData<C>>,
    /// choice of anonyimity revocation parameters
    /// the vec is a vector of ar identities
    /// the second element of the pair is the threshold for revocation.
    /// must be less than or equal the length of the vector.
    /// NB:IP needs to check this
    pub choice_ar_parameters: (Vec<u64>, u64),
    /// Chosen attribute list.
    pub alist: AttributeList<C::Scalar, AttributeType>,
    /// Proof of knowledge of secret credentials corresponding to id_cred_pub_ip
    /// matching the commitment cmm_sc
    pub pok_sc: ComEqProof<P::G_1>,
    /// proof of knowledge of secret credential corresponding to snd_cmm_sc
    pub snd_pok_sc: ComEqProof<C>,
    /// commitment to id cred sec
    pub cmm_sc: pedersen::Commitment<P::G_1>,
    /// commitment to id cred sec in C
    pub snd_cmm_sc: pedersen::Commitment<C>,
    /// proof that cmm_sc and snd_cmm_sc are hiding the same thing
    pub proof_com_eq_sc: ComEqDiffGrpsProof<P::G_1, C>,
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
    pub ip_identity: u32,
    /// Free form description, e.g., how to contact them off-chain
    pub ip_description: String,
    /// PS publice signature key of the IP
    pub ip_verify_key: pssig::PublicKey<P>,
    /// The dlog base of the IP.
    /// Used by account holder to prove knowledge of id cred sec
    pub dlog_base: P::G_1,
    /// list of approved anonymity revokers along with
    /// a shared commitment key
    /// TODO: How is this shared commitment key generated??
    pub ar_info: (Vec<ArInfo<C>>, PedersenKey<C>),
}

/// Information on a single anonymity reovker held by the IP
/// typically an IP will hold a more than one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArInfo<C: Curve> {
    /// unique identifier of the anonymity revoker
    pub ar_identity: u64,
    /// description of the anonymity revoker (e.g. name, contact number)
    pub ar_description: String,
    /// elgamal encryption key of the anonymity revoker
    pub ar_public_key: elgamal::PublicKey<C>,
}

/// Randomness used by the account holder during the interaction with IP
/// The IP signs an unknown message (hidden by this randomness). The user
/// then retrieves the signature on the original message by using this value.
#[derive(Debug)]
pub struct SigRetrievalRandomness<P: Pairing>(pub P::ScalarField);

/// The commitments sent by the account holder to the chain in order to
/// deploy credentials
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CredDeploymentCommitments<C: Curve> {
    /// commitment to the prf key
    pub cmm_prf: pedersen::Commitment<C>,
    /// commitment to credential counter
    pub cmm_cred_counter: pedersen::Commitment<C>,
    /// commitments to anonymity revokers
    /// The account holder needs to commit to a list of ARs
    /// These are checked against the IP signatures
    /// to make sure the prf sharing and id_cred sharing are done
    /// w.r.t. the same list of ARs
    /// These commitments will be sent with randomness 0.
    pub cmm_ars: Vec<pedersen::Commitment<C>>,
    /// list of commitments to the attributes
    pub cmm_attributes: Vec<pedersen::Commitment<C>>,
    /// commitments to the coefficients of the polynomial
    /// used to share id_cred_sec
    /// S + b1 X + b2 X^2...
    /// where S is id_cred_sec
    pub cmm_id_cred_sec_sharing_coeff: Vec<pedersen::Commitment<C>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredDeploymentProofs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// (Blinded) Signature derived from the signature on the pre-identity
    /// object by the IP
    pub sig: Signature<P>,
    /// list of  commitments to the attributes .
    pub commitments: CredDeploymentCommitments<C>,
    /// Proofs that the encrypted shares of id_cred_pub and
    /// commitments (in chain_ar_data) hide the same values.
    /// each proof is indexed by the share number.
    pub proof_id_cred_pub: Vec<(u64, ComEncEqProof<C>)>,
    /// Proof of knowledge of signature of Identity Provider on the list
    /// (idCredSec, prfKey, attributes[0], attributes[1],..., attributes[n],
    /// AR[1], ..., AR[m])
    pub proof_ip_sig: ComEqSigProof<P, C>,
    /// Proof that reg_id = prf_K(x). Also establishes that reg_id is computed
    /// from the prf key signed by the identity provider.
    pub proof_reg_id: ComMultProof<C>,
    /// Proof of knowledge of acc secret key (signing key corresponding to the
    /// verification key).
    pub proof_acc_sk: Ed25519DlogProof,
    /// Proof that the attribute list in commitments.cmm_attributes satisfy the
    /// policy for now this is mainly achieved by opening the corresponding
    /// commitments.
    pub proof_policy: PolicyProof<C>,
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
    pub policy_vec: Vec<(u16, AttributeType)>,
    pub _phantom: std::marker::PhantomData<C>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchemeId {
    Ed25519,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyProof<C: Curve> {
    /// Randomness to open the variant commitment.
    pub variant_rand: C::Scalar,
    /// Randomness to open the expiry commitment.
    pub expiry_rand: C::Scalar,
    /// The u16 is the index of the attribute
    /// The Scalar is the witness (technically the randomness in the commitment)
    /// i.e. to open.
    pub cmm_opening_map: Vec<(u16, C::Scalar)>,
}

/// Values (as opposed to proofs) in credential deployment.
#[derive(Debug, PartialEq, Eq)]
pub struct CredentialDeploymentValues<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Id of the signature scheme of the account. The verification key must
    /// correspond to the
    pub acc_scheme_id: SchemeId,
    /// Chosen verification key of the account.
    pub acc_pub_key: acc_sig_scheme::PublicKey,
    /// Credential registration id of the credential.
    pub reg_id: C,
    /// Identity of the identity provider who signed the identity object from
    /// which this credential is derived.
    pub ip_identity: u32,
    /// Anonymity revocation data.
    pub ar_data: Vec<ChainArData<C>>,
    /// Policy of this credential object.
    pub policy: Policy<C, AttributeType>,
    /// Redundant, could be deduced from ar_data
    /// ar_parameters, vector of ar handles
    pub choice_ar_handles: Vec<u64>,
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
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the id cred sec key.
    pub commitment_key_sc: PedersenKey<P::G_1>,
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the prf key.
    pub commitment_key_prf: PedersenKey<P::G_1>,
    /// choice of anonyimity revocation parameters
    /// that is a choice of subset of anonymity revokers
    /// threshold  parameter
    pub choice_ar_parameters: (Vec<ArInfo<C>>, u64),
}

pub struct GlobalContext<C: Curve> {
    /// Base of dlog proofs with chain.
    pub dlog_base_chain: C,

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
    choice_ar_handles: (Vec<u64>, u64),
) -> Context<P, C> {
    // TODO: Check with Bassel that these parameters are correct.
    let dlog_base = ip_info.dlog_base;
    let commitment_key_sc = PedersenKey(ip_info.ip_verify_key.2[0], dlog_base);
    let commitment_key_prf = PedersenKey(ip_info.ip_verify_key.2[1], dlog_base);
    let mut choice_ars = Vec::with_capacity(choice_ar_handles.0.len());
    let ip_ar_parameters = &ip_info.ar_info.0.clone();
    for ar in choice_ar_handles.0.into_iter() {
        match ip_ar_parameters.iter().find(|&x| x.ar_identity == ar) {
            None => panic!("AR handle not in the IP list"),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }

    // find ars from their handles
    Context {
        ip_info,
        commitment_key_sc,
        commitment_key_prf,
        choice_ar_parameters: (choice_ars, choice_ar_handles.1),
    }
}

/// Account data needed by the account holder to generate proofs to deploy the
/// credential object.
pub struct AccountData {
    /// Signature key of the account.
    pub verify_key: ed25519::PublicKey,
    /// And the corresponding verification key.
    pub sign_key: ed25519::SecretKey,
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::from(&self.ar_identity.to_be_bytes()[..]);
        out.extend_from_slice(&self.enc_prf_key_share.to_bytes());
        out.extend_from_slice(&self.prf_key_share_number.to_be_bytes());
        out.extend_from_slice(&self.proof_com_enc_eq.to_bytes());
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = cur.read_u64::<BigEndian>().ok()?;
        let enc_prf_key_share = Cipher::from_bytes(cur).ok()?;
        let prf_key_share_number = cur.read_u64::<BigEndian>().ok()?;
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::from(&self.ar_identity.to_be_bytes()[..]);
        out.extend_from_slice(&self.enc_id_cred_pub_share.to_bytes());
        out.extend_from_slice(&self.id_cred_pub_share_number.to_be_bytes());
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = cur.read_u64::<BigEndian>().ok()?;
        let enc_id_cred_pub_share = Cipher::from_bytes(cur).ok()?;
        let id_cred_pub_share_number = cur.read_u64::<BigEndian>().ok()?;
        Some(ChainArData {
            ar_identity,
            enc_id_cred_pub_share,
            id_cred_pub_share_number,
        })
    }
}

impl<C: Curve> CredDeploymentCommitments<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::from(self.cmm_prf.to_bytes());
        out.extend_from_slice(&self.cmm_cred_counter.to_bytes());
        let ars = &self.cmm_ars;
        out.extend_from_slice(&(ars.len() as u16).to_be_bytes());
        for a in ars {
            out.extend_from_slice(&a.to_bytes());
        }
        let atts = &self.cmm_attributes;
        out.extend_from_slice(&(atts.len() as u16).to_be_bytes());
        for a in atts {
            out.extend_from_slice(&a.to_bytes());
        }
        let cmm_id_cred_sec_sharing_coeff = &self.cmm_id_cred_sec_sharing_coeff;
        out.extend_from_slice(&(cmm_id_cred_sec_sharing_coeff.len() as u16).to_be_bytes());
        for cmm in cmm_id_cred_sec_sharing_coeff.iter() {
            out.extend_from_slice(&cmm.to_bytes());
        }
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let cmm_prf = pedersen::Commitment::from_bytes(cur).ok()?;
        let cmm_cred_counter = pedersen::Commitment::from_bytes(cur).ok()?;
        let m = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_ars = Vec::with_capacity(m as usize);
        for _ in 0..m {
            cmm_ars.push(pedersen::Commitment::from_bytes(cur).ok()?);
        }
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_attributes = Vec::with_capacity(l as usize);
        for _ in 0..l {
            cmm_attributes.push(pedersen::Commitment::from_bytes(cur).ok()?)
        }
        let len = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_id_cred_sec_sharing_coeff = Vec::with_capacity(len as usize);
        for _ in 0..len {
            cmm_id_cred_sec_sharing_coeff.push(pedersen::Commitment::from_bytes(cur).ok()?);
        }
        Some(CredDeploymentCommitments {
            cmm_prf,
            cmm_cred_counter,
            cmm_ars,
            cmm_attributes,
            cmm_id_cred_sec_sharing_coeff,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> CredDeploymentProofs<P, C> {
    pub fn to_bytes(&self) -> Vec<u8> {
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
            out.extend_from_slice(&i.to_be_bytes());
            out.extend_from_slice(&p.to_bytes());
        }
        out.extend_from_slice(&self.proof_ip_sig.to_bytes());
        out.extend_from_slice(&self.proof_reg_id.to_bytes());
        out.extend_from_slice(&self.proof_acc_sk.to_bytes());
        out.extend_from_slice(&self.proof_policy.to_bytes());
        let len = (out.len() - 4) as u32;
        out[0..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let _redundant = cur.read_u32::<BigEndian>().ok()?;
        let sig = Signature::from_bytes(cur).ok()?;
        let commitments = CredDeploymentCommitments::from_bytes(cur)?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut proof_id_cred_pub = Vec::with_capacity(l as usize);
        for _ in 0..l {
            proof_id_cred_pub.push((
                cur.read_u64::<BigEndian>().ok()?,
                ComEncEqProof::from_bytes(cur).ok()?,
            ));
        }
        let proof_ip_sig = ComEqSigProof::from_bytes(cur).ok()?;
        let proof_reg_id = ComMultProof::from_bytes(cur).ok()?;
        let proof_acc_sk = Ed25519DlogProof::from_bytes(cur).ok()?;
        let proof_policy = PolicyProof::from_bytes(cur)?;
        Some(CredDeploymentProofs {
            sig,
            commitments,
            proof_id_cred_pub,
            proof_ip_sig,
            proof_reg_id,
            proof_acc_sk,
            proof_policy,
        })
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Policy<C, AttributeType> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::from(&self.variant.to_be_bytes()[..]);
        // vec.extend_from_slice(&self.variant.to_be_bytes());
        vec.extend_from_slice(&self.expiry.to_be_bytes());
        let l = self.policy_vec.len();
        vec.extend_from_slice(&(l as u16).to_be_bytes());
        for (idx, v) in self.policy_vec.iter() {
            vec.extend_from_slice(&idx.to_be_bytes());
            vec.extend_from_slice(&v.to_bytes());
        }
        vec
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let variant = cur.read_u16::<BigEndian>().ok()?;
        let expiry = cur.read_u64::<BigEndian>().ok()?;
        let len = cur.read_u16::<BigEndian>().ok()?;
        let mut policy_vec = common::safe_with_capacity(len as usize);
        for _ in 0..len {
            let idx = cur.read_u16::<BigEndian>().ok()?;
            let att = AttributeType::from_bytes(cur)?;
            policy_vec.push((idx, att));
        }
        Some(Policy {
            variant,
            expiry,
            policy_vec,
            _phantom: Default::default(),
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.acc_scheme_id.to_bytes().to_vec();
        // NOTE: Serialize the public key with length to match what is in Haskell code
        // and in order to accept different signature schemes in the future.
        let sig_bytes = self.acc_pub_key.to_bytes();
        v.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(&sig_bytes);
        v.extend_from_slice(&self.reg_id.curve_to_bytes());
        v.extend_from_slice(&self.ip_identity.to_be_bytes());
        v.extend_from_slice(&(self.ar_data.len() as u16).to_be_bytes());
        for ar in self.ar_data.iter() {
            v.extend_from_slice(&ar.to_bytes());
        }
        v.extend_from_slice(&self.policy.to_bytes());
        v.extend_from_slice(&(self.choice_ar_handles.len() as u16).to_be_bytes());
        for ar in self.choice_ar_handles.iter() {
            v.extend_from_slice(&ar.to_be_bytes());
        }
        v
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let acc_scheme_id = SchemeId::from_bytes(cur)?;
        let sig_length = cur.read_u16::<BigEndian>().ok()?;
        let mut buf = vec![0; sig_length as usize];
        cur.read_exact(&mut buf).ok()?;
        let acc_pub_key = acc_sig_scheme::PublicKey::from_bytes(&buf).ok()?;
        let reg_id = curve_serialization::read_curve::<C>(cur).ok()?;
        let ip_identity = cur.read_u32::<BigEndian>().ok()?;
        let number_of_ars = cur.read_u16::<BigEndian>().ok()?;
        let mut ar_data = Vec::with_capacity(number_of_ars as usize);
        for _ in 0..number_of_ars {
            ar_data.push(ChainArData::from_bytes(cur)?);
        }
        let policy = Policy::from_bytes(cur)?;
        let number_of_ars = cur.read_u16::<BigEndian>().ok()?;
        let mut choice_ar_handles = Vec::with_capacity(number_of_ars as usize);
        for _ in 0..number_of_ars {
            choice_ar_handles.push(cur.read_u64::<BigEndian>().ok()?);
        }
        Some(CredentialDeploymentValues {
            acc_scheme_id,
            acc_pub_key,
            reg_id,
            ip_identity,
            ar_data,
            choice_ar_handles,
            policy,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredDeploymentInfo<P, C, AttributeType>
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.values.to_bytes();
        let proof_bytes = self.proofs.to_bytes();
        v.extend_from_slice(&proof_bytes);
        v
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let values = CredentialDeploymentValues::from_bytes(cur);

        let proofs = CredDeploymentProofs::<P, C>::from_bytes(cur);
        Some(CredDeploymentInfo {
            values: values?,
            proofs: proofs?,
        })
    }
}

impl<P: Pairing> SigRetrievalRandomness<P> {
    pub fn to_bytes(&self) -> Box<[u8]> { P::G_1::scalar_to_bytes(&self.0) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let scalar = curve_serialization::read_curve_scalar::<P::G_1>(cur).ok()?;
        Some(SigRetrievalRandomness(scalar))
    }
}

impl<C: Curve> PolicyProof<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut v = Vec::with_capacity(2 * C::SCALAR_LENGTH);
        v.extend_from_slice(&C::scalar_to_bytes(&self.variant_rand));
        v.extend_from_slice(&C::scalar_to_bytes(&self.expiry_rand));
        v.extend_from_slice(&(self.cmm_opening_map.len() as u16).to_be_bytes());
        for (idx, r) in self.cmm_opening_map.iter() {
            v.extend_from_slice(&idx.to_be_bytes());
            v.extend_from_slice(&C::scalar_to_bytes(r));
        }
        v.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let variant_rand = C::bytes_to_scalar(cur).ok()?;
        let expiry_rand = C::bytes_to_scalar(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_opening_map = common::safe_with_capacity(l as usize);
        for _ in 0..l {
            let idx = cur.read_u16::<BigEndian>().ok()?;
            let scalar = curve_serialization::read_curve_scalar::<C>(cur).ok()?;
            cmm_opening_map.push((idx, scalar));
        }
        Some(PolicyProof {
            variant_rand,
            expiry_rand,
            cmm_opening_map,
        })
    }
}
impl<C: Curve> ArInfo<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r: Vec<u8> = Vec::from(&self.ar_identity.to_be_bytes()[..]);
        // let mut r = Vec::with_capacity(4);
        // r.extend_from_slice(self.ar_identity.to_be_bytes());
        r.extend_from_slice(&short_string_to_bytes(&self.ar_description));
        r.extend_from_slice(&self.ar_public_key.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_identity = cur.read_u64::<BigEndian>().ok()?;
        let ar_description = bytes_to_short_string(cur)?;
        let ar_public_key = elgamal::PublicKey::from_bytes(cur).ok()?;
        Some(ArInfo {
            ar_identity,
            ar_description,
            ar_public_key,
        })
    }
}
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> IpInfo<P, C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = Vec::with_capacity(4);
        r.extend_from_slice(&self.ip_identity.to_be_bytes());
        r.extend_from_slice(&short_string_to_bytes(&self.ip_description));
        r.extend_from_slice(&self.ip_verify_key.to_bytes());
        r.extend_from_slice(&self.dlog_base.curve_to_bytes());
        let l = &self.ar_info.0.len();
        r.extend_from_slice(&l.to_be_bytes());
        for item in &self.ar_info.0 {
            r.extend_from_slice(&item.to_bytes());
        }
        r.extend_from_slice(&self.ar_info.1.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ip_identity = cur.read_u32::<BigEndian>().ok()?;
        let ip_description = bytes_to_short_string(cur)?;
        let ip_verify_key = pssig::PublicKey::from_bytes(cur).ok()?;
        let dlog_base = P::G_1::bytes_to_curve(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut ar_list = Vec::with_capacity(l as usize);
        for _ in 0..l {
            ar_list.push(ArInfo::from_bytes(cur)?);
        }
        let ar_info = (ar_list, PedersenKey::from_bytes(cur).ok()?);
        Some(IpInfo {
            ip_identity,
            ip_description,
            ip_verify_key,
            dlog_base,
            ar_info,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> Context<P, C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        r.extend_from_slice(&self.ip_info.to_bytes());
        r.extend_from_slice(&self.commitment_key_sc.to_bytes());
        r.extend_from_slice(&self.commitment_key_prf.to_bytes());
        let l = &self.choice_ar_parameters.0.len();
        r.extend_from_slice(&l.to_be_bytes());
        for item in &self.choice_ar_parameters.0 {
            r.extend_from_slice(&item.to_bytes());
        }
        r.extend_from_slice(&self.choice_ar_parameters.1.to_be_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ip_info = IpInfo::from_bytes(cur)?;
        let commitment_key_sc = PedersenKey::from_bytes(cur).ok()?;
        let commitment_key_prf = PedersenKey::from_bytes(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut ar_list = Vec::with_capacity(l as usize);
        for _ in 0..l {
            ar_list.push(ArInfo::from_bytes(cur)?);
        }
        let choice_ar_parameters = (ar_list, cur.read_u64::<BigEndian>().ok()?);
        Some(Context {
            ip_info,
            commitment_key_sc,
            commitment_key_prf,
            choice_ar_parameters,
        })
    }
}

impl<C: Curve> GlobalContext<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        r.extend_from_slice(&self.dlog_base_chain.curve_to_bytes());
        r.extend_from_slice(&self.on_chain_commitment_key.to_bytes());
        r.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let dlog_base_chain = C::bytes_to_curve(cur).ok()?;
        let on_chain_commitment_key = PedersenKey::from_bytes(cur).ok()?;
        Some(GlobalContext {
            dlog_base_chain,
            on_chain_commitment_key,
        })
    }
}
