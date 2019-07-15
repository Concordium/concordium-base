use curve_arithmetic::{curve_arithmetic::*, serialization as curve_serialization};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as acc_sig_scheme;
use ed25519_dalek as ed25519;
use eddsa_ed25519::dlog_ed25519::Ed25519DlogProof;
use elgamal::cipher::Cipher;
use pairing::Field;
use pedersen_scheme::{commitment as pedersen, key::CommitmentKey as PedersenKey};
use ps_sig::{public as pssig, signature::*};

use sigma_protocols::{
    com_enc_eq::ComEncEqProof, com_eq::ComEqProof, com_eq_different_groups::ComEqDiffGrpsProof,
    com_eq_sig::ComEqSigProof, com_mult::ComMultProof,
};

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub struct CommitmentParams<C: Curve>(pub (C, C));
pub struct ElgamalParams<C: Curve>(pub (C, C));

pub trait Attribute<F: Field>: Copy + Clone + Sized + Send + Sync {
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
pub struct IdCredentials<C: Curve, T: Curve<Scalar = C::Scalar>> {
    pub id_cred_sec:    C::Scalar,
    pub id_cred_pub:    C,
    pub id_cred_pub_ip: T,
}

/// Private credential holder information. A user maintaints these
/// through many different interactions with the identity provider and
/// the chain.
#[derive(Debug)]
pub struct CredentialHolderInfo<C: Curve, T: Curve<Scalar = C::Scalar>> {
    /// Name of the credential holder.
    pub id_ah: String,
    /// Public and private keys of the credential holder. NB: These are distinct
    /// from the public/private keys of the account holders.
    pub id_cred: IdCredentials<C, T>,
    // aux_data: &[u8]
}

/// Private and public data chosen by the credential holder before the
/// interaction with the identity provider. The credential holder chooses a prf
/// key and an attribute list.
#[derive(Debug)]
pub struct AccCredentialInfo<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub acc_holder_info: CredentialHolderInfo<C, P::G_1>,
    /// Chosen prf key of the credential holder.
    pub prf_key: prf::SecretKey<C>,
    /// Chosen attribute list.
    pub attributes: AttributeList<C::Scalar, AttributeType>,
}

pub struct IpArData<C: Curve> {
    /// Identity of the anonymity revoker.
    pub ar_name: String,
    /// Encryption of the prf key of the credential holder.
    pub prf_key_enc: Cipher<C>,
}
/// Data created by the credential holder to support anonymity revocation.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainArData<C: Curve> {
    /// Identity of the anonymity revoker.
    pub ar_name: String,
    /// Encryption of public identity credentials
    pub id_cred_pub_enc: Cipher<C>,
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
    /// Information on the chosen anonymity revoker, and the encryption of the
    /// account holder's prf key with the anonymity revoker's encryption key.
    pub ip_ar_data: IpArData<C>,
    /// Chosen attribute list.
    pub alist: AttributeList<C::Scalar, AttributeType>,
    /// Proof of knowledge of secret credentials corresponding to id_cred_pub
    /// matching the commitment cmm_sc
    pub pok_sc: ComEqProof<P::G_1>,
    /// commitment to id cred sec
    pub cmm_sc: pedersen::Commitment<P::G_1>,
    /// Commitment to the prf key.
    pub cmm_prf: pedersen::Commitment<P::G_1>,
    /// commitment to the prf key in the same group as the elgamal key of the
    /// anonymity revoker
    pub snd_cmm_prf: pedersen::Commitment<C>,
    /// Proof that the encryption of the prf key in id_ar_data is the same as
    /// the key in snd_cmm_prf (hidden behind the commitment).
    pub proof_com_enc_eq: ComEncEqProof<C>,
    /// Proof that the first and snd commitments to the prf are hiding the same
    /// value
    pub proof_com_eq: ComEqDiffGrpsProof<P::G_1, C>,
}

/// Public information about an identity provider.
#[derive(Debug, Clone)]
pub struct IpInfo<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub ip_identity: String,
    pub ip_verify_key: pssig::PublicKey<P>,
    /// In the current design the identity provider chooses a single anonymity
    /// revoker. This will be changed in the future.
    pub ar_info: ArInfo<C>,
}

#[derive(Clone, Debug)]
pub struct ArInfo<C: Curve> {
    /// The name and public key of the anonymity revoker chosen by this identity
    /// provider. In the future each identity provider will allow a set of
    /// anonymity revokers.
    pub ar_name: String,
    pub ar_public_key: elgamal::PublicKey<C>,
    pub ar_elgamal_generator: C,
}

#[derive(Debug)]
pub struct SigRetrievalRandomness<P: Pairing>(pub P::ScalarField);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CredDeploymentCommitments<C: Curve> {
    // commitment to id_cred_sec
    pub cmm_id_cred_sec: pedersen::Commitment<C>,
    // commitment to the prf key
    pub cmm_prf: pedersen::Commitment<C>,
    // commitment to credential counter
    pub cmm_cred_counter: pedersen::Commitment<C>,
    // commitments to the attribute list
    pub cmm_attributes: Vec<pedersen::Commitment<C>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredDeploymentProofs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Signature derived from the signature of the pre-identity object by the
    /// IP
    pub sig: Signature<P>,
    /// Individual commitments to each item in the attribute list.
    pub commitments: CredDeploymentCommitments<C>,
    /// Proof of knowledge of IdCredSec corresponding to the commitment made on
    /// the chain. The commitment is signed by the IP, and so this proof makes
    /// sure that we have encrypted IDCredPub correctly so anonymity can be
    /// revoked.
    pub proof_id_cred_pub: ComEncEqProof<C>,
    /// Proof of knowledge of signature of Identity Provider on the list
    /// (idCredSec, prfKey, attributes[0], attributes[1],..., attributes[n])
    pub proof_ip_sig: ComEqSigProof<P, C>,
    /// Proof that reg_id = prf_K(x). Also establishes that reg_id is computed
    /// from the prf key signed by the identity provider.
    pub proof_reg_id: ComMultProof<C>,
    /// Proof of knowledge of acc secret key (signing key corresponding to the
    /// verification key).
    pub proof_acc_sk: Ed25519DlogProof,
    /// Proof that the attributelist in commitments.cmm_attributes satisfy the
    pub proof_policy: PolicyProof<C>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Policy<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub variant: u16,
    /// Expiry time, in seconds since the unix epoch, ignoring leap seconds.
    pub expiry: u64,
    /// TODO: Policy should not be scalars, but rather attributetype elements
    /// (which means we need an additional parameter).
    pub policy_vec: Vec<(u16, AttributeType)>,
    pub _phantom: std::marker::PhantomData<C>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchemeId {
    Ed25519,
    CL,
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
    pub ip_identity: String,
    /// Anonymity revocation data. Which anonymity revokers have the capability
    /// to remove the anonymity of the account.
    pub ar_data: ChainArData<C>,
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
    /// base point of the dlog proof (account holder knows secret credentials
    /// corresponding to the public credentials), shared at least between id
    /// provider and the account holder
    pub dlog_base: P::G_1,
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the id cred sec key.
    pub commitment_key_sc: PedersenKey<P::G_1>,
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the prf key.
    pub commitment_key_prf: PedersenKey<P::G_1>,
    /// Commitment key shared by the anonymity revoker, identity provider, and
    /// account holder. Used to commit to the prf key of the account holder in
    /// the same group as the encryption of the prf key as given to the
    /// anonymity revoker.
    pub commitment_key_ar: PedersenKey<C>,
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
) -> Context<P, C> {
    // TODO: Check with Bassel that these parameters are correct.
    let dlog_base = <P as Pairing>::G_1::one_point();
    let commitment_key_sc = PedersenKey(vec![ip_info.ip_verify_key.2[0]], dlog_base);
    let commitment_key_prf = PedersenKey(vec![ip_info.ip_verify_key.2[1]], dlog_base);
    let commitment_key_ar = PedersenKey(
        vec![ip_info.ar_info.ar_elgamal_generator],
        ip_info.ar_info.ar_public_key.0,
    );
    Context {
        ip_info,
        dlog_base,
        commitment_key_sc,
        commitment_key_prf,
        commitment_key_ar,
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
    let mut out = Vec::with_capacity(l + 2);
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
        let mut r = short_string_to_bytes(&self.ar_name);
        r.extend_from_slice(&self.prf_key_enc.to_bytes());
        r
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_name = bytes_to_short_string(cur)?;
        let prf_key_enc = Cipher::from_bytes(cur).ok()?;
        Some(IpArData {
            ar_name,
            prf_key_enc,
        })
    }
}

impl<C: Curve> ChainArData<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut r = short_string_to_bytes(&self.ar_name);
        r.extend_from_slice(&self.id_cred_pub_enc.to_bytes());
        r
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let ar_name = bytes_to_short_string(cur)?;
        let id_cred_pub_enc = Cipher::from_bytes(cur).ok()?;
        Some(ChainArData {
            ar_name,
            id_cred_pub_enc,
        })
    }
}

impl<C: Curve> CredDeploymentCommitments<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::from(self.cmm_id_cred_sec.to_bytes());
        out.extend_from_slice(&self.cmm_prf.to_bytes());
        out.extend_from_slice(&self.cmm_cred_counter.to_bytes());
        let atts = &self.cmm_attributes;
        out.extend_from_slice(&(atts.len() as u16).to_be_bytes());
        for a in atts {
            out.extend_from_slice(&a.to_bytes());
        }
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let cmm_id_cred_sec = pedersen::Commitment::from_bytes(cur).ok()?;
        let cmm_prf = pedersen::Commitment::from_bytes(cur).ok()?;
        let cmm_cred_counter = pedersen::Commitment::from_bytes(cur).ok()?;
        let l = cur.read_u16::<BigEndian>().ok()?;
        let mut cmm_attributes = Vec::with_capacity(l as usize);
        for _ in 0..l {
            cmm_attributes.push(pedersen::Commitment::from_bytes(cur).ok()?)
        }
        Some(CredDeploymentCommitments {
            cmm_id_cred_sec,
            cmm_prf,
            cmm_cred_counter,
            cmm_attributes,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> CredDeploymentProofs<P, C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.sig.to_bytes().to_vec();
        out.extend_from_slice(&self.commitments.to_bytes());
        out.extend(&self.proof_id_cred_pub.to_bytes());
        out.extend_from_slice(&self.proof_ip_sig.to_bytes());
        out.extend_from_slice(&self.proof_reg_id.to_bytes());
        out.extend_from_slice(&self.proof_acc_sk.to_bytes());
        out.extend_from_slice(&self.proof_policy.to_bytes());
        out
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let sig = Signature::from_bytes(cur).ok()?;
        let commitments = CredDeploymentCommitments::from_bytes(cur)?;
        let proof_id_cred_pub = ComEncEqProof::from_bytes(cur).ok()?;
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
        let mut vec = Vec::with_capacity(4);
        vec.extend_from_slice(&self.variant.to_be_bytes());
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
        let mut policy_vec = Vec::with_capacity(len as usize);
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
            SchemeId::CL => [0],
            SchemeId::Ed25519 => [1],
        }
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<SchemeId> {
        match cur.read_u8().ok()? {
            0 => Some(SchemeId::CL),
            1 => Some(SchemeId::Ed25519),
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
        v.extend_from_slice(&short_string_to_bytes(&self.ip_identity));
        v.extend_from_slice(&self.ar_data.to_bytes());
        v.extend_from_slice(&self.policy.to_bytes());
        v
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let acc_scheme_id = SchemeId::from_bytes(cur)?;
        let sig_length = cur.read_u16::<BigEndian>().ok()?;
        let mut buf = vec![0; sig_length as usize];
        cur.read_exact(&mut buf).ok()?;
        let acc_pub_key = acc_sig_scheme::PublicKey::from_bytes(&buf).ok()?;
        let reg_id = curve_serialization::read_curve::<C>(cur).ok()?;
        let ip_identity = bytes_to_short_string(cur)?;
        let ar_data = ChainArData::from_bytes(cur)?;
        let policy = Policy::from_bytes(cur)?;
        Some(CredentialDeploymentValues {
            acc_scheme_id,
            acc_pub_key,
            reg_id,
            ip_identity,
            ar_data,
            policy,
        })
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredDeploymentInfo<P, C, AttributeType>
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.values.to_bytes();
        v.extend_from_slice(&self.proofs.to_bytes());
        v
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let values = CredentialDeploymentValues::from_bytes(cur)?;
        let proofs = CredDeploymentProofs::from_bytes(cur)?;
        Some(CredDeploymentInfo { values, proofs })
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
        let mut cmm_opening_map = Vec::with_capacity(l as usize);
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
