use curve_arithmetic::curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use elgamal::cipher::Cipher;
use pairing::Field;
use pedersen_scheme::commitment as pedersen;
use ps_sig::{public as pssig, signature::*};

use sigma_protocols::{
    com_enc_eq::ComEncEqProof, com_eq_different_groups::ComEqDiffGrpsProof, dlog::DlogProof,
};

pub struct CommitmentParams<C: Curve>(pub (C, C));
pub struct ElgamalParams<C: Curve>(pub (C, C));

pub trait Attribute<F: Field> {
    fn to_field_element(&self) -> F;
}

#[derive(Clone, Debug)]
pub struct AttributeList<F: Field, AttributeType: Attribute<F>> {
    pub variant:  u32,
    pub alist:    Vec<AttributeType>,
    pub _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug)]
pub struct IdCredentials<C: Curve> {
    pub id_cred_sec: elgamal::SecretKey<C>,
    pub id_cred_pub: elgamal::PublicKey<C>,
}

/// Private credential holder information. A user maintaints these
/// through many different interactions with the identity provider and
/// the chain.
#[derive(Debug)]
pub struct CredentialHolderInfo<P: Pairing> {
    /// Name of the credential holder.
    pub id_ah: String,
    /// Public and private keys of the credential holder. NB: These are distinct
    /// from the public/private keys of the account holders.
    pub id_cred: IdCredentials<P::G_1>,
    // aux_data: &[u8]
}

/// Private and public data chosen by the credential holder before the
/// interaction with the identity provider. The credential holder chooses a prf
/// key and an attribute list.
#[derive(Debug)]
pub struct AccCredentialInfo<P: Pairing, AttributeType: Attribute<P::ScalarField>> {
    pub acc_holder_info: CredentialHolderInfo<P>,
    /// Chosen prf key of the credential holder.
    pub prf_key: prf::SecretKey<P::G_1>,
    /// Chosen attribute list.
    pub attributes: AttributeList<P::ScalarField, AttributeType>,
}

/// Data created by the credential holder to support anonymity revocation.
pub struct ArData<C: Curve> {
    /// Identity of the anonymity revoker.
    pub ar_name: String,
    /// Encryption of the prf key of the credential holder.
    pub e_reg_id: Cipher<C>,
}

/// Information sent from the account holder to the identity provider.
pub struct PreIdentityObject<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
> {
    /// Name of the account holder.
    pub id_ah: String,
    /// Public credential of the account holder only.
    pub id_cred_pub: elgamal::PublicKey<P::G_1>,
    /// Information on the chosen anonymity revoker, and the encryption of the
    /// account holder's prf key with the anonymity revoker's encryption key.
    pub id_ar_data: ArData<C>,
    /// Chosen attribute list.
    pub alist: AttributeList<P::ScalarField, AttributeType>,
    /// Proof of knowledge of secret credentials corresponding to id_cred_pub
    pub pok_sc: DlogProof<P::G_1>,
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
pub struct IpInfo<P: Pairing, C: Curve> {
    pub id_identity: String,
    pub id_verify_key: pssig::PublicKey<P>,
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

/// Information the account holder has after the interaction with the identity
/// provider. The account holder uses this information to generate credentials
/// to deploy on the chain.
pub struct IdentityObject<P: Pairing, AttributeType: Attribute<P::ScalarField>, C: Curve> {
    /// Identity provider who checked and signed the data in the
    /// PreIdentityObject.
    pub id_provider: IpInfo<P, C>,
    pub acc_credential_info: AccCredentialInfo<P, AttributeType>,
    /// Signature of the PreIdentityObject data.
    pub sig: Signature<P>,
    /// Information on the chosen anonymity revoker, and the encryption of the
    /// account holder's prf key with the anonymity revoker's encryption key.
    /// Should be the same as the data signed by the identity provider.
    pub ar_data: ArData<C>,
}

pub struct CredDeploymentInfo<P: Pairing, AttributeType: Attribute<P::ScalarField>> {
    pub reg_id:     P::G_1,
    pub attributes: AttributeList<P::ScalarField, AttributeType>,
}
