use curve_arithmetic::curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use elgamal::cipher::Cipher;
use pairing::Field;
use pedersen_scheme::{commitment as pedersen, key::CommitmentKey as PedersenKey};
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
#[derive(Debug, Clone)]
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

/// Context needed to generate pre-identity object.
/// This context is derived from the public information of the identity
/// provider, as well as some other global parameters which can be found in the
/// struct 'GlobalContext'.
pub struct Context<P: Pairing, C: Curve> {
    /// Public information on the chosen identity provider and anonymity
    /// revoker(s).
    pub ip_info: IpInfo<P, C>,
    /// base point of the dlog proof (account holder knows secret credentials
    /// corresponding to the public credentials), shared at least between id
    /// provider and the account holder
    pub dlog_base: P::G_1,
    /// Commitment key shared by the identity provider and the account holder.
    /// It is used to generate commitments to the prf key.
    pub commitment_key_id: PedersenKey<P::G_1>,
    /// Commitment key shared by the anonymity revoker, identity provider, and
    /// account holder. Used to commit to the prf key of the account holder in
    /// the same group as the encryption of the prf key as given to the
    /// anonymity revoker.
    pub commitment_key_ar: PedersenKey<C>,
}

pub struct GlobalContext<P: Pairing> {
    /// Base point of the dlog proof. This must be the same as the generator of
    /// the elgamal encryption group used by the identity providers. Currently
    /// we assume that the generator is fixed globally for the group (since all
    /// identity providers use the same group). This parameter is currently not
    /// in the IpInfo struct because we might need it to not be chosen by
    /// the identity provider.
    ///
    /// If it is then maybe the identity provider could revel the prf key of the
    /// account holder. TODO: CHECK IF THIS IS REALLY THE CASE.
    pub dlog_base: P::G_1,

    /// A shared commitment key known to the chain and the account holder (and
    /// therefore it is public). The account holder uses this commitment key to
    /// generate commitments to values in the attribute list.
    /// This key should presumably be generated at genesis time via some shared
    /// multi-party computation since none of the parties should know anything
    /// special about it (so that commitment is binding, and that the commitment
    /// cannot be broken).
    /// TODO: Check with Bassel that the key is over the correct group.
    pub on_chain_commitment_key: PedersenKey<P::G_1>,
}

/// Make a context in which the account holder can produce a pre-identity object
/// to send to the identity provider. Also requires access to the global context
/// of parameters, e.g., dlog-proof base point.
pub fn make_context_from_ip_info<P: Pairing, C: Curve>(
    ip_info: IpInfo<P, C>,
    global: &GlobalContext<P>,
) -> Context<P, C> {
    // TODO: Check with Bassel that these parameters are correct.
    let commitment_key_id =
        PedersenKey(vec![ip_info.id_verify_key.0[0]], ip_info.id_verify_key.0[1]);
    let commitment_key_ar = PedersenKey(
        vec![ip_info.ar_info.ar_elgamal_generator],
        ip_info.ar_info.ar_public_key.0,
    );
    Context {
        ip_info,
        dlog_base: global.dlog_base,
        commitment_key_id,
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
