use crate::types::*;

use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use pedersen_scheme::value as pedersen;
use elgamal::message::Message as ElgamalMessage;
use rand::*;
use sigma_protocols::{com_enc_eq, com_eq_different_groups, dlog};

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
pub fn generate_pio<
    P: Pairing,
    AttributeType: Attribute<C::Scalar>,
    C: Curve<Scalar = P::ScalarField>,
>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<P, C, AttributeType>,
) -> PreIdentityObject<P, C, AttributeType>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();
    let id_ah = aci.acc_holder_info.id_ah.clone();
    let id_cred_pub = aci.acc_holder_info.id_cred.id_cred_pub;
    let id_cred_pub_ip = aci.acc_holder_info.id_cred.id_cred_pub_ip;
    let prf::SecretKey(prf_key_scalar) = aci.prf_key;
    let id_cred_pub_point = aci.acc_holder_info.id_cred.id_cred_pub; 
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    let (prf_key_enc, prf_key_enc_rand) = context
        .ip_info
        .ar_info
        .ar_public_key
        .encrypt_exponent_rand(&mut csprng, &prf_key_scalar);
    let id_cred_pub_enc = context
        .ip_info
        .ar_info
        .ar_public_key
        .encrypt(&mut csprng, &ElgamalMessage::<C>(id_cred_pub));
    let id_ar_data = ArData {
        ar_name:  context.ip_info.ar_info.ar_name.clone(),
        prf_key_enc : prf_key_enc,
        id_cred_pub_enc: id_cred_pub_enc,
    };
    let alist = aci.attributes.clone();
    let pok_sc = dlog::prove_dlog(
        &mut csprng,
        &id_cred_pub_ip,
        &aci.acc_holder_info.id_cred.id_cred_sec,
        &context.dlog_base,
    );
    let (cmm_prf, rand_cmm_prf) = context
        .commitment_key_id
        .commit(&pedersen::Value(vec![prf_key_scalar]), &mut csprng);
    let (snd_cmm_prf, rand_snd_cmm_prf) = context
        .commitment_key_ar
        .commit(&pedersen::Value(vec![prf_key_scalar]), &mut csprng);
    // now generate the proof that the commitment hidden in snd_cmm_prf is to
    // the same prf key as the one encrypted in id_ar_data via anonymity revokers
    // public key.
    let proof_com_enc_eq = {
        let public = (prf_key_enc.0, prf_key_enc.1, snd_cmm_prf.0);
        // TODO: Check that this order of secret values is correct!
        // FIXME: I think this is consistent with the way the protocol in the whitepaper
        // is written, but is different from what Bassel said it should be.
        // Doing it like this at least works correctly in the application.
        let secret = (prf_key_enc_rand, prf_key_scalar, rand_snd_cmm_prf);
        let base = (
            context.ip_info.ar_info.ar_elgamal_generator,
            context.ip_info.ar_info.ar_public_key.0,
            context.commitment_key_ar.0[0],
            context.commitment_key_ar.1,
        );
        com_enc_eq::prove_com_enc_eq(&mut csprng, &public, &secret, &base)
    };
    let proof_com_eq = {
        let public = (cmm_prf.0, snd_cmm_prf.0);
        // TODO: Check that this is the correct order of secret values.
        let secret = (prf_key_scalar, rand_cmm_prf, rand_snd_cmm_prf);
        let coeff = (
            (context.commitment_key_id.0[0], context.commitment_key_id.1),
            (context.commitment_key_ar.0[0], context.commitment_key_ar.1),
        );
        com_eq_different_groups::prove_com_eq_diff_grps(&mut csprng, &public, &secret, &coeff)
    };
    PreIdentityObject {
        id_ah,
        id_cred_pub_ip,
        id_ar_data,
        alist,
        pok_sc,
        cmm_prf,
        snd_cmm_prf,
        proof_com_enc_eq,
        proof_com_eq,
    }
}
