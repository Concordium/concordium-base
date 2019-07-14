use crate::types::*;

use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::{cipher::Cipher, message::Message as ElgamalMessage};
use pairing::Field;
use pedersen_scheme::{
    commitment::Commitment,
    key::{CommitmentKey, CommitmentKey as PedersenKey},
    value as pedersen,
    value::Value,
};
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult, dlog};

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
) -> (
    PreIdentityObject<P, C, AttributeType>,
    SigRetrievalRandomness<P>,
)
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();
    let id_ah = aci.acc_holder_info.id_ah.clone();
    let id_cred_pub_ip = aci.acc_holder_info.id_cred.id_cred_pub_ip;
    let prf::SecretKey(prf_key_scalar) = aci.prf_key;
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    let (prf_key_enc, prf_key_enc_rand) = context
        .ip_info
        .ar_info
        .ar_public_key
        .encrypt_exponent_rand(&mut csprng, &prf_key_scalar);
    let ip_ar_data = IpArData {
        ar_name: context.ip_info.ar_info.ar_name.clone(),
        prf_key_enc,
    };
    let alist = aci.attributes.clone();

    let id_cred_sec = aci.acc_holder_info.id_cred.id_cred_sec;
    let sc_ck = &context.commitment_key_sc;
    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(&pedersen::Value(vec![id_cred_sec]), &mut csprng);
    let pok_sc = {
        let Commitment(cmm_sc_point) = cmm_sc;
        let CommitmentKey(sc_ck_1, sc_ck_2) = sc_ck;
        com_eq::prove_com_eq(
            &[],
            &(vec![cmm_sc_point], id_cred_pub_ip),
            &(sc_ck_1[0], *sc_ck_2, vec![context.dlog_base]),
            &(vec![cmm_sc_rand], vec![id_cred_sec]),
            &mut csprng,
        )
    };

    let (cmm_prf, rand_cmm_prf) = context
        .commitment_key_prf
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
        com_enc_eq::prove_com_enc_eq(&mut csprng, &[], &public, &secret, &base)
    };
    let proof_com_eq = {
        let public = (cmm_prf.0, snd_cmm_prf.0);
        // TODO: Check that this is the correct order of secret values.
        let secret = (prf_key_scalar, rand_cmm_prf, rand_snd_cmm_prf);
        let coeff = (
            (
                context.commitment_key_prf.0[0],
                context.commitment_key_prf.1,
            ),
            (context.commitment_key_ar.0[0], context.commitment_key_ar.1),
        );
        com_eq_different_groups::prove_com_eq_diff_grps(&mut csprng, &[], &public, &secret, &coeff)
    };
    let prio = PreIdentityObject {
        id_ah,
        id_cred_pub_ip,
        ip_ar_data,
        alist,
        cmm_sc,
        pok_sc,
        cmm_prf,
        snd_cmm_prf,
        proof_com_enc_eq,
        proof_com_eq,
    };
    let mut sig_retrieval_rand = cmm_sc_rand;
    sig_retrieval_rand.add_assign(&rand_cmm_prf);
    (prio, SigRetrievalRandomness(sig_retrieval_rand))
}

pub fn generate_cdi<
    P: Pairing,
    AttributeType: Attribute<C::Scalar>,
    C: Curve<Scalar = P::ScalarField>,
>(
    ip_info: &IpInfo<P, C>,
    global_context: &GlobalContext<C>,

    aci: &AccCredentialInfo<P, C, AttributeType>,
    prio: &PreIdentityObject<P, C, AttributeType>,
    cred_counter: u8,
    ip_sig: &ps_sig::Signature<P>,
    policy: &Policy<C>,
    acc_data: &AccountData,
    sig_retrieval_rand: &SigRetrievalRandomness<P>,
) -> CredDeploymentInfo<P, C>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();

    let commitment_base = global_context.on_chain_commitment_key.0[0];

    let alist = &prio.alist;
    let prf_key = aci.prf_key;
    let id_cred_sec = aci.acc_holder_info.id_cred.id_cred_sec;
    let reg_id_exponent = match aci.prf_key.prf_exponent(cred_counter) {
        Ok(exp) => exp,
        Err(err) => unimplemented!("Handle the (very unlikely) case where K + x = 0, {}", err),
    };

    let reg_id = commitment_base.mul_by_scalar(&reg_id_exponent);

    // IdCredPub in the same group as the anonymity revoker's data.
    // FIXME: We need to have the generator as parameter. Right now this all
    // works by accident because the generator is always chosen as C::one_point().
    let id_cred_pub = aci.acc_holder_info.id_cred.id_cred_pub;
    let (id_cred_pub_enc, id_cred_pub_rand) =
        ip_info
        .ar_info
        .ar_public_key
        .encrypt_rand(&mut csprng, &ElgamalMessage::<C>(id_cred_pub));

    let ip_pub_key = &ip_info.ip_verify_key;

    let ar_data = ChainArData {
        ar_name: prio.ip_ar_data.ar_name.clone(),
        id_cred_pub_enc,
    };

    // retrieve the signature on the underlying idcredsec + prf_key + attribute_list
    let retrieved_sig = ps_sig::retrieve_sig(&ip_sig, sig_retrieval_rand.0);

    // and then we blind the signature to disassociate it from the message.
    // only the second part is used (as per the protocol)
    let (blinded_sig, _r, t) = ps_sig::blind_sig(&retrieved_sig, &mut csprng);

    // We now compute commitments to all the items in the attribute list.
    // We use the on-chain pedersen commitment key.
    let (commitments, commitment_rands) = compute_commitments(
        &global_context.on_chain_commitment_key,
        &alist,
        &prf_key,
        &id_cred_sec,
        cred_counter,
        &mut csprng,
    );

    // Compute the proof of the fact that the encryption of idcredpub we
    // computed above corresponds to the same id_cred_sec that is signed by the
    // identity provider (and commited to)
    let pok_id_cred_pub = compute_pok_id_cred_pub(
        &ip_info,
        &global_context,
        &id_cred_sec,
        &id_cred_pub_enc,
        &id_cred_pub_rand,
        &commitments.cmm_id_cred_sec,
        &commitment_rands.id_cred_sec_rand,
        &mut csprng,
    );

    // Proof that the registration id is computed correctly from the prf key K and
    // the cred_counter x. At the moment there is no proof that x is less than
    // max_account.
    let pok_reg_id = compute_pok_reg_id(
        &global_context.on_chain_commitment_key,
        prf_key,
        &commitments.cmm_prf,
        commitment_rands.prf_rand,
        cred_counter,
        &commitments.cmm_cred_counter,
        commitment_rands.cred_counter_rand,
        reg_id_exponent,
        reg_id,
        &mut csprng,
    );

    // Proof of knowledge of the signature of the identity provider.
    let pok_sig = compute_pok_sig(
        &global_context.on_chain_commitment_key,
        &commitments,
        &commitment_rands,
        &id_cred_sec,
        &prf_key,
        &alist,
        &ip_pub_key,
        &blinded_sig,
        &t,
        &mut csprng,
    );

    // TODO: Fix
    let challenge_prefix = [0; 32];

    // Proof of knowledge of the secret key corresponding to the public
    // (verification) key.
    let proof_acc_sk =
        eddsa_dlog::prove_dlog_ed25519(&challenge_prefix, &acc_data.verify_key, &acc_data.sign_key);

    let cdp = CredDeploymentProofs {
        proof_id_cred_pub: pok_id_cred_pub,
        proof_ip_sig: pok_sig,
        proof_reg_id: pok_reg_id,
        proof_acc_sk,
    };

    CredDeploymentInfo {
        acc_scheme_id: SchemeId::Ed25519,
        reg_id,
        sig: blinded_sig,
        ar_data,
        ip_identity: ip_info.ip_identity.clone(),
        policy: policy.clone(),
        acc_pub_key: acc_data.verify_key,
        commitments,
        proofs: cdp,
        proof_policy: open_policy_commitments(&policy, &commitment_rands),
    }
}

fn open_policy_commitments<C: Curve>(
    policy: &Policy<C>,
    commitment_rands: &CommitmentsRandomness<C>,
) -> PolicyProof<C> {
    // FIXME: Handle this more resiliantly.
    let att_rands = &commitment_rands.attributes_rand;
    assert!(att_rands.len() >= 2);
    let variant_rand = att_rands[0];
    let expiry_rand = att_rands[1];
    // FIXME: Handle out-of-range.
    let cmm_opening_map = policy
        .policy_vec
        .iter()
        .map(|(idx, _)| (*idx, att_rands[*idx as usize + 2]))
        .collect();
    PolicyProof {
        variant_rand,
        expiry_rand,
        cmm_opening_map,
    }
}

fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    R: Rng,
>(
    commitment_key: &PedersenKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    commitment_rands: &CommitmentsRandomness<C>,
    id_cred_sec: &P::ScalarField,
    prf_key: &prf::SecretKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::Signature<P>,
    t: &P::ScalarField,
    csprng: &mut R,
) -> com_eq_sig::ComEqSigProof<P, C> {
    let att_vec = &alist.alist;
    let n = att_vec.len() + 2; // CHECK

    let ps_sig::Signature(a, b) = blinded_sig;
    let (eval_pair, eval) = (b, P::G_2::one_point());
    let (g, h) = ((commitment_key.0)[0], commitment_key.1);
    let ps_sig::PublicKey(_gen1, _gen2, _, yxs, x) = ip_pub_key;
    assert!(yxs.len() >= n + 2);

    let (p_pair, p) = (a, x);

    let (q_pair, q) = (a, P::G_2::one_point());
    let q_sec = t;

    let mut gxs = Vec::with_capacity(n + 2);
    let mut gxs_sec = Vec::with_capacity(n + 2);
    gxs_sec.push(*id_cred_sec);
    gxs.push(yxs[0]);
    let prf_key_scalar = prf_key.0;
    gxs_sec.push(prf_key_scalar);
    gxs.push(yxs[1]);
    gxs_sec.push(C::scalar_from_u64(u64::from(alist.variant)).unwrap());
    gxs.push(yxs[2]);
    gxs_sec.push(C::scalar_from_u64(alist.expiry.timestamp() as u64).unwrap());
    gxs.push(yxs[3]);
    for i in 4..n+2 {
        gxs_sec.push(att_vec[i - 4].to_field_element());
        gxs.push(yxs[i]);
    }
    let challenge_prefix = [0; 32];

    let gxs_pair = a; // CHECK with Bassel

    let mut pedersen_rands = Vec::with_capacity(n + 2);
    pedersen_rands.push(commitment_rands.id_cred_sec_rand);
    pedersen_rands.push(commitment_rands.prf_rand);
    pedersen_rands.extend_from_slice(&commitment_rands.attributes_rand);

    let mut comm_vec = Vec::with_capacity(n + 2);
    comm_vec.push(commitments.cmm_id_cred_sec.0);
    comm_vec.push(commitments.cmm_prf.0);
    for v in commitments.cmm_attributes.iter() {
        comm_vec.push(v.0);
    }
    com_eq_sig::prove_com_eq_sig::<P, C, R>(
        &challenge_prefix,
        &((*eval_pair, eval), comm_vec),
        &((*p_pair, *p), (*q_pair, q), (*gxs_pair, gxs), (g, h)),
        &((*q_sec, gxs_sec), pedersen_rands),
        csprng,
    )
}

pub struct CommitmentsRandomness<C: Curve> {
    id_cred_sec_rand:  C::Scalar,
    prf_rand:          C::Scalar,
    cred_counter_rand: C::Scalar,
    // variant_rand     : C::Scalar,
    // expirty_rand     : C::Scalar,
    attributes_rand: Vec<C::Scalar>,
}

fn compute_commitments<C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    prf_key: &prf::SecretKey<C>,
    id_cred_sec: &C::Scalar,
    cred_counter: u8,
    csprng: &mut R,
) -> (CredDeploymentCommitments<C>, CommitmentsRandomness<C>) {
    let (cmm_id_cred_sec, id_cred_sec_rand) =
        commitment_key.commit(&Value(vec![*id_cred_sec]), csprng);
    let prf::SecretKey(prf_scalar) = prf_key;
    let (cmm_prf, prf_rand) = commitment_key.commit(&Value(vec![*prf_scalar]), csprng);
    let variant_scalar = C::scalar_from_u64(u64::from(alist.variant)).unwrap();
    let (cmm_variant, variant_rand) = commitment_key.commit(&Value(vec![variant_scalar]), csprng);
    let expiry_scalar = C::scalar_from_u64(alist.expiry.timestamp() as u64).unwrap();
    let (cmm_expiry, expiry_rand) = commitment_key.commit(&Value(vec![expiry_scalar]), csprng);
    let cred_counter_scalar = C::scalar_from_u64(u64::from(cred_counter)).unwrap();
    let (cmm_cred_counter, cred_counter_rand) =
        commitment_key.commit(&Value(vec![cred_counter_scalar]), csprng);
    let att_vec = &alist.alist;
    let n = att_vec.len();
    let mut cmm_attributes = Vec::with_capacity(n + 2);
    let mut attributes_rand = Vec::with_capacity(n + 2);
    cmm_attributes.push(cmm_variant);
    attributes_rand.push(variant_rand);
    cmm_attributes.push(cmm_expiry);
    attributes_rand.push(expiry_rand);
    for val in att_vec.iter() {
        let (cmm, rand) = commitment_key.commit(&Value(vec![val.to_field_element()]), csprng);
        cmm_attributes.push(cmm);
        attributes_rand.push(rand);
    }
    let cdc = CredDeploymentCommitments {
        cmm_id_cred_sec,
        cmm_prf,
        cmm_cred_counter,
        cmm_attributes,
    };

    let cr = CommitmentsRandomness {
        id_cred_sec_rand,
        prf_rand,
        cred_counter_rand,
        attributes_rand,
    };

    (cdc, cr)
}

fn compute_pok_reg_id<C: Curve, R: Rng>(
    on_chain_commitment_key: &PedersenKey<C>,
    prf_key: prf::SecretKey<C>,
    cmm_prf: &Commitment<C>,
    prf_rand: C::Scalar,
    cred_counter: u8,
    cmm_cred_counter: &Commitment<C>,
    cred_counter_rand: C::Scalar,
    reg_id_exponent: C::Scalar,
    reg_id: C,
    csprng: &mut R,
) -> com_mult::ComMultProof<C> {
    // coefficients of the protocol derived from the pedersen key
    let g = on_chain_commitment_key.0[0];
    let h = on_chain_commitment_key.1;

    let coeff = [g, h];

    // commitments are the public values.
    let public = [cmm_prf.0.plus_point(&cmm_cred_counter.0), reg_id, g];
    // finally the secret keys are derived from actual commited values
    // and the randomness.

    let mut k = prf_key.0;
    // FIXME: Handle the error case (which cannot happen for the current curve, but
    // in general ...)
    k.add_assign(&C::scalar_from_u64(u64::from(cred_counter)).unwrap());
    let mut rand_1 = prf_rand;
    rand_1.add_assign(&cred_counter_rand);
    let s1 = (k, rand_1);
    // reg_id is the commitment to reg_id_exponent with randomness 0
    let s2 = (reg_id_exponent, C::Scalar::zero());
    // the right-hand side of the equation is commitment to 1 with randomness 0
    let s3 = (C::Scalar::one(), C::Scalar::zero());

    let secret = [s1, s2, s3];

    let challenge_prefix = [0; 32]; // FIXME
    com_mult::prove_com_mult(csprng, &challenge_prefix, &public, &secret, &coeff)
}

fn compute_pok_id_cred_pub<P: Pairing, C: Curve<Scalar = P::ScalarField>, R: Rng>(
    ip_info: &IpInfo<P, C>,
    global_context: &GlobalContext<C>,
    id_cred_sec: &C::Scalar,
    id_cred_pub_enc: &Cipher<C>,
    id_cred_pub_rand: &C::Scalar,
    cmm_id_cred_sec: &Commitment<C>,
    id_cred_sec_rand: &C::Scalar,
    csprng: &mut R,
) -> com_enc_eq::ComEncEqProof<C> {
    // FIXME
    let challenge_prefix = [0; 32];
    let public = (id_cred_pub_enc.0, id_cred_pub_enc.1, cmm_id_cred_sec.0);
    // FIXME: The one_point needs to be a parameter.
    let ar_info = &ip_info.ar_info;
    let cmm_key = &global_context.on_chain_commitment_key;
    let base = (
        ar_info.ar_elgamal_generator,
        ar_info.ar_public_key.0,
        cmm_key.0[0],
        cmm_key.1,
    );
    let secret = (*id_cred_pub_rand, *id_cred_sec, *id_cred_sec_rand);

    com_enc_eq::prove_com_enc_eq::<C, R>(csprng, &challenge_prefix, &public, &secret, &base)
}
