use crate::types::*;

use curve_arithmetic::{Curve, Pairing};
use pairing::Field;
use dodis_yampolskiy_prf::secret as prf;
use pedersen_scheme::value as pedersen;
use pedersen_scheme::commitment::Commitment; 
use pedersen_scheme::key::CommitmentKey;
use elgamal::message::Message as ElgamalMessage;
use ed25519_dalek as acc_sig_scheme;
use ps_sig;
use rand::*;
use sigma_protocols::{com_eq, com_enc_eq, com_eq_different_groups, dlog};

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
) -> (PreIdentityObject<P, C, AttributeType>, SigRetrievalRandomness<P>)
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
        ar_name:  context.ip_info.ar_info.ar_name.clone(),
        prf_key_enc : prf_key_enc,
        //id_cred_pub_enc: id_cred_pub_enc,
    };
    let alist = aci.attributes.clone();

    let id_cred_sec = aci.acc_holder_info.id_cred.id_cred_sec;
    let sc_ck = &context.commitment_key_sc;
    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(&pedersen::Value(vec![id_cred_sec]), &mut csprng);
    let pok_sc = {
        let Commitment(cmm_sc_point) = cmm_sc;
        let CommitmentKey(sc_ck_1, sc_ck_2) = sc_ck;
        com_eq::prove_com_eq(&[], &(vec![cmm_sc_point] , id_cred_pub_ip), &(sc_ck_1[0], *sc_ck_2, vec![context.dlog_base]), &(vec![cmm_sc_rand], vec![id_cred_sec]), &mut csprng)    
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
            (context.commitment_key_prf.0[0], context.commitment_key_prf.1),
            (context.commitment_key_ar.0[0], context.commitment_key_ar.1),
        );
        com_eq_different_groups::prove_com_eq_diff_grps(&mut csprng, &[], &public, &secret, &coeff)
    };
    let prio =PreIdentityObject {
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

/*
pub fn generate_cdi<
      P: Pairing,
      AttributeType: Attribute<C::Scalar>,
      C: Curve<Scalar = P::ScalarField>,
  >(
      context: &Context<P, C>,
      global_context: &GlobalContext<C>,

      aci: &AccCredentialInfo<P, C, AttributeType>,
      prio: &PreIdentityObject<P, C, AttributeType>,
      cred_counter: u8,
      ip_sig: &ps_sig::Signature<P>,
      policy: &Policy<C>,
      acc_pub_key: &acc_sig_scheme::PublicKey,
  ) -> CredDeploymentInfo<P, C>
  where
      AttributeType: Clone, {
          let alist = prio.alist;
          let prf_key = aci.prf_key;
          let id_cred_sec = aci.acc_holder_info.acc_cred.id_cred_sec;
          let reg_id = aci.prf_key.prf(cred_counter);
          let id_cred_pub_enc = context
          .ip_info
          .ar_info
          .ar_public_key
          .encrypt(&mut csprng, &ElgamalMessage::<C>(id_cred_pub));
          let ar_data = prio.ip_ar_data;
          let ip_pub_key = context.ip_info.ip_verify_key;
          
          let ar_data = ChainArData{
              ar_name: prio.ip_ar_data.ar_name,
              prf_key_enc : prio.ip_ar_data.prf_key_enc,
              id_cred_pub_enc : id_cred_pub_enc 
          };

          let mut csprng = thread_rng(); 
          let retrieved_sig = ps_sig::retriev_sig(&ip_sig, &id_cred_sec);
          let (blinded_sig, r, t) = ps_sig::blind_sig(&retrived_sig, &mut csprng);

          let (commitments, commitments_rands) = compute_commitments<C>(&global_context.on_chain_commitment_key, &alist, &prf_key, &id_cred_sec, &cred_counter: u8, &mut csprng);
          let pok_prf = compute_pok_prf(&prf_key, &commitments.cmm_prf, &commitment_rands.prf_rand);
          let pok_reg_id = compute_pok_reg_id(&global_context.on_chain_commitment_key, &prf_key, &commitments.cmm_prf, &commitment_rands.prf_rand, cred_counter, &commitments.cmm_cred_counter, &commitments_rands.cred_counter_rand,  &reg_id);
          let pok_sig   = compute_pok_sig(&global_context.on_chain_commitment_key, &commitments, &commitments_rand, &id_cred_sec, &prf_key, &alist,  &ip_pub_key, &blinded_sig, &t); 
          let cdp = CredDeploymentProofs{
              proof_prf : pok_prf,
              proof_ip_sig: pok_sig,
              proof_reg_id: pok_reg_id,
          }

          CredentialDeploymentInfo{
              reg_id  : reg_id,
              sig     : ip_sig.clone(),
              ar_data : ar_data,
              ip_identity: context.ip_info.ip_identity,
              policy : policy.clone(),
              acc_pub_key: acc_pub_key.clone(),
              commitments: commitmens,
              proofs : cdp,

          }

}

fn compute_pok_sig<P:Pairing, C:Curve<Scalar=P::ScalarField>, AttributeType::Attributes<C::Scalar>> (commitment_key: &PedersenKey<C>, commitments: &CredDeploymentCommitments, commitments_rand: &commitmentsRandomness, id_cred_sec: &P::ScalarField, prf_key: &prf::SecretKey<P::Scalar>, alist: &AttributeList<C::Scalar, AttributeType>, ip_pub_key: &ps_sig::PublicKey, blinded_sig: &ps_sig::Signature<P>, t: &P::ScalarField) -> ComEqSigProof<P>{
    let att_vec = alist.alist;
    let n = att_vec.len();

    let (a, b) = blinded_sig;
    let (eval_pair, eval) = (b, P::G_2::one_point());
    let (g,h) = ((commitment_key.0)[0], commitment_key.1);
    let ps_sig::PublicKey (_, yxs, x) = ip_pub_key; 
    assert!(yxs.len()>= n + 2);

    let (p_pair, p) = (a, x); 

    let (q_pair, q) = (a, P::G_2::one_point());
    let q_sec = t;

    let gxs = Vec::with_capacity(n+2); 
    let gxs_sec = Vec::with_capacity(n+2);
    gxs_sec.push(id_cred_sec);
    gxs.push(yxs[0]);
    let prf_key_scalar = prf_key.0;
    gxs_sec.push(pr_key_scalar);
    gxs.push(yxs[1]);
    for i in 2..n {
        gxs_sec.push(att_vec[i-2]);
        gxs.push(yxs[i]);
    }
    let 


     
}


pub struct CommitmentsRandomness<C:Curve>{
    id_cred_sec_rand : C::Scalar, 
    prf_rand    : C::Scalar,
    cred_counter_rand   : C::Scalar
    //variant_rand     : C::Scalar,
    //expirty_rand     : C::Scalar,
    attributes_rand     : Vec<C::Scalar>,
}

fn compute_commitments<C:Curve, AttributeType:Attribute<C::Scalar>, R:Rng>(commitment_key: &PedersenKey<C>, alist: &AttributeList<C::Scalar, AttributeType>, prf_key: &prf::SecretKey<C>, id_cred_sec: &C::Scalar, cred_counter: u8, &mut csprng : R ) -> (CredDeploymentCommitments<C>, CommitmentRandomness<C>){
    (cmm_id_cred_sec, id_cred_sec_rand) = commitment_key.commit(Value(vec![id_cred_sec]), commitment_key, csprng);
    let SecretKey(prf_scalar) = prf_key;
    (cmm_prf, prf_rand) = commitment_key.commit(Value(vec![prf_scalar]), commitment_key, csprng);
    let variant_scalar = C::scalar_from_u64(alist.variant as u64);
    (cmm_variant, variant_rand) = commitment_key.commit(Value(vec![variant_scalar]), commitment_key, csprng);
    let expiry_scalar = C::scalar_from_u64(alist.expiry as u64);
    (cmm_expirty, expiry_rand) = commitment_key.commit(Value(vec![expiry_scalar]), commitment_key, csprng);
    let cred_counter_scalar = C::scalar_from_u64(cred_counter as u64);
    let (cmm_cred_counter, cred_counter_rand) = commitment_key.commit(Value(vec![cred_counter_scalar]), commitment_key, csprng);
    let att_vec = alist.alist;
    let n = att_vec.len();
    let mut cmm_attributes = Vec::with_capacity(n+2);
    let mut attributes_rand      = Vec::with_capacity(n+2);
    cmm_attributes.push(cmm_variant);
    attributes_rand.push(variant_rand); 
    cmm_attributes.push(cmm_expiry);
    attributes_rand.push(expiry_rand); 
    for val in att_vec.iter(){
        (cmm, rand) = commitment_key.commit(Value(vec![val]), commitment_key, csprng);
        cmm_attributes.push(cmm);
        attributes_rand.push(rand);
    }
    let cdc = CredDeploymentCommitments{
        cmm_id_cred_sec,
        cmm_prf,
        cmm_cred_counter,
        cmm_attributes,
    }

    let cr = CommitmentRandomness{
        id_cred_sec_rand,
        prf_rand,
        cred_counter_rand,
        attributes_rand,
    }

    (cdc, cr)

}

*/
