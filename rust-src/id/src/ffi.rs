#![cfg(feature = "ffi")]

use crate::{
    chain::{self, CdiVerificationError},
    constants::*,
    types::*,
};
use crypto_common::{size_t, types::TransactionTime, *};
use either::Either::{Left, Right};
use ffi_helpers::*;
use pairing::bls12_381::{Bls12, G1};
use pedersen_scheme::CommitmentKey as PedersenKey;
use rand::thread_rng;
use std::{collections::BTreeMap, convert::TryInto, io::Cursor};

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn verify_initial_cdi_ffi(
    ip_info_ptr: *const IpInfo<Bls12>,
    // acc_keys_ptr: *const u8,
    // acc_keys_len: size_t,
    initial_cdi_ptr: *const u8,
    initial_cdi_len: size_t,
    expiry: u64,
) -> i32 {
    let cdi_bytes = slice_from_c_bytes!(initial_cdi_ptr, initial_cdi_len as usize);
    match InitialCredentialDeploymentInfo::<G1, AttributeKind>::deserial(&mut Cursor::new(
        &cdi_bytes,
    )) {
        Err(_) => -3,
        Ok(cdi) => {
            match chain::verify_initial_cdi::<Bls12, G1, AttributeKind>(
                from_ptr!(ip_info_ptr),
                &cdi,
                TransactionTime { seconds: expiry },
            ) {
                Ok(()) => 1, // verification succeeded
                Err(_) => -2, /* Only signature verification can fail, so just map all failures
                               * to one. */
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn verify_cdi_ffi(
    gc_ptr: *const GlobalContext<G1>,
    ip_info_ptr: *const IpInfo<Bls12>,
    ars_infos_ptr: *const *mut ArInfo<G1>,
    ars_infos_len: size_t,
    cdi_ptr: *const u8,
    cdi_len: size_t,
    addr_ptr: *const u8, // pointer to an account address, or null, 32 bytes
    expiry: u64,         // if addr_ptr is null this is used
) -> i32 {
    if gc_ptr.is_null() {
        return -9;
    }
    if ip_info_ptr.is_null() {
        return -10;
    }

    let new_or_existing = if addr_ptr.is_null() {
        Left(TransactionTime { seconds: expiry })
    } else if let Ok(bytes) = slice_from_c_bytes!(addr_ptr, ACCOUNT_ADDRESS_SIZE).try_into() {
        Right(AccountAddress(bytes))
    } else {
        return -14;
    };

    let cdi_bytes = slice_from_c_bytes!(cdi_ptr, cdi_len as usize);
    match CredentialDeploymentInfo::<Bls12, G1, AttributeKind>::deserial(&mut Cursor::new(
        &cdi_bytes,
    )) {
        Err(_) => -12,
        Ok(cdi) => {
            let mut ars_infos = BTreeMap::new();
            let ars: &[*mut ArInfo<G1>] =
                slice_from_c_bytes!(ars_infos_ptr, ars_infos_len as usize);
            for &ptr in ars {
                let ar_info: &ArInfo<G1> = from_ptr!(ptr);
                if ars_infos
                    .insert(ar_info.ar_identity, ar_info.ar_public_key)
                    .is_some()
                {
                    // There should be no duplicate ar_ids in the list. The caller should ensure
                    // that.
                    return -13;
                }
            }
            match chain::verify_cdi::<Bls12, G1, AttributeKind, ArPublicKey<G1>>(
                from_ptr!(gc_ptr),
                from_ptr!(ip_info_ptr),
                &ars_infos,
                &cdi,
                &new_or_existing,
            ) {
                Ok(()) => 1, // verification succeeded
                Err(CdiVerificationError::RegId) => -1,
                Err(CdiVerificationError::IdCredPub) => -2,
                Err(CdiVerificationError::Signature) => -3,
                Err(CdiVerificationError::Dlog) => -4,
                Err(CdiVerificationError::Policy) => -5,
                Err(CdiVerificationError::Ar) => -6,
                Err(CdiVerificationError::AccountOwnership) => -7,
                Err(CdiVerificationError::Proof) => -8,
            }
        }
    }
}

macro_derive_from_bytes!(
    Box
    pedersen_key_from_bytes,
    PedersenKey<G1>
);
macro_derive_to_bytes!(Box pedersen_key_to_bytes, PedersenKey<G1>);
macro_free_ffi!(Box pedersen_key_free, PedersenKey<G1>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn pedersen_key_gen() -> *mut PedersenKey<G1> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(PedersenKey::generate(&mut csprng)))
}

macro_derive_from_bytes!(
    Box
    ps_sig_key_from_bytes,
    ps_sig::PublicKey<Bls12>
);
macro_derive_to_bytes!(Box ps_sig_key_to_bytes, ps_sig::PublicKey<Bls12>);
macro_free_ffi!(Box ps_sig_key_free, ps_sig::PublicKey<Bls12>);
macro_generate_commitment_key!(
    ps_sig_key_gen,
    ps_sig::PublicKey<Bls12>,
    ps_sig::PublicKey::arbitrary
);

// derive conversion methods for IpInfo to be used in Haskell.
macro_free_ffi!(Box ip_info_free, IpInfo<Bls12>);
macro_derive_from_bytes!(Box ip_info_from_bytes, IpInfo<Bls12>);
macro_derive_to_bytes!(Box ip_info_to_bytes, IpInfo<Bls12>);
macro_derive_from_json!(ip_info_from_json, IpInfo<Bls12>);
macro_derive_to_json!(ip_info_to_json, IpInfo<Bls12>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ip_info_ip_identity(ip_info_ptr: *const IpInfo<Bls12>) -> u32 {
    let ip_info = from_ptr!(ip_info_ptr);
    ip_info.ip_identity.0
}

// derive conversion methods for GlobalContext to be used in Haskell
macro_free_ffi!(Box global_context_free, GlobalContext<G1>);
macro_derive_from_bytes!(Box global_context_from_bytes, GlobalContext<G1>);
macro_derive_to_bytes!(Box global_context_to_bytes, GlobalContext<G1>);
macro_derive_from_json!(global_context_from_json, GlobalContext<G1>);
macro_derive_to_json!(global_context_to_json, GlobalContext<G1>);
#[no_mangle]
extern "C" fn dummy_generate_global_context() -> *mut GlobalContext<G1> {
    Box::into_raw(Box::new(GlobalContext::generate(String::from(
        "genesis_string",
    ))))
}

// derive conversion methods for ArInfo to be used in Haskell
macro_free_ffi!(Box ar_info_free, ArInfo<G1>);
macro_derive_from_bytes!(Box ar_info_from_bytes, ArInfo<G1>);
macro_derive_to_bytes!(Box ar_info_to_bytes, ArInfo<G1>);
macro_derive_from_json!(ar_info_from_json, ArInfo<G1>);
macro_derive_to_json!(ar_info_to_json, ArInfo<G1>);
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ar_info_ar_identity(ar_info_ptr: *const ArInfo<G1>) -> u32 {
    let ar_info = from_ptr!(ar_info_ptr);
    ar_info.ar_identity.into()
}

//  Return the name of the AR.
#[no_mangle]
pub extern "C" fn ar_info_name(input_ptr: *mut ArInfo<G1>, output_len: *mut size_t) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ar_description.name.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

//  Return the url of the AR.
#[no_mangle]
pub extern "C" fn ar_info_url(input_ptr: *mut ArInfo<G1>, output_len: *mut size_t) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ar_description.url.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

//  Return the description text of the AR.
#[no_mangle]
pub extern "C" fn ar_info_description(
    input_ptr: *mut ArInfo<G1>,
    output_len: *mut size_t,
) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ar_description.description.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

// Return the public key of the AR.
#[no_mangle]
pub extern "C" fn ar_info_public_key(
    input_ptr: *mut ArInfo<G1>,
    output_len: *mut size_t,
) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = to_bytes(&input.ar_public_key);
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

//  Return the name of the IP.
#[no_mangle]
pub extern "C" fn ip_info_name(input_ptr: *mut IpInfo<Bls12>, output_len: *mut size_t) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ip_description.name.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

//  Return the url of the IP.
#[no_mangle]
pub extern "C" fn ip_info_url(input_ptr: *mut IpInfo<Bls12>, output_len: *mut size_t) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ip_description.url.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

//  Return the description text of the ip.
#[no_mangle]
pub extern "C" fn ip_info_description(
    input_ptr: *mut IpInfo<Bls12>,
    output_len: *mut size_t,
) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = input.ip_description.description.as_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

// Return the verify key of the IP.
#[no_mangle]
pub extern "C" fn ip_info_verify_key(
    input_ptr: *mut IpInfo<Bls12>,
    output_len: *mut size_t,
) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = to_bytes(&input.ip_verify_key);
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

// Return the cdi verify key of the IP.
#[no_mangle]
pub extern "C" fn ip_info_cdi_verify_key(
    input_ptr: *mut IpInfo<Bls12>,
    output_len: *mut size_t,
) -> *mut u8 {
    let input = from_ptr!(input_ptr);
    let mut bytes = to_bytes(&input.ip_cdi_verify_key);
    unsafe { *output_len = bytes.len() as size_t }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        account_holder::*,
        constants::{ArCurve, BaseField},
        identity_provider::*,
        secret_sharing::Threshold,
        test::*,
    };
    use crypto_common::types::{KeyIndex, KeyPair};
    use dodis_yampolskiy_prf as prf;
    use std::{collections::btree_map::BTreeMap, convert::TryFrom};

    type ExampleAttributeList = AttributeList<BaseField, AttributeKind>;
    const EXPIRY: TransactionTime = TransactionTime {
        seconds: 111111111111111111,
    };

    #[test]
    fn test_pipeline() {
        let mut csprng = thread_rng();

        let ah_info = CredentialHolderInfo::<ArCurve> {
            id_cred: IdCredentials::generate(&mut csprng),
        };

        // Create IP
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ip_cdi_secret_key,
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);

        let prf_key = prf::SecretKey::generate(&mut csprng);

        let alist = {
            let mut alist = BTreeMap::new();
            alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
            alist.insert(AttributeTag::from(1u8), AttributeKind::from(313_123_333));
            alist
        };

        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key,
        };
        let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng);
        let id_use_data = IdObjectUseData { aci, randomness };
        let acc_data = InitialAccountData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };

        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        let alist = ExampleAttributeList {
            valid_to,
            created_at,
            max_accounts: 238,
            alist,
            _phantom: Default::default(),
        };

        let global_ctx = GlobalContext::<G1>::generate(String::from("genesis_string"));

        let (ars_infos, _ars_secret) = test_create_ars(
            &global_ctx.on_chain_commitment_key.g,
            num_ars - 1,
            &mut csprng,
        );

        let context = IpContext::new(&ip_info, &ars_infos, &global_ctx);
        let threshold = Threshold(num_ars - 1);
        let (pio, _) = generate_pio(&context, threshold, &id_use_data, &acc_data)
            .expect("Creating the credential should succeed.");

        let ver_ok = verify_credentials(
            &pio,
            context,
            &alist,
            EXPIRY,
            &ip_secret_key,
            &ip_cdi_secret_key,
        );

        // First test, check that we have a valid signature.
        assert!(ver_ok.is_ok());

        let (ip_sig, initial_cdi) = ver_ok.unwrap();

        let initial_cdi_bytes = to_bytes(&initial_cdi);
        let initial_cdi_bytes_len = initial_cdi_bytes.len() as size_t;
        let ip_info_ptr = Box::into_raw(Box::new(ip_info.clone()));
        let initial_cdi_check = verify_initial_cdi_ffi(
            ip_info_ptr,
            initial_cdi_bytes.as_ptr(),
            initial_cdi_bytes_len,
            EXPIRY.seconds,
        );
        assert_eq!(initial_cdi_check, 1);

        let policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(AttributeTag::from(0u8), AttributeKind::from(55));
                tree
            },
            _phantom: Default::default(),
        };

        let wrong_policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(AttributeTag::from(0u8), AttributeKind::from(5));
                tree
            },
            _phantom: Default::default(),
        };

        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));

        let acc_data = CredentialData {
            keys,
            threshold: SignatureThreshold(2),
        };

        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist,
            signature: ip_sig,
        };

        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            0,
            policy,
            &acc_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Should generate the credential successfully.");

        let (wrong_cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            0,
            wrong_policy,
            &acc_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Should generate the credential successfully.");

        let cdi_bytes = to_bytes(&cdi);
        let cdi_bytes_len = cdi_bytes.len() as size_t;

        let gc_ptr = Box::into_raw(Box::new(global_ctx));
        // let ip_info_ptr = Box::into_raw(Box::new(ip_info));
        let ars_infos_ptr = ars_infos
            .into_iter()
            .map(|(_, x)| Box::into_raw(Box::new(x)))
            .collect::<Vec<_>>();

        let cdi_check = verify_cdi_ffi(
            gc_ptr,
            ip_info_ptr,
            ars_infos_ptr.as_ptr(),
            ars_infos_ptr.len() as size_t,
            cdi_bytes.as_ptr(),
            cdi_bytes_len,
            std::ptr::null(),
            EXPIRY.seconds,
        );
        assert_eq!(cdi_check, 1);
        let wrong_cdi_bytes = to_bytes(&wrong_cdi);
        let wrong_cdi_bytes_len = wrong_cdi_bytes.len() as size_t;
        let wrong_cdi_check = verify_cdi_ffi(
            gc_ptr,
            ip_info_ptr,
            ars_infos_ptr.as_ptr(),
            ars_infos_ptr.len() as size_t,
            wrong_cdi_bytes.as_ptr(),
            wrong_cdi_bytes_len,
            std::ptr::null(),
            EXPIRY.seconds,
        );
        assert_ne!(wrong_cdi_check, 1);
    }
}
