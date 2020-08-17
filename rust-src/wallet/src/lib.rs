#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_json;
use crypto_common::*;

use crypto_common::{base16_decode_string, base16_encode_string, c_char, Put};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use either::Either::{Left, Right};
use failure::Fallible;
use id::{
    account_holder::{create_credential, generate_pio},
    ffi::AttributeKind,
    secret_sharing::Threshold,
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use rand::thread_rng;
use serde_json::{from_str, from_value, to_string, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    cmp::max,
    collections::BTreeMap,
    convert::TryInto,
    ffi::{CStr, CString},
};

type ExampleCurve = G1;

/// Context for a transaction to send.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransferContext {
    pub from:   AccountAddress,
    pub to:     AccountAddress,
    pub expiry: u64,
    pub nonce:  u64,
    pub keys:   Map<String, Value>,
    pub energy: u64, // FIXME: This was added, needs to be updated.
}

fn make_signatures<H: AsRef<[u8]>>(
    keys: &Map<String, Value>,
    hash: &H,
) -> Fallible<BTreeMap<u8, String>> {
    let mut out = BTreeMap::new();
    for (key_index_str, value) in keys.iter() {
        let key_index = key_index_str.parse::<u8>()?;
        match value.as_object() {
            None => bail!("Malformed keys."),
            Some(value) => {
                let public = match value.get("verifyKey").and_then(Value::as_str) {
                    None => bail!("Malformed keys: missing verifyKey."),
                    Some(x) => base16_decode_string(&x)?,
                };
                let secret = match value.get("signKey").and_then(Value::as_str) {
                    None => bail!("Malformed keys: missing signKey."),
                    Some(x) => base16_decode_string(&x)?,
                };
                out.insert(
                    key_index,
                    base16_encode_string(&ed25519::Keypair { secret, public }.sign(hash.as_ref())),
                );
            }
        }
    }
    Ok(out)
}

/// Create a JSON encoding of an encrypted transfer transaction.
fn create_encrypted_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let ctx: TransferContext = from_value(v.clone())?;

    // context with parameters
    let global_context: GlobalContext<ExampleCurve> = {
        match v.get("global") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'global' not present, but should be."),
        }
    };

    // plaintext amount to transfer
    let amount: u64 = {
        match v.get("amount") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'amount' not present, but should be."),
        }
    };

    let sender_sk: elgamal::SecretKey<ExampleCurve> = {
        match v.get("senderSecretKey") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'senderSecretKey' not present, but should be."),
        }
    };

    let receiver_pk = {
        match v.get("receiverPublicKey") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'receiverPublicKey' not present, but should be."),
        }
    };

    let input_amount = {
        match v.get("inputEncryptedAmount") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'inputEncryptedAmount' not present, but should be."),
        }
    };

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let payload = encrypted_transfers::make_transfer_data(
        &global_context,
        &receiver_pk,
        &sender_sk,
        &input_amount,
        amount,
        &mut csprng,
    );
    let payload = match payload {
        Some(payload) => payload,
        None => bail!("Could not produce payload."),
    };

    let (hash, body) = {
        let mut payload_bytes = Vec::new();
        payload_bytes.put(&16u8); // transaction type is encrypted transfer
        payload_bytes.put(&ctx.to);
        payload_bytes.extend_from_slice(&to_bytes(&payload));

        make_transaction_bytes(&ctx, &payload_bytes)
    };

    let signatures = make_signatures(&ctx.keys, &hash)?;

    let response = json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
        "remaining": payload.remaining_amount,
    });

    Ok(to_string(&response)?)
}

/// Given payload bytes, make a full transaction (minus the signature) together
/// with its hash.
fn make_transaction_bytes(
    ctx: &TransferContext,
    payload_bytes: &[u8],
) -> (impl AsRef<[u8]>, Vec<u8>) {
    let payload_size: u32 = payload_bytes.len() as u32;
    let mut body = Vec::new();
    // this needs to match with what is in Transactions.hs
    body.put(&ctx.from);
    body.put(&ctx.nonce);
    body.put(&ctx.energy);
    body.put(&payload_size);
    body.put(&ctx.expiry);
    body.extend_from_slice(payload_bytes);

    let hasher = Sha256::new().chain(&body);
    (hasher.result(), body)
}

fn create_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;

    let amount: u64 = {
        match v.get("amount") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'amount' not present, but should be."),
        }
    };

    let (hash, body) = {
        let mut payload = Vec::new();
        payload.put(&3u8); // transaction type is transfer
        payload.put(&ctx.to);
        payload.put(&amount);

        let payload_size: u32 = payload.len() as u32;
        assert_eq!(payload_size, 41);

        make_transaction_bytes(&ctx, &payload)
    };

    let signatures = make_signatures(&ctx.keys, &hash)?;

    let response = json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
    });

    Ok(to_string(&response)?)
}

fn check_account_address_aux(input: &str) -> bool { input.parse::<AccountAddress>().is_ok() }

fn create_id_request_and_private_data_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ip_info: IpInfo<Bls12> = {
        match v.get("ipInfo") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'ipInfo' not present, but should be."),
        }
    };

    let global_context: GlobalContext<ExampleCurve> = {
        match v.get("global") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'global' not present, but should be."),
        }
    };

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ExampleCurve>> = {
        match v.get("arsInfos") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'arsInfos' not present, but should be."),
        }
    };

    // FIXME: IP defined threshold
    let threshold = {
        let l = ars_infos.len();
        ensure!(l > 0, "ArInfos should have at least 1 anonymity revoker.");
        Threshold(max((l - 1).try_into().unwrap_or(255), 1))
    };

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let chi = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    // Choice of anonymity revokers, all of them in this implementation.
    let context = IPContext::new(&ip_info, &ars_infos, &global_context);
    let (pio, randomness) = {
        match generate_pio(&context, threshold, &aci) {
            Some(x) => x,
            None => bail!("Generating the pre-identity object failed."),
        }
    };

    let id_use_data = IdObjectUseData { aci, randomness };

    let response = json!({
        "idObjectRequest": Versioned::new(Version::from(0u32), pio),
        "privateIdObjectData": Versioned::new(Version::from(0u32), id_use_data),
    });

    Ok(to_string(&response)?)
}

fn create_credential_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let ip_info: IpInfo<Bls12> = {
        match v.get("ipInfo") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'ipInfo' not present, but should be."),
        }
    };

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ExampleCurve>> = {
        match v.get("arsInfos") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'arsInfos' not present, but should be."),
        }
    };

    let global_context: GlobalContext<ExampleCurve> = {
        match v.get("global") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'global' not present, but should be."),
        }
    };

    let id_object: IdentityObject<Bls12, ExampleCurve, AttributeKind> =
        match v.get("identityObject") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'identityObject' not present, but should be."),
        };

    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = match v.get("privateIdObjectData") {
        Some(v) => from_value(v.clone())?,
        None => bail!("Field 'privateIdObjectData' not present, but should be."),
    };

    let tags: Vec<AttributeTag> = match v.get("revealedAttributes") {
        Some(v) => from_value(v.clone())?,
        None => vec![],
    };

    let acc_num: u8 = match v.get("accountNumber") {
        Some(v) => from_value(v.clone())?,
        None => bail!("Account number must be present."),
    };

    // if account data is present then use it, otherwise generate new.
    let acc_data = {
        if let Some(acc_data) = v.get("accountData") {
            match from_value(acc_data.clone()) {
                Ok(acc_data) => acc_data,
                Err(e) => bail!("Cannot decode accountData {}", e),
            }
        } else {
            let mut keys = std::collections::BTreeMap::new();
            let mut csprng = thread_rng();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));

            AccountData {
                keys,
                existing: Left(SignatureThreshold(1)),
            }
        }
    };

    let mut policy_vec = std::collections::BTreeMap::new();
    for tag in tags {
        if let Some(att) = id_object.alist.alist.get(&tag) {
            if policy_vec.insert(tag, att.clone()).is_some() {
                bail!("Cannot reveal an attribute more than once.")
            }
        } else {
            bail!("Cannot reveal an attribute which is not part of the attribute list.")
        }
    }

    let policy = Policy {
        valid_to: id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec,
        _phantom: Default::default(),
    };

    let context = IPContext::new(&ip_info, &ars_infos, &global_context);

    let cdi = create_credential(
        context,
        &id_object,
        &id_use_data,
        acc_num,
        policy,
        &acc_data,
    )?;

    let address = match acc_data.existing {
        Left(_) => AccountAddress::new(&cdi.values.reg_id),
        Right(addr) => addr,
    };

    // unwrap is safe here since we've generated the credential already, and that
    // does the same computation.
    let enc_key = id_use_data.aci.prf_key.prf_exponent(acc_num).unwrap();
    let secret_key = elgamal::SecretKey {
        generator: *global_context.elgamal_generator(),
        scalar:    enc_key,
    };

    let response = json!({
        "credential": Versioned::new(Version::from(0u32), cdi),
        "accountData": acc_data,
        "encryptionSecretKey": secret_key,
        "accountAddress": address,
    });
    Ok(to_string(&response)?)
}

/// Set the flag to 0, and return a newly allocated string containing
/// the error message.
///
/// # Safety
/// This function does not check that the flag pointer is not null.
unsafe fn signal_error(flag: *mut u8, err_msg: String) -> *mut c_char {
    *flag = 0;
    CString::new(err_msg)
        .expect("Error message string should be non-zero and utf8.")
        .into_raw()
}

/// Make a wrapper for a function of the form
///
/// ```
///    f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char
/// ```
macro_rules! make_wrapper {
    ($(#[$attr:meta])* => $f:ident -> $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char {
            if input_ptr.is_null() {
                return signal_error(success, "Null pointer input.".to_owned());
            }
            let input_str = {
                match CStr::from_ptr(input_ptr).to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not decode JSON: {}", e))
                    }
                }
            };
            let response = $call(input_str);
            match response {
                Ok(s) => {
                    let cstr: CString = {
                        match CString::new(s) {
                            Ok(s) => s,
                            Err(e) => {
                                return signal_error(
                                    success,
                                    format!("Could not encode response: {}", e),
                                )
                            }
                        }
                    };
                    *success = 1;
                    cstr.into_raw()
                }
                Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
            }
        }
    };
}

// Make external wrappers that can be used in android and iOS libraries.
make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_transfer_ext -> create_transfer_aux);
make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The input string should contain the JSON payload of an
    /// attribute list, name of id object, and the identity provider public
    /// information.
    ///
    /// The return value contains a JSON object with two values, one is
    /// the request for the identity object that is public, and the other is the
    /// private keys and other secret values that must be kept by the user.
    /// These secret values will be needed later to use the identity object.
    ///
    /// The returned string must be freed by the caller by calling the function
    /// 'free_response_string'. In case of failure the function returns an error
    /// message as the response, and sets the 'success' flag to 0.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_id_request_and_private_data_ext -> create_id_request_and_private_data_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_credential_ext -> create_credential_aux);

make_wrapper!(
    /// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// See rust-bins/wallet-notes/README.md for the description of input and output
    /// formats for encrypted transfers.
    ///
    /// # Safety
    /// The input pointer must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => create_encrypted_transfer_ext -> create_encrypted_transfer_aux);

#[no_mangle]
/// # Safety
/// The input must be NUL-terminated.
pub unsafe fn check_account_address_ext(input_ptr: *const c_char) -> u8 {
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    if check_account_address_aux(input_str) {
        1
    } else {
        0
    }
}

/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe fn free_response_string_ext(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
