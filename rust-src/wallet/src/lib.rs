#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_json;
use crypto_common::{types::Amount, *};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use either::Either::{Left, Right};
use encrypted_transfers::encrypt_amount_with_fixed_randomness;
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
    io::Cursor,
};

type ExampleCurve = G1;

/// Context for a transaction to send.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct TransferContext {
    pub from:   AccountAddress,
    pub to:     Option<AccountAddress>,
    pub expiry: u64,
    pub nonce:  u64,
    pub keys:   Map<String, Value>,
    pub energy: u64,
}

/// Sign the given hash. This method will try to recover secret keys from the
/// map and sign the given hash with each of the keys.
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
    let ctx_to = match ctx.to {
        Some(to) => to,
        None => bail!("to account should be present"),
    };

    // context with parameters
    let global_context: GlobalContext<ExampleCurve> = try_get(&v, "global")?;

    // plaintext amount to transfer
    let amount: Amount = try_get(&v, "amount")?;

    let sender_sk: elgamal::SecretKey<ExampleCurve> = try_get(&v, "senderSecretKey")?;

    let receiver_pk = try_get(&v, "receiverPublicKey")?;

    let input_amount = try_get(&v, "inputEncryptedAmount")?;

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
        payload_bytes.put(&ctx_to);
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

/// Given payload bytes, make a full transaction body (that is, transaction
/// minus the signature) together with its hash.
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
    (hasher.finalize(), body)
}

fn create_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;
    let ctx_to = match ctx.to {
        Some(to) => to,
        None => bail!("to account should be present"),
    };

    let amount: Amount = try_get(&v, "amount")?;

    let (hash, body) = {
        let mut payload = Vec::new();
        payload.put(&3u8); // transaction type is transfer
        payload.put(&ctx_to);
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

fn create_pub_to_sec_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ctx: TransferContext = from_value(v.clone())?;

    let amount: Amount = try_get(&v, "amount")?;

    // context with parameters
    let global_context: GlobalContext<ExampleCurve> = try_get(&v, "global")?;

    let (hash, body) = {
        let mut payload = Vec::new();
        payload.put(&17u8); // transaction type is public to secret transfer
        payload.put(&amount);

        // let payload_size: u32 = payload.len() as u32;
        // assert_eq!(payload_size, 41);

        make_transaction_bytes(&ctx, &payload)
    };

    let signatures = make_signatures(&ctx.keys, &hash)?;
    let encryption = encrypt_amount_with_fixed_randomness(&global_context, amount);
    let response = json!({
        "signatures": signatures,
        "transaction": hex::encode(&body),
        "addedSelfEncryptedAmount": encryption
    });

    Ok(to_string(&response)?)
}

/// Create a JSON encoding of a secret to public amount transaction.
fn create_sec_to_pub_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let ctx: TransferContext = from_value(v.clone())?;

    // context with parameters
    let global_context: GlobalContext<ExampleCurve> = try_get(&v, "global")?;

    // plaintext amount to transfer
    let amount: Amount = try_get(&v, "amount")?;

    let sender_sk: elgamal::SecretKey<ExampleCurve> = try_get(&v, "senderSecretKey")?;

    let input_amount = try_get(&v, "inputEncryptedAmount")?;

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let payload = encrypted_transfers::make_sec_to_pub_transfer_data(
        &global_context,
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
        payload_bytes.put(&18u8); // transaction type is secret to public transfer
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

fn check_account_address_aux(input: &str) -> bool { input.parse::<AccountAddress>().is_ok() }

/// Aggregate two encrypted amounts together into one.
fn combine_encrypted_amounts_aux(left: &str, right: &str) -> Fallible<String> {
    let left = from_str(left)?;
    let right = from_str(right)?;
    Ok(to_string(&encrypted_transfers::aggregate::<ExampleCurve>(
        &left, &right,
    ))?)
}

/// Try to extract a field with a given name from the JSON value.
fn try_get<A: serde::de::DeserializeOwned>(v: &Value, fname: &str) -> Fallible<A> {
    match v.get(fname) {
        Some(v) => Ok(from_value(v.clone())?),
        None => bail!(format!("Field {} not present, but should be.", fname)),
    }
}

fn create_id_request_and_private_data_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;
    let global_context: GlobalContext<ExampleCurve> = try_get(&v, "global")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ExampleCurve>> = try_get(&v, "arsInfos")?;

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
        "idObjectRequest": Versioned::new(VERSION_0, pio),
        "privateIdObjectData": Versioned::new(VERSION_0, id_use_data),
    });

    Ok(to_string(&response)?)
}

fn create_credential_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let ip_info: IpInfo<Bls12> = try_get(&v, "ipInfo")?;

    let ars_infos: BTreeMap<ArIdentity, ArInfo<ExampleCurve>> = try_get(&v, "arsInfos")?;

    let global_context: GlobalContext<ExampleCurve> = try_get(&v, "global")?;

    let id_object: IdentityObject<Bls12, ExampleCurve, AttributeKind> =
        try_get(&v, "identityObject")?;

    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = try_get(&v, "privateIdObjectData")?;

    let tags: Vec<AttributeTag> = try_get(&v, "revealedAttributes")?;

    let acc_num: u8 = try_get(&v, "accountNumber")?;

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
        "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
        "accountAddress": address,
    });
    Ok(to_string(&response)?)
}

/// Embed the precomputed table for decryption.
/// It is unfortunate that this is pure bytes, but not enough of data is marked
/// as const, and in any case a HashMap relies on an allocator, so will never be
/// const.
static TABLE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/table_bytes.bin"));

fn decrypt_encrypted_amount_aux(input: &str) -> Fallible<Amount> {
    let v: Value = from_str(input)?;
    let encrypted_amount = try_get(&v, "encryptedAmount")?;
    let secret = try_get(&v, "encryptionSecretKey")?;

    let table = (&mut Cursor::new(TABLE_BYTES)).get()?;
    Ok(
        encrypted_transfers::decrypt_amount::<id::constants::ArCurve>(
            &table,
            &secret,
            &encrypted_amount,
        ),
    )
}

/// Set the flag to 0, and return a newly allocated string containing
/// the error message. The returned string is NUL terminated.
///
/// # Safety
/// This function does not check that the flag pointer is not null.
unsafe fn signal_error(flag: *mut u8, err_msg: String) -> *mut c_char {
    *flag = 0;
    CString::new(err_msg)
        .expect("Error message string should be non-zero and utf8.")
        .into_raw()
}

unsafe fn encode_response(response: Fallible<String>, success: *mut u8) -> *mut c_char {
    match response {
        Ok(s) => {
            let cstr: CString = {
                match CString::new(s) {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not encode response: {}", e))
                    }
                }
            };
            *success = 1;
            cstr.into_raw()
        }
        Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
    }
}

/// Try to get a normal string from a `*const c_char`.
///
/// This needs to be a macro due to early return.
macro_rules! get_string {
    ($input_ptr:expr, $success:expr) => {{
        if $input_ptr.is_null() {
            return signal_error($success, "Null pointer input.".to_owned());
        }
        match CStr::from_ptr($input_ptr).to_str() {
            Ok(s) => s,
            Err(e) => {
                return signal_error($success, format!("Could not decode input string: {}", e))
            }
        }
    }};
}

/// Make a wrapper for functions of the form
///
/// ```
///    f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char
/// ```
/// or
/// ```
///    f(input_ptr_1: *const c_char, input_ptr_2: *const c_char, success: *mut u8) -> *mut c_char
/// ```
macro_rules! make_wrapper {
    ($(#[$attr:meta])* => $f:ident -> $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(input_ptr: *const c_char, success: *mut u8) -> *mut c_char {
            let input_str = get_string!(input_ptr, success);
            let response = $call(input_str);
            encode_response(response, success)
        }
    };
    ($(#[$attr:meta])* => $f:ident --> $call:expr) => {
        $(#[$attr])*
        #[no_mangle]
        pub unsafe fn $f(input_ptr_1: *const c_char, input_ptr_2: *const c_char, success: *mut u8) -> *mut c_char {
            let input_str_1 = get_string!(input_ptr_1, success);
            let input_str_2 = get_string!(input_ptr_2, success);
            let response = $call(input_str_1, input_str_2);
            encode_response(response, success)
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
    => create_pub_to_sec_transfer_ext -> create_pub_to_sec_transfer_aux);

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
    => create_sec_to_pub_transfer_ext -> create_sec_to_pub_transfer_aux);

make_wrapper!(
    /// Take pointers to NUL-terminated UTF8-strings and return a NUL-terminated
    /// UTF8-encoded string. The returned string must be freed by the caller by
    /// calling the function 'free_response_string'. In case of failure the function
    /// returns an error message as the response, and sets the 'success' flag to 0.
    ///
    /// The input strings must contain base16 encoded encrypted amounts. If they can be
    /// decoded then the result is also a string of the same form, and the success flag is 1.
    /// If there is failure decoding input arguments the return value is a string
    /// describing the error.
    ///
    /// # Safety
    /// The input pointers must point to a null-terminated buffer, otherwise this
    /// function will fail in unspecified ways.
    => combine_encrypted_amounts_ext --> combine_encrypted_amounts_aux);

/// Take pointers to a NUL-terminated UTF8-string and return a u64.
///
/// In case of failure to decode the input the function will
/// set the `success` flag to `0`, and the return value should not be used.
/// If `success` is set to `1` the return value is the decryption of the input
/// amount.
///
/// The input string should encode a JSON object with two fields "global" and
/// "encryptedAmount".
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
#[no_mangle]
pub unsafe fn decrypt_encrypted_amount_ext(input_ptr: *const c_char, success: *mut u8) -> u64 {
    let input_str = if input_ptr.is_null() {
        *success = 0;
        return 0;
    } else {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => {
                *success = 0;
                return 0;
            }
        }
    };
    if let Ok(v) = decrypt_encrypted_amount_aux(input_str) {
        *success = 1;
        u64::from(v)
    } else {
        *success = 0;
        0
    }
}

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

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe fn free_response_string_ext(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// If genesis data identity providers are regenerated, then this needs to be
/// updated to correspond to the private key of identity-provider-0.json.
pub const IP_PRIVATE_KEY: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e4f791a70bdd528c23824cd1db8de55b89e807dcb757f0a929f3633dc87cfa55361813677fc79a67d8ec509ad0faa01d0a35bc0fb2542878b89397a51700b507b603a7e39cadcd970c561b0ed061fce1de479c47271721683064e5e4c5773c72f3a8cabac076ea893f6ae915bb24b6efee33d3beaa3d0788b9c0fb53ab574ce94467c9cda3a30740d254598611c3cc9804e39e64654f30a94ff45df41a94e58056c30ee46a95a66a95739269fc3b8db3eb01b2600385faa5791a16d22984c092a377417024eb4d03a164717241de73bc57fd83e8114a7cd3fd4491617ad985e435080973fa1a4e7fa750cc9c799847ab8add2e743f76874f425ecd1b08da9eee864c05b84899115a30b86d1fa196e4a5aae791ef7636c75017c5f52d0b127236b4502c82eede03d314e666d5ee8a14c24365ac0c56505b73a9a17048032ecc0285c3f12aec3ae00f150fea3bbdfb760307dbb16b5bf422a77faa847ee96b9b59631429bc4547e7d14c4870bd1b97c8e95f679b181b62bc97c435b1e8a74d7ac5b2f21c6e312ce51dda672886e0623849f88482cf71239db83c6775cd51819c67a6f2a7f8dfc47c3dce95204f3778f3f227474a5c70088b4e760364e8b4a6e5f27099472024b650301b0194b820c5bf1c7e14b250498ec8b1f2e194bc031ad887f5ebd327e482490847caf5301e379be4820c80f1340fe6eef2924605ffd654da666c4a260b5613d82216d15e90de7e62856d8e9627b14b6194c7f58969c68849202ae1770208080e5c2010bcbe23921be558e2d0d389afcc646f9fa8a7c19758871b6e7ba881d3f11913f75d5975df181907e075066857f2a6c9e29076ea8d4bd20161826a93ad55c25bd3d34f5921c800bd157133a3f33c19d0e7feb01b577bd7300c3f2394efad82ffb5061673020b130d0ee30ec780b7712062e59f938b0b34c42dae6f2ef0f631b6232736546b19e672498a80020422c276f4a2884690da950ede981f49e2ca79e9e3540a17b18ff0e82880151fc5476405a8978b17d1a6732e6726a644ad66198c59b05082e35beacc160955fde613fd3275acbf80606af4a9c22d38ca5f5e2116e5c674f6aa1fc9ffae17df2e20b533d1bd361b7a93ba326d6d1367dd579ff897eb644486d47686e98443c9de9f16bc9526ee9ad2d4743449ab4228ac9e159a35affebeeabf2db7f8898e4d6fc0efbb326eb9266f88e4a6cf9d03ffee9ae490ee868f417f24c659ef290f1e4f2ceba546afde3b97388423440701f55d461ba739b0d5015076cc0cdba03a63e7891e189418dfff04535bb1eca0baa43115c3f1ce7c933fdf9ba97b84e7957e87672a1d8b44ca7ce334caa17eab204b9f42df0c1e7e040bea15f36af424a3b77ce1cc494931aba7da56271";

pub const IP_INFO: &str = r#"{
    "ipIdentity": 0,
    "ipDescription": {
      "name": "identity_provider-0",
      "url": "",
      "description": ""
    },
    "ipVerifyKey": "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001ea35299487b6e66d2bed67e7e02069154de49b6c0920a0f76f7c57e94a9bc86336d1859c5495a563cd07b77423a3e16238c0e6bb4ea3d28f3d01c5a8ec8245d3baf50a617da75f4aa0107e37d63e256ca384cecfe5f50f038679706acc47da741b0a4ec2ee1e602c85b042c70a3041283ae4351a7621805a5be68d89e0171603bcf63f2f0e18e537223074151f435493785c6e0becedb8b8c88b60d03414fc3c06151d58a3566761490b2440f5af6463ba8756e111d1eb9887e58599f3cd4c2c1b81ad49132c62031db13f61caee43162ce66c2d08fa9f7bebe4c886636391506a6fcbe94f9e519ebf8c73ac89049833c807c505d81e441bbe69de368334440dae669c3d97b9e5f1c56edd412147af819a9679191c9567573cf4c3aeab3f48bf7818a95dffdf9d1a1fc60208a173acdaef8289c9a68a85873c05b485538d809328f47d2043da284d687275c19c1586a80ab6ade37675dfa240427c94a48cdce30da9eac8c5df165968d23c5dc99e158c3de92b69dc27d91109d1030fdf388f6f3979355de2e45b701a3cc504fc746d4872a6628b2c18355b3f17ae53cdd7908ca1d0dc4e3a30d15c643df9895f4b0d2f6900d168e4a66542c45bafbbaf94e18c4ad450e1163b8b8543274abc5136c956e9fa65e923fbed068512e4ff15771f88b8c81f2d51b799149b4c20276ae1e3d37e4d2f71b9e86f7a749fbeb226d24690252b769fdf81b853b990875d5cceed11ba9fbfb7f75347986fd1dcb6c332699c6ce0167555fef02e062eed49faac543bbb56d06cadd3211a3260f5a53f3fe6e4da6f4e8a574f1d9be53ff046166a316af57941da0c11b1f4ec2f0311f1634c9ba18e7868822d4842ef87b77403ddfd81dae532a232ad4acd0b19a6d7a023b89f3a79553b2c2cab41906e4138e0b0c8c41f0bfa15adc26eb0cae9ffe9de82d0d2da530a1364c11ae94fad1361a405c1fc7e58fb2259301a0de66d7637f6e95b8567e0c9ccc3aa751f36a8ff4997e36dea1984a3b39aa87a89c82af1a30051349a095f0c930c31449d989ddfe9fdbb039fc877537fb290027146d00df5610e3b11486915e51d8ab7284fcbe40a60b833a104cbb782836c2aa06debb9e845d98f3c006bedde9cc462a9a38b5a1dee943542eb1d1be5bb066e6b39601256c2f7de5a0c798862c7d6f4dd9aee7966f5f7e892664b0666e127a79fa8fc51dc6b94b1849a70b29106c0caadf0ac3a62b8a5f1a1af8f63c23285f6fcc7054cdac438a2e2f0badd1ab98545c3233e47ff3bdd234f39885eee752956e07c503db9a48dfcfa70ebcb6da0b493c70e76eb76483d3641046d562001b7101648515b1da0ad3502082e49052b1564b2cefdc404b7879a2d4bc2407359f6ae7effe84110ef4a3e5ee18f33dd96d59cd9417c47d5a10638fc782ae40f5c040f3f74d46a16262574a58716d019f1327e01cb2085f06e1a662b48a901fc3d52ee118e4747c67f7af7b19abb9f221c9258a9a77e312363c6bd94ff42df8b2f6d39d2709662009c16dfecc92a55adf544f8f480082d997a7913a898540c1dcd0c3e6329f8e144fb11d4d3e7c00316912f98205ab20ca49cd20c44d127aabf2e0eea31cf686d1598d3d0df1b7964ea2fbeefcf129caf7044aee09555e114c028a4c2a4f21f0483a28f3b7491014b47800ac0d2a8c95d0e37b10eb038f194cc220e57a70a8aa0baa14f9199bb49aac0c602dc9e2720e8c564ee546a75bceef37aaaec9a3cffe3e1a61b252e8865f6e6388241a2280d7a88b4b37423880f4930a784a0ee9d26cfe0462bf0436f2317c5c54ee1a14eefd2290821572e2b05b98a0b8287bcd6939ec6822d17cd8ef09dc703b3df3a339d469d05efa8a11ecd3f980f970968181a0c6eedab7663f85b940c79f6aa11d759290398a2457a5599b046c5fa64342ce7af417a8c2d9719d8dfd2115564c086c22ef8bb9536748a0f1a837b9867cedfa80dc0d65f484c0563dd3e18d3acac92ed1a9100eddeb1c7a974d661da9254c133bb7105f9c1f2a0000001ea455de8cbf245e72960383979a145c0ec7420c170b98a57adecb3f5d24c51ec43fe2bebb3a3a49fd7f35ba027188f2380dd8aa20239766a08e495343b818b440c44cca93096498901e0c706fc435afce35b7ce3c11a53cff7abdb753a2eeeaa2b848d755b7c03997376ffb5db4fa1f81e6b6ac8864e4ea73d983785dc077efc5513a60ad2c7824c0cacc6b0ad1c52e3403bb712026961809d70c94e3a6a569d804c989425bdc100b1c803c47604c5309f6f4a88262bb113e2f918ba40a73a536a39e6d6d2055e6547a7e2c64e2101b5bb2b9932a7c8afcacb069f93b0b7240d9b92a09fbc3da8dd91c7e135cd1e2acfd0a2f89f59a5669886b27d7db7273c798aac569acbd37badff857d74e97cab190dccddb7016e6daf805b8ed858b935dc7869176eb93a1d82e43b1ad8adf238095c71a74a3c51cfcb951cd0ec247303ae9f1fe6a5f8bce262276b2250e74d9271d1384a89ee2cd7b747f398759c4c16f0c5b76e9ade7b8722690138f7ee13f09ebce0ef0ff20d1245daafd472469057d838cf4aa0dfc3e446d01eac6bb58d81d02f659d1668aafae67c0e9971ac50cb01932a7d93db61f9aee9d6975e7e9f349dd0872ffff69317e715120d34ad4a3d725dcfe1931b97c8cbca3424285923a410732ed791522b4f3c3d60cb7bd706b8fd2881ab6fb419c2cd93b0f6f1761deddda30e680aa3928fb04bf041378c88de173b7a73e3bad292c9882c6da8aa2dd6f841935deb8eddbd8041524017bbf47111ec8cddf5cc94c1f8bf237ff0ef8a19b5d6b48442d886131c15e62351e290752e0ab378ff2b86389cdecd6c4a6f8b2cf19c58ad38b2ade0610301ac8d638e935f8896f27f6bb298459b1fe52671d95b6b90c79e571147ca277d195c9b2a031dded411ce1271f427e3809952c4c66e24c9ccc284310d1836e9528c96c0b6b7d3960a74737ee7c56d2b2c179d5da11565fd913708d91e7372eb4a9f394ed0ff51168f16a781f2e768f7ce4b32bce44868045112ac31095cb3fd9b4551e1dcf289523fb3ee720641ba6c6007013e416de5442a728dc50974f99d85e7ad1220162662f80f77b09ff9f0f7e916f68538835e31a9a5a09c37039dc112b40718f7d983d9f8258b9aebfb8cf9dcdcc0dde23c409c50da4e7ef0bd743d0552f099dd89f27c9edd61f555adfbf5280419b8c6b13e8ad6adea9133f7442d059baebd21d489a9f8bbc415fc479cfe8f3a2bdef19d4d8981abdbaf043d7fe528c16543ead96f03ef7847836d5b7c7abe2152d2d600ae02e156b48711f60ce5931339f44fa235e05c08fa5e97b27ab488e81e0ef78030b6b5c4fd82bf68accb9840600f5209024669170753cdf47eea28c5133030e112f260037dc9ac70bf6944aee2e548faa83e3f94c283031cc7862d8504c1c44f8948d10b51cc32f129b86addb608cae6419e0f5681bda8b2aa95cdd40910dc23140de21ade181605d9e08dcd2aa15bd52b12a87230953267768ef8fb998efbad6c4d57b8da7ff270ed09aad816793e855e8a319a4ad310c1e99820aea63495f8dd66108b1546db6eaab5989a7ed52875130c9a40664de62e821ea27a511eba9b9806b29d2aa2234f5c3374668caacb7fa539a93690c13d8a1dd56166b1e862007de475b0770f13fe4d7eb7ba0217d78baf4803722a9879595fca4b0e5ab5ec9ace42b17b084d286dbc527564e225e6890ebca4420724840fc9779a39704997ff2eee218903a07261b08c6b236bba1af09b69294f50b0290fee3cb328a5ced7e5ec4308e0d66ff8ab517cb9bba40e20766955f18f3a8d5d81a9f0fc3a46119b60c09b9179bc692155af110e7571a4946a5f334177874546e2a27113d387bb9ad9578ea4e07bb9e42d1df2026c9777afd1c6fc08e9250980944e88a6b51676895edac78ac49b1ab9cfcb3023a6717023e3bda352ae5975de8da99734e54b69947dfa6c30ae8dd98e763dd1144e8434cb3043584dafee32abb527b5bfe704d6a34a66f7eb1defa42a522b5b8ae935cb52fb6f32a93ac5f74e5f32e938cd5b283887bc5391eacf59b4ce04ca7d0c2782007fb36c64012b0cb3a3d8e2d2474002493996571057597207e57f72c15ceab3dc20c7559f1b3918b4bb21a4043ca215da11ac490a8bb6fd9788b1779f70d0828a15b387ab15185d375e814ef56684d9cfa6feafc18cc847207962b7824db51e1573c063ae11e9a6f016245ef93d5a582bbb0c8d81914f15fa786408e5fc32a6808b776a8efda52761803ee63210ef0070165abf423d3fce03216cab156688dbd7366f7baafe29ed64304c830cf0648804d901b7d65b2ac12b565ccb3ab222f8faf970094b133e183c33114b9a0aff0ab5bce178e092d24f9f666221e2b0092075fe78ff898e057453383416a4ab13ed4836d8f203e5ba36d92eb9e6c6990e245a52cb43ab023b106ea66dfa8c8a02b051f2bda61d718d01f4848c2ced2d4829fc087c6c0580696770ea80d7037bb7c608e86a6950eefd928567f15b6550d8f8fddb08018d9d15fbc037b0d44d16bbd3a46cdf156b7c9956e78a1102d6ba3260d0a7cac01b921d2f346e8f937f6b9846a9a58826616be256ff74b598df194f12efb28685e170c0fecd2209e78f66ecd6a97ee85970c408fb265789fd53b1d45409a39e8c63c6ca0cf38e5b9d1d59404bf4305151fb1def13aa19458fc4eb039cbc26da1ca9309d87dd5cb30d274d528437280a38effe3ceb578a5f232bc8ebc9760241f7e3f600d636875e47b6f71227dbf78b87e13fdc5c8a12d4ea9dae76dc3385834c2353cd3bdbf33952ca55842f89cbc3c269e425b85467ccfd2d8fcbcedb95c82a7a4d3802293ca8d2f95fc6ff783bedebbe4dd99bb15a207db52110878aa5249be6b07d614ec68c8f6bf8e2c167702041a0b4690596cbc8f69763137ee26966ab119978dc17977ec0eb09c8b222a30805aee995b6406aac288f5fcf2e116ce2e4593ed0cabbcb5d8dd1924def6fdbfdb416de72601c0ff4774e21fe571ec8c2257ae53b8e0119b3b46f0213e0e9ddd363106b110a9a9f2f6a312d289b104f4a40540be9f659cf92cbf442b0bfc310bff7a82a6f7db51f05fbe7949bbe41a5f1d4bb55f1057cc62fb53b4e2c4c1fc0d576ab9b5567a9128dc187f228ac76fce4d13437f080f3de0fd91f4b979b3d438db4b01fe88cd55567eb7f2e65135f6f02406a0adb4c940e1024206676c1f50d53e22d4e4c69da5e4c3c47971ca81f6777642a59468b2649db2ab7f298af8dbba28e3db99dbba69caebdb9f2c7b67512315020d36ab17d0fc4f18151b3916c8597bfd0bc744163186fa4d95f35ae7940d1fc5e2d0b8abd80fb5dca354886e72fc5c2d413edf0a01c21e48d5a1d78be321556aac672c6c488f240c5fd90afd677ac72ed7b63bf11002bd7455a8b578042f2cb11515f7dae59579c8b053de2a87e3dcf4022903a08d9e10dc6d590481a80a67b8f7909a30382eeb873edff545518d8be9e8d5780e1a687e064e7853644dd1570d8f4fd50e96e3ef5fc6cbc340e7294fe4ca2fa775a09d2940b13f6fbacc5707297a75c5724292c111645429bd962abd1e05c4c67d5812321872575a2a59726aeca86a469105a4d8f4ff8d2aa1937f93d4b4fc981c4124bed296b121b224e025fc904d37a0611e23bb863885c98dac8eb5d6078da5146c65013a2523f67b2169617f8a29cbcc9b876cd8b990cd17e053dc13efa10dc3aa3fc18b7ed42c58717b9ef70a093bf5ff58e58bb01ea54893d0fc210d0c27af7c725595830119547c1296878c092ab4731c16c21cfc6b0fab8e9e662d61734a9a333271e92703d7c696473883df1655b478dd2ee55cd4cd6deb4d11c24c18b191c4baef72dcfff558de9c5fa426af131194178745c48abfadfc32ef8393ec05e2b5d6fdc7fc22e08cba4c80b4d50ed08ab320ac656db11bb8e73ef805c674c6fbc30f15a4fc43970a48ab215332c262a3b8c8d2a1712ba78954e6091407803c23b52a9c3c63dc160c347b9079b340bca1f86365e1e5afb61f20186dfebc096c9bb48b14bf2a6b9fb2e7898a504b6ddd66bf0358ccd1c3501fa570ae6560609b630394abf64cedeb4e1c9501eb0a4a620ea1b5acff7ad5b5f998c1136f199b1e86d4bd0c00b43e7259b4882d08f688cb9345d2d9e02b7d59115191a71129897c1b19eb6b1d3a4b88a67cd9"
  }"#;

pub const ALIST: &str = r#"{
      "chosenAttributes": {
        "countryOfResidence": "DE",
        "dob": "19800229",
        "firstName": "John",
        "idDocExpiresAt": "20291231",
        "idDocIssuedAt": "20200401",
        "idDocIssuer": "DK",
        "idDocNo": "1234567890",
        "idDocType": "1",
        "lastName": "Doe",
        "nationalIdNo": "DK123456789",
        "nationality": "DK",
        "sex": "1",
        "taxIdNo": "DE987654321"
      },
      "createdAt": "202008",
      "maxAccounts": 239,
      "validTo": "202111"
  }"#;

/// # This is temporary for testing until notabene puts up the server with the
/// new version of the idiss library.
fn id_object_response_aux(input_str: &str) -> Fallible<String> {
    let request: Versioned<PreIdentityObject<Bls12, ExampleCurve>> = {
        let v: Value = from_str(input_str)?;
        try_get(&v, "idObjectRequest")?
    };
    if request.version != VERSION_0 {
        bail!("Incorrect request version.")
    }
    let ip_private_key: ps_sig::SecretKey<Bls12> = base16_decode_string(IP_PRIVATE_KEY)?;

    let ip_info: IpInfo<Bls12> = from_str(IP_INFO)?;

    let alist: AttributeList<_, AttributeKind> = from_str(ALIST)?;

    let signature = match id::identity_provider::sign_identity_object(
        &request.value,
        &ip_info,
        &alist,
        &ip_private_key,
    ) {
        Ok(x) => x,
        Err(e) => bail!("{:?}", e),
    };

    let id = IdentityObject {
        pre_identity_object: request.value,
        alist,
        signature,
    };
    Ok(to_string(&Versioned::new(VERSION_0, id))
        .expect("JSON serialization of id objects should not fail."))
}

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
    => id_object_response_ext -> id_object_response_aux);
