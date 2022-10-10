use anyhow::Context;
use crypto_common::{base16_decode_string, types::TransactionTime, Versioned, VERSION_0};
use curve_arithmetic::*;
use id::{
    constants::{ArCurve, AttributeKind},
    identity_provider::{
        create_initial_cdi, sign_identity_object, sign_identity_object_v1,
        validate_id_recovery_request, validate_request as ip_validate_request,
        validate_request_v1 as ip_validate_request_v1,
    },
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
#[cfg(feature = "nodejs")]
use serde_json::ser::to_string;

type ExampleCurve = G1;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

// Parse an IpInfo taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_ip_info(bytes: &[u8]) -> anyhow::Result<IpInfo<Bls12>> {
    let v: Versioned<IpInfo<Bls12>> =
        serde_json::from_slice(bytes).context("Could not parse versioned ip info.")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect IpInfo version.");
    }
}

// Parse anonymity revokers taking into account the version.
// For now only version 0 is supported.

fn parse_exact_versioned_ars_infos(bytes: &[u8]) -> anyhow::Result<ArInfos<ArCurve>> {
    let v: Versioned<ArInfos<ArCurve>> =
        serde_json::from_slice(bytes).context("Could not parse versioned ar infos.")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect Ars version.");
    }
}

// Parse an GlobalContext taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_global_context(
    bytes: &[u8],
) -> anyhow::Result<GlobalContext<ExampleCurve>> {
    let v: Versioned<GlobalContext<ExampleCurve>> =
        serde_json::from_slice(bytes).context("Could not parse versioned global context.")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect Global context version.");
    }
}

fn parse_exact_versioned_pio_from_request(
    bytes: &[u8],
) -> anyhow::Result<PreIdentityObject<Bls12, ExampleCurve>> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .context("Could not parse JSON containing idObjectRequest.")?;
    let pre_id_obj_value = v
        .get("idObjectRequest")
        .context("Field 'idObjectRequest' not found")?;

    let v = serde_json::from_value::<Versioned<PreIdentityObject<_, _>>>(pre_id_obj_value.clone())
        .context("Could not parse preIdentityObject")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect version of pre identity object.");
    }
}

fn parse_exact_versioned_pio_from_request_v1(
    bytes: &[u8],
) -> anyhow::Result<PreIdentityObjectV1<Bls12, ExampleCurve>> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .context("Could not parse JSON containing idObjectRequest.")?;
    let pre_id_obj_value = v
        .get("idObjectRequest")
        .context("Field 'idObjectRequest' not found")?;

    let v =
        serde_json::from_value::<Versioned<PreIdentityObjectV1<_, _>>>(pre_id_obj_value.clone())
            .context("Could not parse preIdentityObject")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect version of pre identity object.");
    }
}

fn parse_exact_versioned_recovery_request(
    bytes: &[u8],
) -> anyhow::Result<IdRecoveryRequest<ExampleCurve>> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .context("Could not parse JSON containing idObjectRequest.")?;
    let pre_id_obj_value = v
        .get("idRecoveryRequest")
        .context("Field 'idObjectRequest' not found")?;

    let v = serde_json::from_value::<Versioned<IdRecoveryRequest<_>>>(pre_id_obj_value.clone())
        .context("Could not parse preIdentityObject")?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        anyhow::bail!("Incorrect version of pre identity object.");
    }
}

/// Validate a request
fn validate_request(
    global_context_bytes: &[u8],
    ip_info_bytes: &[u8],
    ars_infos_bytes: &[u8],
    request_bytes: &[u8],
) -> anyhow::Result<AccountAddress> {
    let global_context: GlobalContext<ExampleCurve> =
        parse_exact_versioned_global_context(global_context_bytes)?;
    let ip_info: IpInfo<Bls12> = parse_exact_versioned_ip_info(ip_info_bytes)?;
    let ars_infos: ArInfos<ArCurve> = parse_exact_versioned_ars_infos(ars_infos_bytes)?;
    let request: PreIdentityObject<Bls12, ExampleCurve> =
        parse_exact_versioned_pio_from_request(request_bytes)?;

    let context = IpContext {
        ip_info:        &ip_info,
        ars_infos:      &ars_infos.anonymity_revokers,
        global_context: &global_context,
    };
    let addr = account_address_from_registration_id(&request.pub_info_for_ip.reg_id);
    if let Err(e) = ip_validate_request(&request, context) {
        anyhow::bail!("Ip validation failed: {:?}", e);
    }
    Ok(addr)
}

/// Validate a version 1 request
fn validate_request_v1(
    global_context_bytes: &[u8],
    ip_info_bytes: &[u8],
    ars_infos_bytes: &[u8],
    request_bytes: &[u8],
) -> anyhow::Result<()> {
    let global_context: GlobalContext<ExampleCurve> =
        parse_exact_versioned_global_context(global_context_bytes)?;
    let ip_info: IpInfo<Bls12> = parse_exact_versioned_ip_info(ip_info_bytes)?;
    let ars_infos: ArInfos<ArCurve> = parse_exact_versioned_ars_infos(ars_infos_bytes)?;
    let request: PreIdentityObjectV1<Bls12, ExampleCurve> =
        parse_exact_versioned_pio_from_request_v1(request_bytes)?;

    let context = IpContext {
        ip_info:        &ip_info,
        ars_infos:      &ars_infos.anonymity_revokers,
        global_context: &global_context,
    };
    if let Err(e) = ip_validate_request_v1(&request, context) {
        anyhow::bail!("Ip validation failed: {:?}", e);
    }
    Ok(())
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCreation {
    id_obj:          Versioned<IdentityObject<Bls12, ExampleCurve, AttributeKind>>,
    ar_record:       Versioned<AnonymityRevocationRecord<ExampleCurve>>,
    request:         Versioned<AccountCredentialMessage<Bls12, ExampleCurve, AttributeKind>>,
    account_address: AccountAddress,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCreationV1 {
    id_obj:    Versioned<IdentityObjectV1<Bls12, ExampleCurve, AttributeKind>>,
    ar_record: Versioned<AnonymityRevocationRecord<ExampleCurve>>,
}

/// Create an identity object, the anonymity revocation record, and the initial
/// account object.
fn create_identity_object(
    ip_info_bytes: &[u8],
    request_bytes: &[u8],
    alist_bytes: &[u8],
    expiry: u64,
    ip_private_key_bytes: &[u8],
    ip_cdi_private_key_bytes: &[u8],
) -> anyhow::Result<IdentityCreation> {
    let ip_info: IpInfo<Bls12> = parse_exact_versioned_ip_info(ip_info_bytes)?;
    let alist: ExampleAttributeList =
        serde_json::from_slice(alist_bytes).context("Could not parse attribute list")?;
    let ip_private_key_str = std::str::from_utf8(ip_private_key_bytes)?;
    let ip_cdi_private_key_str = std::str::from_utf8(ip_cdi_private_key_bytes)?;

    let ip_private_key: id::ps_sig::SecretKey<Bls12> =
        base16_decode_string(ip_private_key_str).context("Could not parse ip_private_key")?;
    let ip_cdi_private_key: ed25519_dalek::SecretKey = base16_decode_string(ip_cdi_private_key_str)
        .context("Could not parse ip_cdi_private_key")?;

    let request: PreIdentityObject<Bls12, ExampleCurve> =
        parse_exact_versioned_pio_from_request(request_bytes)?;

    let signature = match sign_identity_object(&request, &ip_info, &alist, &ip_private_key) {
        Ok(sig) => sig,
        Err(e) => anyhow::bail!("Signing failed, {}", e),
    };

    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  request.pub_info_for_ip.id_cred_pub,
        ar_data:      request.ip_ar_data.clone(),
        max_accounts: alist.max_accounts,
        threshold:    request.choice_ar_parameters.threshold,
    });

    let icdi = create_initial_cdi(
        &ip_info,
        request.pub_info_for_ip.clone(),
        &alist,
        TransactionTime::from(expiry),
        &ip_cdi_private_key,
    );

    let id = IdentityObject {
        pre_identity_object: request,
        alist,
        signature,
    };
    let vid = Versioned::new(VERSION_0, id);

    let account_address =
        account_address_from_registration_id(&vid.value.pre_identity_object.pub_info_for_ip.reg_id);

    let message = AccountCredentialMessage {
        message_expiry: TransactionTime { seconds: expiry },
        credential:     AccountCredential::Initial::<id::constants::IpPairing, _, _> { icdi },
    };
    let v_initial_cdi = Versioned::new(VERSION_0, message);

    let response = IdentityCreation {
        id_obj: vid,
        account_address,
        ar_record,
        request: v_initial_cdi,
    };

    Ok(response)
}

/// Create a version 1 identity object and the anonymity revocation record.
fn create_identity_object_v1(
    ip_info_bytes: &[u8],
    request_bytes: &[u8],
    alist_bytes: &[u8],
    ip_private_key_bytes: &[u8],
) -> anyhow::Result<IdentityCreationV1> {
    let ip_info: IpInfo<Bls12> = parse_exact_versioned_ip_info(ip_info_bytes)?;
    let alist: ExampleAttributeList =
        serde_json::from_slice(alist_bytes).context("Could not parse attribute list")?;
    let ip_private_key_str = std::str::from_utf8(ip_private_key_bytes)?;

    let ip_private_key: id::ps_sig::SecretKey<Bls12> =
        base16_decode_string(ip_private_key_str).context("Could not parse ip_private_key")?;

    let request: PreIdentityObjectV1<Bls12, ExampleCurve> =
        parse_exact_versioned_pio_from_request_v1(request_bytes)?;

    let signature = match sign_identity_object_v1(&request, &ip_info, &alist, &ip_private_key) {
        Ok(sig) => sig,
        Err(e) => anyhow::bail!("Signing failed, {}", e),
    };

    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  request.id_cred_pub,
        ar_data:      request.ip_ar_data.clone(),
        max_accounts: alist.max_accounts,
        threshold:    request.choice_ar_parameters.threshold,
    });

    let id = IdentityObjectV1 {
        pre_identity_object: request,
        alist,
        signature,
    };
    let vid = Versioned::new(VERSION_0, id);

    let response = IdentityCreationV1 {
        id_obj: vid,
        ar_record,
    };

    Ok(response)
}

/// Validate an identity recovery request
fn validate_recovery_request(
    global_context_bytes: &[u8],
    ip_info_bytes: &[u8],
    request_bytes: &[u8],
) -> anyhow::Result<()> {
    let global_context: GlobalContext<ExampleCurve> =
        parse_exact_versioned_global_context(global_context_bytes)?;
    let ip_info: IpInfo<Bls12> = parse_exact_versioned_ip_info(ip_info_bytes)?;
    let recovery_request: IdRecoveryRequest<ExampleCurve> =
        parse_exact_versioned_recovery_request(request_bytes)?;

    if !validate_id_recovery_request(&ip_info, &global_context, &recovery_request) {
        anyhow::bail!("Invalid ID ownership proof.");
    }
    Ok(())
}

#[cfg(feature = "csharp")]
mod cs_exports;

#[cfg(feature = "nodejs")]
mod nodejs_exports;
