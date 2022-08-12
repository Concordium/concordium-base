use anyhow::Context;
use chrono::TimeZone;
use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{types::TransactionTime, *};
use dialoguer::Input;
use id::{
    constants::{ArCurve, AttributeKind, IpPairing},
    identity_provider::*,
    types::*,
};
use pairing::bls12_381::Bls12;
use std::{collections::btree_map::BTreeMap, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    about = "Command line client that supports issuing identities for enterprises.",
    name = "Identity provider CLI",
    author = "Concordium",
    version = "2.0.0"
)]
struct IpV0 {
    #[structopt(
        long = "request",
        help = "File with the identity object request received from the user."
    )]
    pio:                PathBuf,
    #[structopt(
        long = "ip-data",
        help = "Possibly encrypted file with all information about the identity provider (public \
                and private)."
    )]
    ip_data:            PathBuf,
    #[structopt(long = "id-out", help = "File to write the signed identity object to.")]
    out_file:           PathBuf,
    #[structopt(
        long = "ar-record-out",
        help = "File to write anonymity revocation record to."
    )]
    ar_record:          PathBuf,
    #[structopt(
        long = "initial-account-out",
        help = "File to output the payload of the initial account creation transaction."
    )]
    out_icdi:           PathBuf,
    #[structopt(
        name = "cryptographic-parameters",
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:             PathBuf,
    #[structopt(long = "ars", help = "File with a list of anonymity revokers.")]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "message-expiry",
        help = "Expiry time of the initial credential transaction. In seconds from __now__.",
        default_value = "900"
    )]
    expiry:             u64,
    #[structopt(
        long = "id-object-expiry",
        help = "Expiry time of the identity object. As YYYYMM."
    )]
    id_expiry:          Option<YearMonth>,
    #[structopt(
        long = "max-accounts",
        help = "Maximum number of accounts that can be created from the identity object.",
        default_value = "25"
    )]
    max_accounts:       u8,
}

#[derive(StructOpt)]
#[structopt(
    about = "Command line client that supports issuing identities for enterprises.",
    name = "Identity provider CLI",
    author = "Concordium",
    version = "2.0.0"
)]
struct IpV1 {
    #[structopt(
        long = "request",
        help = "File with the identity object request received from the user."
    )]
    pio:                PathBuf,
    #[structopt(
        long = "ip-data",
        help = "Possibly encrypted file with all information about the identity provider (public \
                and private)."
    )]
    ip_data:            PathBuf,
    #[structopt(long = "id-out", help = "File to write the signed identity object to.")]
    out_file:           PathBuf,
    #[structopt(
        long = "ar-record-out",
        help = "File to write anonymity revocation record to."
    )]
    ar_record:          PathBuf,
    #[structopt(
        name = "cryptographic-parameters",
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:             PathBuf,
    #[structopt(long = "ars", help = "File with a list of anonymity revokers.")]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "id-object-expiry",
        help = "Expiry time of the identity object. As YYYYMM."
    )]
    id_expiry:          Option<YearMonth>,
    #[structopt(
        long = "max-accounts",
        help = "Maximum number of accounts that can be created from the identity object.",
        default_value = "25"
    )]
    max_accounts:       u8,
}

#[derive(StructOpt)]
#[structopt(
    about = "Command line client that supports issuing identities for enterprises.",
    name = "User CLI",
    author = "Concordium",
    version = "2.0.0"
)]
enum IpClient {
    #[structopt(
        name = "sign-identity-request",
        about = "Validate, sign and return version 0 identity object.",
        version = "2.0.0"
    )]
    SignPioV0(IpV0),
    #[structopt(
        name = "sign-identity-request-v1",
        about = "Validate, sign and return version 1 identity object.",
        version = "2.0.0"
    )]
    SignPioV1(IpV1),
    #[structopt(
        name = "validate-recovery-request",
        about = "Validate id recovery request.",
        version = "2.0.0"
    )]
    ValidateIdRecoveryRequest(ValidateIdRecoveryRequest),
}

#[derive(StructOpt)]
struct ValidateIdRecoveryRequest {
    #[structopt(long = "request", help = "File with id recovery request.")]
    request: PathBuf,
    #[structopt(
        long = "ip-info",
        help = "File with information about the identity provider."
    )]
    ip_info: PathBuf,
    #[structopt(
        name = "cryptographic-parameters",
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:  PathBuf,
}

fn main() -> anyhow::Result<()> {
    let app = IpClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let client = IpClient::from_clap(&matches);
    use IpClient::*;
    match client {
        SignPioV0(sip) => handle_sign_pio_v0(sip),
        SignPioV1(sip) => handle_sign_pio_v1(sip),
        ValidateIdRecoveryRequest(vir) => handle_validate_recovery(vir),
    }
}

fn handle_sign_pio_v0(app: IpV0) -> anyhow::Result<()> {
    let pio = read_pre_identity_object(&app.pio).context(format!(
        "Could not read the identity object request from file {}.",
        app.pio.display()
    ))?;

    let ip_data = decrypt_input::<_, IpData<Bls12>>(&app.ip_data)
        .context("Could not read identity provider keys.")?;

    let global_ctx = read_global_context(&app.global).context(format!(
        "Could not read cryptographic parameters file '{}'.",
        app.global.display()
    ))?;

    // all known anonymity revokers.
    let ars = read_anonymity_revokers(&app.anonymity_revokers).context(format!(
        "Could not read anonymity revokers from the file {}.",
        app.anonymity_revokers.display()
    ))?;

    let confirm_ar = dialoguer::Confirm::new()
        .default(false)
        .show_default(true)
        .wait_for_newline(true)
        .with_prompt(format!(
            "The user chose anonymity revocation threshold {} and anonymity revokers [{}]. Accept?",
            pio.choice_ar_parameters.threshold,
            pio.choice_ar_parameters
                .ar_identities
                .iter()
                .map(|ar| ar.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .interact()
        .context("Did not get acceptable response.")?;
    anyhow::ensure!(
        confirm_ar,
        "Anonymity revocation parameters are not acceptable."
    );

    let created_at = YearMonth::now();
    let valid_to = match app.id_expiry {
        Some(exp) => exp,
        None => {
            let default_value = YearMonth {
                year:  created_at.year + 5,
                month: created_at.month,
            };
            let input: String = Input::new()
                .with_prompt("Enter identity object expiry (YYYYMM)")
                .default(default_value.to_string())
                .interact()?;
            input
                .parse()
                .context("Could not parse the valid to date.")?
        }
    };

    let alist = {
        let mut alist: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
        let s: String = Input::new()
            .with_prompt("Please provide LEI (Legal Entity Identifier) (Leave empty for no LEI)")
            .allow_empty(true)
            .interact()
            .context("Could not read attribute LEI")?;
        if !s.is_empty() {
            alist.insert(ATTRIBUTE_TAG_LEI, AttributeKind(s));
        }
        alist
    };

    let attributes = AttributeList {
        valid_to,
        created_at,
        max_accounts: app.max_accounts,
        alist,
        _phantom: Default::default(),
    };
    let context = IpContext::new(
        &ip_data.public_ip_info,
        &ars.anonymity_revokers,
        &global_ctx,
    );
    let message_expiry = TransactionTime {
        seconds: chrono::Utc::now().timestamp() as u64 + app.expiry,
    };
    let vf = verify_credentials(
        &pio,
        context,
        &attributes,
        message_expiry,
        &ip_data.ip_secret_key,
        &ip_data.ip_cdi_secret_key,
    );
    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  pio.pub_info_for_ip.id_cred_pub,
        ar_data:      pio.ip_ar_data.clone(),
        max_accounts: attributes.max_accounts,
        threshold:    pio.choice_ar_parameters.threshold,
    });

    let (signature, icdi) = vf.map_err(|e| {
        anyhow::anyhow!(
            "Could not verify the identity object request. The reason is {}.",
            e
        )
    })?;
    let account_address = account_address_from_registration_id(&pio.pub_info_for_ip.reg_id);
    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist: attributes,
        signature,
    };
    let ver_id_object = Versioned::new(VERSION_0, id_object);
    println!("Successfully checked pre-identity data.");
    write_json_to_file(&app.out_file, &ver_id_object).context(format!(
        "Could not write the identity object to file {}.",
        app.out_file.display()
    ))?;
    println!(
        "Wrote signed identity object to file {}. Return it to the user.",
        &app.out_file.display()
    );

    let icdi_message = AccountCredentialMessage::<IpPairing, ArCurve, _> {
        message_expiry,
        credential: AccountCredential::Initial { icdi },
    };
    let versioned_icdi = Versioned::new(VERSION_0, icdi_message);
    write_json_to_file(&app.out_icdi, &versioned_icdi).context(format!(
        "Could not write the initial account transaction to file {}. Try again.",
        app.out_icdi.display()
    ))?;
    println!(
        "Wrote initial account transaction to file {}. Submit it before {}.",
        &app.out_icdi.to_string_lossy(),
        chrono::Local.timestamp(message_expiry.seconds as i64, 0),
    );
    println!(
        "Address of the initial account will be {}.",
        account_address
    );

    let to_store = serde_json::json!({
        "arRecord": ar_record,
        "accountAddress": account_address
    });
    write_json_to_file(&app.ar_record, &to_store).context(format!(
        "Could not write the anonymity revocation record to file {}.",
        app.ar_record.display()
    ))?;
    println!(
        "Wrote anonymity revocation record to file {}. Store it.",
        &app.ar_record.display()
    );
    Ok(())
}

fn handle_sign_pio_v1(app: IpV1) -> anyhow::Result<()> {
    let pio = read_pre_identity_object_v1(&app.pio).context(format!(
        "Could not read the identity object request from file {}.",
        app.pio.display()
    ))?;

    let ip_data = decrypt_input::<_, IpData<Bls12>>(&app.ip_data)
        .context("Could not read identity provider keys.")?;

    let global_ctx = read_global_context(&app.global).context(format!(
        "Could not read cryptographic parameters file '{}'.",
        app.global.display()
    ))?;

    // all known anonymity revokers.
    let ars = read_anonymity_revokers(&app.anonymity_revokers).context(format!(
        "Could not read anonymity revokers from the file {}.",
        app.anonymity_revokers.display()
    ))?;

    let confirm_ar = dialoguer::Confirm::new()
        .default(false)
        .show_default(true)
        .wait_for_newline(true)
        .with_prompt(format!(
            "The user chose anonymity revocation threshold {} and anonymity revokers [{}]. Accept?",
            pio.choice_ar_parameters.threshold,
            pio.choice_ar_parameters
                .ar_identities
                .iter()
                .map(|ar| ar.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .interact()
        .context("Did not get acceptable response.")?;
    anyhow::ensure!(
        confirm_ar,
        "Anonymity revocation parameters are not acceptable."
    );

    let created_at = YearMonth::now();
    let valid_to = match app.id_expiry {
        Some(exp) => exp,
        None => {
            let default_value = YearMonth {
                year:  created_at.year + 5,
                month: created_at.month,
            };
            let input: String = Input::new()
                .with_prompt("Enter identity object expiry (YYYYMM)")
                .default(default_value.to_string())
                .interact()?;
            input
                .parse()
                .context("Could not parse the valid to date.")?
        }
    };

    let alist = {
        let mut alist: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
        let s: String = Input::new()
            .with_prompt("Please provide LEI (Legal Entity Identifier) (Leave empty for no LEI)")
            .allow_empty(true)
            .interact()
            .context("Could not read attribute LEI")?;
        if !s.is_empty() {
            alist.insert(ATTRIBUTE_TAG_LEI, AttributeKind(s));
        }
        alist
    };

    let attributes = AttributeList {
        valid_to,
        created_at,
        max_accounts: app.max_accounts,
        alist,
        _phantom: Default::default(),
    };
    let context = IpContext::new(
        &ip_data.public_ip_info,
        &ars.anonymity_revokers,
        &global_ctx,
    );
    let vf = verify_credentials_v1(&pio, context, &attributes, &ip_data.ip_secret_key);
    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  pio.id_cred_pub,
        ar_data:      pio.ip_ar_data.clone(),
        max_accounts: attributes.max_accounts,
        threshold:    pio.choice_ar_parameters.threshold,
    });

    let signature = vf.map_err(|e| {
        anyhow::anyhow!(
            "Could not verify the identity object request. The reason is {}.",
            e
        )
    })?;
    let id_object = IdentityObjectV1 {
        pre_identity_object: pio,
        alist: attributes,
        signature,
    };
    let ver_id_object = Versioned::new(VERSION_0, id_object);
    println!("Successfully checked pre-identity data.");
    write_json_to_file(&app.out_file, &ver_id_object).context(format!(
        "Could not write the identity object to file {}.",
        app.out_file.display()
    ))?;
    println!(
        "Wrote signed identity object to file {}. Return it to the user.",
        &app.out_file.display()
    );

    let to_store = serde_json::json!({ "arRecord": ar_record });
    write_json_to_file(&app.ar_record, &to_store).context(format!(
        "Could not write the anonymity revocation record to file {}.",
        app.ar_record.display()
    ))?;
    println!(
        "Wrote anonymity revocation record to file {}. Store it.",
        &app.ar_record.display()
    );
    Ok(())
}

fn handle_validate_recovery(vir: ValidateIdRecoveryRequest) -> anyhow::Result<()> {
    let global_ctx = read_global_context(&vir.global).context(format!(
        "Could not read cryptographic parameters file '{}'.",
        vir.global.display()
    ))?;

    let ip_info = read_ip_info(&vir.ip_info).context(format!(
        "Could not read ip info file '{}'.",
        vir.ip_info.display()
    ))?;

    let request = read_recovery_request(&vir.request).context(format!(
        "Could not read recovery request file '{}'.",
        vir.request.display()
    ))?;

    let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
    println!("ID recovery validation result: {}", result);

    Ok(())
}
