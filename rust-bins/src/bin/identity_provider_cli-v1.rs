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
    version = "1.0.0"
)]
struct IpClient {
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

fn main() -> anyhow::Result<()> {
    let app = IpClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let app = IpClient::from_clap(&matches);

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

    let v = validate_request_v1(&pio, context).is_ok();
    print!("{:?}", v);

    // let sig = sign_identity_object_v1(pre_id_obj, &context.ip_info, alist,
    // ip_secret_key)?; let vf = verify_credentials_v1(
    //     &pio,
    //     context,
    //     &attributes,
    //     &ip_data.ip_secret_key,
    // );
    // let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
    //     id_cred_pub:  pio.id_cred_pub,
    //     ar_data:      pio.common_fields.ip_ar_data.clone(),
    //     max_accounts: attributes.max_accounts,
    //     threshold:    pio.common_fields.choice_ar_parameters.threshold,
    // });

    // let signature = vf.map_err(|e| {
    //     anyhow::anyhow!(
    //         "Could not verify the identity object request. The reason is {}.",
    //         e
    //     )
    // })?;
    // let id_object = IdentityObjectV1 {
    //     pre_identity_object: pio,
    //     alist: attributes,
    //     signature,
    // };
    // let ver_id_object = Versioned::new(VERSION_0, id_object);
    // println!("Successfully checked pre-identity data.");
    // write_json_to_file(&app.out_file, &ver_id_object).context(format!(
    //     "Could not write the identity object to file {}.",
    //     app.out_file.display()
    // ))?;
    // println!(
    //     "Wrote signed identity object to file {}. Return it to the user.",
    //     &app.out_file.display()
    // );

    // let to_store = serde_json::json!({
    //     "arRecord": ar_record
    // });
    // write_json_to_file(&app.ar_record, &to_store).context(format!(
    //     "Could not write the anonymity revocation record to file {}.",
    //     app.ar_record.display()
    // ))?;
    // println!(
    //     "Wrote anonymity revocation record to file {}. Store it.",
    //     &app.ar_record.display()
    // );
    Ok(())
}
