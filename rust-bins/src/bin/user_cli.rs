use anyhow::Context;
use chrono::TimeZone;
use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{
    types::{CredentialIndex, KeyIndex, KeyPair, TransactionTime},
    *,
};
use dialoguer::{Input, MultiSelect, Select};
use dodis_yampolskiy_prf as prf;
use either::Either::{Left, Right};
use id::{account_holder::*, secret_sharing::*, types::*};
use rand::*;
use serde_json::{json, to_value};
use std::{collections::btree_map::BTreeMap, convert::TryFrom, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct StartIp {
    #[structopt(
        long = "ip-info",
        help = "File with information about the identity provider."
    )]
    ip_info:            PathBuf,
    #[structopt(
        long = "initial-keys-out",
        help = "File to write the private keys of the user's initial account."
    )]
    initial_keys:       PathBuf,
    #[structopt(long = "ars", help = "File with a list of anonymity revokers.")]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "id-use-data-out",
        help = "File to write the identity object use data to. This contains some private keys."
    )]
    private:            PathBuf,
    #[structopt(
        long = "request-out",
        help = "File to write the request to that is to be sent to the identity provider."
    )]
    public:             PathBuf,
    #[structopt(
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:             PathBuf,
    #[structopt(
        name = "ar-threshold",
        long = "ar-threshold",
        help = "Anonymity revocation threshold.",
        requires = "selected-ars"
    )]
    threshold:          Option<u8>,
    #[structopt(
        long = "selected-ars",
        help = "Indices of selected ars. If none are provided an interactive choice will be \
                presented.",
        requires = "ar-threshold"
    )]
    selected_ars:       Vec<u32>,
}

#[derive(StructOpt)]
struct CreateCredential {
    #[structopt(
        long = "id-object",
        help = "File with the JSON encoded identity object."
    )]
    id_object:   PathBuf,
    #[structopt(long = "id-use-data", help = "File with private identity object data.")]
    id_use_data: PathBuf,
    #[structopt(
        long = "account",
        help = "Account address onto which the credential should be deployed.",
        requires = "key-index"
    )]
    account:     Option<AccountAddress>,
    #[structopt(
        long = "message-expiry",
        help = "Expiry time of the credential message. In seconds from __now__.",
        required_unless = "account",
        conflicts_with = "account",
        default_value = "900"
    )]
    expiry:      u64,
    #[structopt(
        name = "key-index",
        long = "key-index",
        help = "Credential index of the new credential.",
        requires = "account",
        conflicts_with = "expiry"
    )]
    key_index:   Option<u8>,
    #[structopt(long = "credential-out", help = "File to output the credential to.")]
    out:         PathBuf,
    #[structopt(long = "keys-out", help = "File to output account keys to.")]
    keys_out:    PathBuf,
    #[structopt(long = "index", help = "Index of the account to be created.")]
    index:       Option<u8>,
}

#[derive(StructOpt)]
#[structopt(
    about = "Command line client to request identity objects and create credentials.",
    name = "User CLI",
    author = "Concordium",
    version = "1.0.0"
)]
enum UserClient {
    #[structopt(
        name = "generate-request",
        about = "Generate data to send to the identity provider to obtain an identity object.",
        version = "1.0.0"
    )]
    StartIp(StartIp),
    #[structopt(
        name = "create-credential",
        about = "Take the identity object and create a credential object to deploy on chain to \
                 create an account.",
        version = "1.0.0"
    )]
    CreateCredential(CreateCredential),
}

fn main() -> anyhow::Result<()> {
    let app = UserClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let client = UserClient::from_clap(&matches);
    use UserClient::*;
    match client {
        StartIp(ip) => handle_start_ip(ip),
        CreateCredential(cc) => handle_create_credential(cc),
    }
}

fn handle_start_ip(sip: StartIp) -> anyhow::Result<()> {
    let ip_info = read_ip_info(&sip.ip_info).context(format!(
        "Could not read the identity provider information from {}.",
        sip.ip_info.display()
    ))?;
    let ars = read_anonymity_revokers(&sip.anonymity_revokers).context(format!(
        "Could not read anonymity revokers from {}.",
        sip.anonymity_revokers.display()
    ))?;
    let global_ctx = read_global_context(&sip.global).context(format!(
        "Could not read cryptographic parameters from {}.",
        sip.global.display()
    ))?;

    let ar_ids = if sip.selected_ars.is_empty() {
        let mrs: Vec<&str> = ars
            .anonymity_revokers
            .values()
            .map(|x| x.ar_description.name.as_str())
            .collect();
        let keys = ars.anonymity_revokers.keys().collect::<Vec<_>>();
        let defaults = vec![true; keys.len()];
        let ar_ids = MultiSelect::new()
            .with_prompt("Choose anonymity revokers")
            .items(&mrs)
            .defaults(&defaults)
            .interact()?
            .iter()
            .map(|&x| *keys[x])
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !ar_ids.is_empty(),
            "You need to select at least one anonymity revoker."
        );
        ar_ids
    } else {
        let res = sip
            .selected_ars
            .iter()
            .map(|&x| ArIdentity::try_from(x))
            .collect();
        match res {
            Ok(v) => v,
            Err(e) => {
                anyhow::bail!("Incorrect anonymity revoker identities: {}", e);
            }
        }
    };
    let num_ars = ar_ids.len();
    let mut choice_ars = BTreeMap::new();
    for ar_id in ar_ids.iter() {
        choice_ars.insert(
            *ar_id,
            ars.anonymity_revokers
                .get(ar_id)
                .context(format!(
                    "Chosen anonymity revoker {} does not exist in the given list.",
                    ar_id
                ))?
                .clone(),
        );
    }

    let threshold = if let Some(thr) = sip.threshold {
        Threshold(thr)
    } else {
        let threshold = Select::new()
            .with_prompt("Revocation threshold")
            .items(&(1..=num_ars).collect::<Vec<usize>>())
            .default(if num_ars == 1 { 0 } else { num_ars - 2 })
            .interact()?;
        Threshold((threshold + 1) as u8) // +1 because the indexing of the
                                         // selection starts at 1
    };

    let mut csprng = thread_rng();
    let chi = CredentialHolderInfo::<id::constants::ArCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // the chosen account credential information
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    let context = IpContext::new(&ip_info, &choice_ars, &global_ctx);
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let initial_acc_data = InitialAccountData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(1),
    };

    let (pio, randomness) = generate_pio(&context, threshold, &aci, &initial_acc_data)
        .context("Failed to generate the identity object request.")?;
    let id_use_data = IdObjectUseData { aci, randomness };

    let enc_key = id_use_data.aci.prf_key.prf_exponent(0).unwrap();

    let secret_key = elgamal::SecretKey {
        generator: *global_ctx.elgamal_generator(),
        scalar:    enc_key,
    };

    // initial account information. We don't have the credential and
    // the randomness so we don't store them.
    // address of the initial account
    let address = AccountAddress::new(&pio.pub_info_for_ip.reg_id);
    let init_acc = json!({
        "address": address,
        "encryptionSecretKey": secret_key,
        "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
        "accountKeys": AccountKeys::from(initial_acc_data),
        "aci": id_use_data.aci,
    });

    println!(
        "Generated private keys for initial account. The credential has one key with key index 0."
    );
    println!("Address of the initial account will be {}.", address);
    let was_encrypted =
        output_possibly_encrypted(&sip.initial_keys, &init_acc).context(format!(
            "Could not write accounts keys of initial account to {}.",
            sip.initial_keys.display()
        ))?;
    println!(
        "Wrote private keys of initial account to file {}. {}",
        &sip.initial_keys.display(),
        if was_encrypted {
            "Keys are encrypted."
        } else {
            "Keys are in plaintext."
        }
    );

    // the only thing left is to output all the information

    let data = StoredData {
        ars,
        ip_info,
        global_ctx,
        id_use_data,
    };

    let ver_data = Versioned::new(VERSION_0, data);
    println!(
        "Generated the request and id object use data. Writing them to {}.",
        sip.private.display()
    );
    let was_encrypted = output_possibly_encrypted(&sip.private, &ver_data).context(format!(
        "Could not write id object use data to {}.",
        sip.private.display()
    ))?;
    println!(
        "Wrote id object use data to {}. {}",
        &sip.private.display(),
        if was_encrypted {
            "Keys are encrypted."
        } else {
            "Keys are in plaintext."
        }
    );

    let ver_pio = Versioned::new(VERSION_0, pio);
    write_json_to_file(&sip.public, &ver_pio).context(format!(
        "Could not write the request to {}",
        sip.public.display()
    ))?;
    println!(
        "Wrote the identity object request to {}. Send it to the identity provider.",
        &sip.public.display()
    );
    Ok(())
}

#[derive(SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Data stored by the user after generating the identity object request so that
/// they can use the identity object.
struct StoredData {
    ars:         ArInfos<id::constants::ArCurve>,
    ip_info:     IpInfo<id::constants::IpPairing>,
    global_ctx:  GlobalContext<id::constants::ArCurve>,
    id_use_data: IdObjectUseData<id::constants::IpPairing, id::constants::ArCurve>,
}

fn handle_create_credential(cc: CreateCredential) -> anyhow::Result<()> {
    let id_object = read_id_object(&cc.id_object).context(format!(
        "Could not read the identity object from {}.",
        &cc.id_object.display()
    ))?;

    let data: Versioned<StoredData> = decrypt_input(&cc.id_use_data).context(format!(
        "Could not read identity object use data from {}.",
        cc.id_use_data.display()
    ))?;
    anyhow::ensure!(
        data.version == VERSION_0,
        "Only version 0 of id use data is supported."
    );
    let data = data.value;

    let ip_info = data.ip_info;
    let ars = data.ars;
    let global_ctx = data.global_ctx;
    let id_use_data = data.id_use_data;

    // now we have all the data ready.
    // we first ask the user to select which attributes they wish to reveal
    let alist = &id_object.alist.alist;

    let alist_items = alist
        .keys()
        .map(|&x| AttributeStringTag::from(x))
        .collect::<Vec<_>>();
    let atts = if alist_items.is_empty() {
        eprintln!("No attributes on the identity object, so none will be on the credential.");
        Vec::new()
    } else {
        MultiSelect::new()
            .with_prompt("Select which attributes you wish to reveal")
            .items(&alist_items)
            .interact()
            .context("You must select which attributes you wish to reveal on the chain.")?
    };

    // from the above and the pre-identity object we make a policy
    let mut revealed_attributes: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
    for idx in atts {
        let tag = alist.keys().collect::<Vec<_>>()[idx];
        let elem = alist.get(tag).context(format!(
            "You selected an attribute ({}) which does not exist.",
            tag
        ))?;
        if revealed_attributes.insert(*tag, elem.clone()).is_some() {
            anyhow::bail!(
                "Attempt to reveal the same attribute ({}) more than once.",
                tag
            );
        }
    }
    let policy = Policy {
        valid_to:   id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec: revealed_attributes,
        _phantom:   Default::default(),
    };

    // We ask what regid index they would like to use.
    let x = match cc.index {
        Some(x) => x,
        None => Input::new()
            .with_prompt(format!(
                "Credential number (between 1 and {})",
                id_object.alist.max_accounts
            ))
            .default(1)
            .interact()
            .context("You must select which index to use.")?,
    };

    // Now we have have everything we need to generate the proofs
    // we have
    // - chi
    // - pio
    // - ip_info
    // - signature of the identity provider
    // - acc_data of the account onto which we are deploying this credential
    //   (private and public)

    let context = IpContext::new(&ip_info, &ars.anonymity_revokers, &global_ctx);

    // We now generate or read account verification/signature key pair.
    let acc_data = {
        let mut csprng = thread_rng();
        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        CredentialData {
            keys,
            threshold: SignatureThreshold(1),
        }
    };

    let new_or_existing = match cc.account {
        Some(addr) => Right(addr),
        None => Left(TransactionTime {
            seconds: chrono::Utc::now().timestamp() as u64 + cc.expiry,
        }),
    };

    let cdi = create_credential(
        context,
        &id_object,
        &id_use_data,
        x,
        policy,
        &acc_data,
        &new_or_existing,
    );

    let (cdi, commitments_randomness) = cdi.context("Could not generate the credential.")?;

    let address = AccountAddress::new(&cdi.values.cred_id);

    // Output in the format accepted by concordium-client.
    let (versioned_credentials, randomness_map) = {
        let ki = cc.key_index.map_or(KeyIndex(0), KeyIndex);
        let mut credentials = BTreeMap::new();
        let mut randomness = BTreeMap::new();
        let cdvp = AccountCredentialWithoutProofs::Normal {
            cdv:         cdi.values.clone(),
            commitments: cdi.proofs.id_proofs.commitments.clone(),
        };
        credentials.insert(ki, cdvp);
        randomness.insert(ki, &commitments_randomness);
        (Versioned::new(VERSION_0, credentials), randomness)
    };

    let cdi = AccountCredential::Normal { cdi };

    let enc_key = id_use_data.aci.prf_key.prf_exponent(x).unwrap();

    let secret_key = elgamal::SecretKey {
        generator: *global_ctx.elgamal_generator(),
        scalar:    enc_key,
    };

    if let Some(addr) = cc.account {
        let js = json!({
            "address": addr,
            "accountKeys": AccountKeys::from((CredentialIndex{index: cc.key_index.unwrap()}, acc_data)),
            "credentials": versioned_credentials,
            "commitmentsRandomness": randomness_map,
        });
        let was_encrypted = output_possibly_encrypted(&cc.keys_out, &js).context(format!(
            "Could not output account keys to {}.",
            cc.keys_out.display()
        ))?;
        println!(
            "Generated additional keys for the account. They are written to {}. {}",
            cc.keys_out.display(),
            if was_encrypted {
                "Keys are encrypted."
            } else {
                "Keys are in plaintext."
            }
        );
    } else {
        let account_data_json = json!({
            "address": address,
            "encryptionSecretKey": secret_key,
            "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
            "accountKeys": AccountKeys::from(acc_data),
            "credentials": versioned_credentials,
            "commitmentsRandomness": randomness_map,
            "aci": id_use_data.aci,
        });
        let was_encrypted =
            output_possibly_encrypted(&cc.keys_out, &account_data_json).context(format!(
                "Could not output account keys to {}.",
                cc.keys_out.display()
            ))?;
        println!(
            "Generated fresh keys of the account and wrote them to {}. {} DO NOT LOSE THIS FILE.",
            cc.keys_out.display(),
            if was_encrypted {
                "Keys are encrypted."
            } else {
                "Keys are in plaintext."
            }
        );
    }

    let (expiry, cdi_json_value) = match new_or_existing {
        Left(tt) => (
            Some(tt),
            to_value(&Versioned::new(VERSION_0, AccountCredentialMessage {
                message_expiry: tt,
                credential:     cdi,
            }))
            .expect("Cannot fail."),
        ),
        Right(_) => (
            None,
            to_value(&Versioned::new(VERSION_0, cdi)).expect("Cannot fail"),
        ),
    };
    write_json_to_file(&cc.out, &cdi_json_value).context(format!(
        "Could not write credential to {}.",
        cc.out.display()
    ))?;
    if let Some(expiry) = expiry {
        println!(
            "Wrote the account creation transaction to {}. Submit it before {}.",
            cc.out.display(),
            chrono::Local.timestamp(expiry.seconds as i64, 0)
        );
        println!(
            "This transaction will create an account with address {}.",
            address
        );
    } else {
        println!(
            "Wrote the credential to {}. Add it to a transaction and send it.",
            cc.out.display()
        );
    }
    Ok(())
}
