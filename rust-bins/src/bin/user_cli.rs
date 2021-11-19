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
use pairing::bls12_381::Bls12;
use rand::*;
use serde_json::{json, to_value};
use std::{cmp::max, collections::btree_map::BTreeMap, convert::TryFrom, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt)]
struct StartIp {
    #[structopt(
        long = "ip-info",
        help = "File with the JSON encoded information about the identity provider."
    )]
    ip_info:            PathBuf,
    #[structopt(
        long = "initial-keys",
        help = "File to write the JSON encoded private keys of the user's initial account."
    )]
    initial_keys:       PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(long = "private", help = "File to write the private ACI data to.")]
    private:            PathBuf,
    #[structopt(
        long = "public",
        help = "File to write the public data to be sent to the identity provider."
    )]
    public:             PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
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
        help = "Indices of selected ars. If none are provided an interactive choice will be given.",
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
    id_object:          PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global:             PathBuf,
    #[structopt(
        long = "ip-info",
        help = "File with the JSON encoded information about the identity provider."
    )]
    ip_info:            PathBuf,
    #[structopt(
        long = "private",
        help = "File with private credential holder information used to generate the identity \
                object."
    )]
    private:            PathBuf,
    #[structopt(
        long = "account",
        help = "Account address onto which the credential should be deployed.",
        requires = "key-index"
    )]
    account:            Option<AccountAddress>,
    #[structopt(
        long = "expiry",
        help = "Expiry time of the credential message. In seconds from __now__.",
        required_unless = "account",
        conflicts_with = "account"
    )]
    expiry:             Option<u64>,
    #[structopt(
        name = "key-index",
        long = "key-index",
        help = "Credential index of the new credential.",
        requires = "account",
        conflicts_with = "expiry"
    )]
    key_index:          Option<u8>,
    #[structopt(long = "out", help = "File to output the JSON transaction payload to.")]
    out:                PathBuf,
    #[structopt(
        long = "keys-out",
        help = "File to output account keys.",
        default_value = "account_keys.json"
    )]
    keys_out:           PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(long = "index", help = "Index of the account to be created.")]
    index:              Option<u8>,
}

#[derive(StructOpt)]
#[structopt(about = "User client", author = "Concordium", version = "1")]
enum UserClient {
    #[structopt(
        name = "start-ip",
        about = "Generate data to send to the identity provider to sign and verify."
    )]
    StartIp(StartIp),
    #[structopt(
        name = "create-credential",
        about = "Take the identity object, select attributes to reveal and create a credential \
                 object to deploy on chain."
    )]
    CreateCredential(CreateCredential),
}

fn main() {
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

fn handle_start_ip(sip: StartIp) {
    let mut csprng = thread_rng();
    let chi = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // the chosen account credential information
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    let ip_info = match read_ip_info(sip.ip_info) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read identity provider info because {}", err);
            return;
        }
    };

    let ars = {
        if let Ok(ars) = read_anonymity_revokers(sip.anonymity_revokers) {
            ars
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let ar_ids = if sip.selected_ars.is_empty() {
        let mrs: Vec<&str> = ars
            .anonymity_revokers
            .values()
            .map(|x| x.ar_description.name.as_str())
            .collect();
        let keys = ars.anonymity_revokers.keys().collect::<Vec<_>>();
        let ar_ids = MultiSelect::new()
            .with_prompt("Choose anonymity revokers")
            .items(&mrs)
            .interact()
            .unwrap()
            .iter()
            .map(|&x| *keys[x])
            .collect::<Vec<_>>();
        if ar_ids.is_empty() {
            eprintln!("You need to select an AR.");
            return;
        }
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
                eprintln!("Incorrect AR identities: {}", e);
                return;
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
                .expect("Chosen AR does not exist.")
                .clone(),
        );
    }

    let threshold = if let Some(thr) = sip.threshold {
        Threshold(thr)
    } else if let Ok(threshold) = Select::new()
        .with_prompt("Revocation threshold")
        .items(&(1..=num_ars).collect::<Vec<usize>>())
        .default(0)
        .interact()
    {
        Threshold((threshold + 1) as u8) // +1 because the indexing of the
                                         // selection starts at 1
    } else {
        let d = max(1, num_ars - 1);
        println!(
            "Selecting default value (= {}) for revocation threshold.",
            d
        );
        Threshold(d as u8)
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(sip.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    let context = IpContext::new(&ip_info, &choice_ars, &global_ctx);
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let initial_acc_data = InitialAccountData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    println!("Generated private keys for initial account.");
    if let Err(e) = output_possibly_encrypted(&sip.initial_keys, &initial_acc_data) {
        eprintln!(
            "Could not write (encrypted) private keys of initial account to file because: {}",
            e
        );
        return;
    }
    println!(
        "Wrote (encrypted) private keys of initial account to file {}.",
        &sip.private.to_string_lossy()
    );
    let (pio, randomness) = generate_pio(&context, threshold, &aci, &initial_acc_data)
        .expect("Generating the pre-identity object should succeed.");

    // the only thing left is to output all the information

    let id_use_data = IdObjectUseData { aci, randomness };
    let ver_id_use_data = Versioned::new(VERSION_0, id_use_data);
    println!("Generated ACI and randomness.");
    if let Err(e) = output_possibly_encrypted(&sip.private, &ver_id_use_data) {
        eprintln!(
            "Could not write (encrypted) ACI data to file because: {}",
            e
        );
        return;
    }
    println!(
        "Wrote (encrypted) ACI and randomness to file {}.",
        &sip.private.to_string_lossy()
    );

    let ver_pio = Versioned::new(VERSION_0, pio);
    if let Err(e) = write_json_to_file(&sip.public, &ver_pio) {
        println!("Could not write PIO data to file because: {}", e);
        return;
    }
    println!("Wrote PIO data to file {}.", &sip.public.to_string_lossy());
}

fn handle_create_credential(cc: CreateCredential) {
    let id_object = {
        match read_id_object(cc.id_object) {
            Ok(v) => v,
            Err(x) => {
                eprintln!("Could not read identity object because {}", x);
                return;
            }
        }
    };

    let ip_info = match read_ip_info(cc.ip_info) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read identity provider info because {}", err);
            return;
        }
    };

    // we also read the global context from another json file (called
    // global.context). We need commitment keys and other data in there.
    let global_ctx = {
        if let Some(gc) = read_global_context(cc.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

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
        match MultiSelect::new()
            .with_prompt("Select which attributes you wish to reveal")
            .items(&alist_items)
            .interact()
        {
            Ok(idxs) => idxs,
            Err(x) => {
                eprintln!("You need to select which attributes you want. {}", x);
                return;
            }
        }
    };

    // from the above and the pre-identity object we make a policy
    let mut revealed_attributes: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
    for idx in atts {
        let tag = alist.keys().collect::<Vec<_>>()[idx];
        match alist.get(tag) {
            Some(elem) => {
                if revealed_attributes.insert(*tag, elem.clone()).is_some() {
                    eprintln!("Duplicate attribute idx.");
                    return;
                }
            }
            None => {
                eprintln!("Selected an attribute which does not exist. Aborting.");
                return;
            }
        }
    }
    let policy = Policy {
        valid_to:   id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec: revealed_attributes,
        _phantom:   Default::default(),
    };

    // finally we also read the credential holder information with secret keys
    // which we need to generate CDI.
    // This file should also contain the public keys of the identity provider who
    // signed the object.
    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = match read_id_use_data(cc.private) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not read CHI object because: {}", x);
            return;
        }
    };

    // We ask what regid index they would like to use.
    let x = match cc.index {
        Some(x) => x,
        None => Input::new().with_prompt("Index").interact().unwrap_or(0), // 0 is the default index
    };

    // Now we have have everything we need to generate the proofs
    // we have
    // - chi
    // - pio
    // - ip_info
    // - signature of the identity provider
    // - acc_data of the account onto which we are deploying this credential
    //   (private and public)

    // all known anonymity revokers.
    let ars = {
        if let Ok(ars) = read_anonymity_revokers(cc.anonymity_revokers) {
            ars.anonymity_revokers
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let context = IpContext::new(&ip_info, &ars, &global_ctx);

    // We now generate or read account verification/signature key pair.
    let acc_data = {
        let mut csprng = thread_rng();
        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));

        CredentialData {
            keys,
            threshold: SignatureThreshold(2),
        }
    };

    let new_or_existing = match (cc.expiry, cc.account) {
        (None, None) => panic!("One of (expiry, address) is required."),
        (None, Some(addr)) => Right(addr),
        (Some(seconds), None) => Left(TransactionTime {
            seconds: chrono::Utc::now().timestamp() as u64 + seconds,
        }),
        (Some(_), Some(_)) => panic!("Exactly one of (expiry, address) is required."),
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

    let (cdi, commitments_randomness) = match cdi {
        Ok(cdi) => cdi,
        Err(x) => {
            eprintln!("Could not generate the credential because {}", x);
            return;
        }
    };

    let address = AccountAddress::new(&cdi.values.cred_id);

    let cdi = AccountCredential::Normal { cdi };

    let (versioned_credentials, randomness_map) = {
        let ki = cc.key_index.map_or(KeyIndex(0), KeyIndex);
        let mut credentials = BTreeMap::new();
        let mut randomness = BTreeMap::new();
        // NB: We insert the reference to the credential here so as to avoid cloning
        // (which is not implemented for the type)
        credentials.insert(ki, &cdi);
        randomness.insert(ki, &commitments_randomness);
        (Versioned::new(VERSION_0, credentials), randomness)
    };

    let enc_key = id_use_data.aci.prf_key.prf_exponent(x).unwrap();

    let secret_key = elgamal::SecretKey {
        generator: *global_ctx.elgamal_generator(),
        scalar:    enc_key,
    };

    if let Some(addr) = cc.account {
        println!(
            "Generated additional keys for the account to be encrypted and written to file {}.",
            cc.keys_out.to_string_lossy()
        );
        let js = json!({
            "address": addr,
            "accountKeys": AccountKeys::from((CredentialIndex{index: cc.key_index.unwrap()}, acc_data)),
            "credentials": versioned_credentials,
            "commitmentsRandomness": randomness_map,
        });
        if let Err(e) = output_possibly_encrypted(&cc.keys_out, &js) {
            eprintln!("Could not output (encrypted) account keys because: {}", e);
            return;
        }
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
        println!(
            "Generated fresh verification and signature key of the account to be encrypted and \
             written to file {}.",
            cc.keys_out.to_string_lossy()
        );
        if let Err(e) = output_possibly_encrypted(&cc.keys_out, &account_data_json) {
            eprintln!("Could not output (encrypted) account keys because: {}", e);
            return;
        }
    }

    let cdi_json_value = match new_or_existing {
        Left(tt) => to_value(&Versioned::new(VERSION_0, AccountCredentialMessage {
            message_expiry: tt,
            credential:     cdi,
        }))
        .expect("Cannot fail."),
        Right(_) => to_value(&Versioned::new(VERSION_0, cdi)).expect("Cannot fail"),
    };
    match write_json_to_file(&cc.out, &cdi_json_value) {
        Ok(_) => println!("Wrote transaction payload to JSON file."),
        Err(e) => {
            eprintln!("Could not JSON write to file because {}", e);
        }
    }
}
