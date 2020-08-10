use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::*;
use dialoguer::{Checkboxes, Input, Select};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use either::Either::Left;
use elgamal::{PublicKey, SecretKey};
use id::{account_holder::*, identity_provider::*, secret_sharing::*, types::*};
use pairing::bls12_381::{Bls12, G1};
use rand::*;
use std::{
    cmp::max,
    collections::btree_map::BTreeMap,
    convert::TryFrom,
    fs::File,
    io::{self, Write},
    path::PathBuf,
};
use structopt::StructOpt;

static IP_NAME_PREFIX: &str = "identity_provider-";
static AR_NAME_PREFIX: &str = "AR-";

fn mk_ip_filename(path: &PathBuf, n: usize) -> (PathBuf, PathBuf) {
    let mut public = path.clone();
    public.push(format!("{}{}.pub.json", IP_NAME_PREFIX, n));
    let mut private = path.clone();
    private.push(format!("{}{}.json", IP_NAME_PREFIX, n));
    (public, private)
}

fn mk_ip_description(n: usize) -> Description {
    let mut s = IP_NAME_PREFIX.to_string();
    s.push_str(&n.to_string());
    mk_dummy_description(s)
}

// Generate name for the n-th anonymity revoker.
// Returns the pair for public and public + private data.
fn mk_ar_filename(path: &PathBuf, n: u32) -> (PathBuf, PathBuf) {
    let mut public = path.clone();
    public.push(format!("{}{}.pub.json", AR_NAME_PREFIX, n));
    let mut private = path.clone();
    private.push(format!("{}{}.json", AR_NAME_PREFIX, n));
    (public, private)
}

fn mk_ar_description(n: u32) -> Description {
    let mut s = AR_NAME_PREFIX.to_string();
    s.push_str(&n.to_string());
    mk_dummy_description(s)
}

/// Read validTo from stdin in format YYYYMM and return YearMonth
fn read_validto() -> io::Result<YearMonth> {
    let input: String = Input::new()
        .with_prompt("Enter valid to (YYYYMM)")
        .interact()?;
    match parse_yearmonth(&input) {
        Some(ym) => Ok(ym),
        None => panic!("Unable to parse YYYYMM"),
    }
}

#[derive(StructOpt)]
struct CreateChi {
    #[structopt(long = "out")]
    out: Option<PathBuf>,
}

#[derive(StructOpt)]
struct StartIp {
    #[structopt(long = "chi", help = "File with input credential holder information.")]
    chi: PathBuf,
    #[structopt(long = "ips", help = "File with a list of identity providers.", default_value = IDENTITY_PROVIDERS)]
    identity_providers: PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(long = "private", help = "File to write the private ACI data to.")]
    private: Option<PathBuf>,
    #[structopt(
        long = "public",
        help = "File to write the public data to be sent to the identity provider."
    )]
    public: Option<PathBuf>,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global: PathBuf,
}

#[derive(StructOpt)]
struct GenerateIps {
    #[structopt(
        long = "num",
        help = "Number of identity providers to generate.",
        default_value = "10"
    )]
    num: usize,
    #[structopt(
        long = "num-ars",
        help = "Number of anonymity revokers to generate.",
        default_value = "5"
    )]
    num_ars: u32,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global: PathBuf,
    #[structopt(
        long = "key-capacity",
        help = "Size of the identity provider key. The length of this key limits the number of \
                attributes the identity provider can sign.",
        default_value = "30"
    )]
    key_capacity: usize,
    #[structopt(
        long = "out-dir",
        help = "Directory to write the generate identity providers to.",
        default_value = "database"
    )]
    output_dir: PathBuf,
}

#[derive(StructOpt)]
struct GenerateGlobal {
    #[structopt(
        long = "out-file",
        help = "File to write the generated global parameters to.",
        default_value = "database/global.json"
    )]
    output_file: PathBuf,
}

#[derive(StructOpt)]
struct IpSignPio {
    #[structopt(
        long = "pio",
        help = "File with input pre-identity object information."
    )]
    pio: PathBuf,
    #[structopt(
        long = "ip-data",
        help = "File with all information about the identity provider (public and private)."
    )]
    ip_data: PathBuf,
    #[structopt(long = "out", help = "File to write the signed identity object to.")]
    out_file: Option<PathBuf>,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global: PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
}

#[derive(StructOpt)]
struct CreateCredential {
    #[structopt(
        long = "id-object",
        help = "File with the JSON encoded identity object."
    )]
    id_object: PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global: PathBuf,
    #[structopt(
        long = "ip-info",
        help = "File with the JSON encoded information about the identity provider."
    )]
    ip_info: PathBuf,
    #[structopt(
        long = "private",
        help = "File with private credential holder information used to generate the identity \
                object."
    )]
    private: PathBuf,
    #[structopt(
        long = "account",
        help = "File with existing account private info (verification and signature keys). If not \
                present a fresh key-pair will be generated."
    )]
    account: Option<PathBuf>,
    #[structopt(
        long = "bin-out",
        help = "File to output the binary transaction payload to."
    )]
    bin_out: Option<PathBuf>,
    #[structopt(long = "out", help = "File to output the JSON transaction payload to.")]
    out: Option<PathBuf>,
    #[structopt(
        long = "keys-out",
        help = "File to output account keys.",
        default_value = "account_keys.json"
    )]
    keys_out: PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
}

#[derive(StructOpt)]
struct ExtendIpList {
    #[structopt(
        long = "ips-meta-file",
        help = "File with identity providers with metadata.",
        default_value = "identity-providers-with-metadata.json"
    )]
    ips_with_metadata: PathBuf,
    #[structopt(
        long = "ip",
        help = "File with public information about the new identity provider"
    )]
    ip: PathBuf,
    #[structopt(
        long = "metadata",
        help = "File with metadata that should be included with the identity provider."
    )]
    metadata: PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of all known anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "selected-ars",
        help = "List of identifiers for anonymity revokers that should be included with the \
                identity provider."
    )]
    selected_ars: Vec<u32>,
}

#[derive(StructOpt)]
#[structopt(
    about = "Prototype client showcasing ID layer interactions.",
    author = "Concordium",
    version = "0.36787944117"
)]
enum IdClient {
    #[structopt(
        name = "create-chi",
        about = "Create new credential holder information."
    )]
    CreateChi(CreateChi),
    #[structopt(
        name = "start-ip",
        about = "Generate data to send to the identity provider to sign and verify."
    )]
    StartIp(StartIp),
    #[structopt(
        name = "generate-ips",
        about = "Generate given number of identity providers and anonymity revokers. With public \
                 and private keys."
    )]
    GenerateIps(GenerateIps),
    #[structopt(name = "generate-global")]
    GenerateGlobal(GenerateGlobal),
    #[structopt(
        name = "ip-sign-pio",
        about = "Act as the identity provider, checking and signing a pre-identity object."
    )]
    IpSignPio(IpSignPio),
    #[structopt(
        name = "create-credential",
        about = "Take the identity object, select attributes to reveal and create a credential \
                 object to deploy on chain."
    )]
    CreateCredential(CreateCredential),
    #[structopt(
        name = "extend-ip-list",
        about = "Extend the list of identity providers as served by the wallet-proxy."
    )]
    ExtendIpList(ExtendIpList),
}

fn main() {
    let app = IdClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let client = IdClient::from_clap(&matches);
    use IdClient::*;
    match client {
        CreateChi(chi) => handle_create_chi(chi),
        StartIp(ip) => handle_start_ip(ip),
        GenerateIps(ips) => handle_generate_ips(ips),
        GenerateGlobal(gl) => handle_generate_global(gl),
        IpSignPio(isp) => handle_act_as_ip(isp),
        CreateCredential(cc) => handle_create_credential(cc),
        ExtendIpList(eil) => handle_extend_ip_list(eil),
    }
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct IpsWithMetadata {
    #[serde(rename = "metadata")]
    metadata: IpMetadata,
    #[serde(rename = "ipInfo")]
    ip_info: IpInfo<Bls12>,
    #[serde(rename = "arsInfos")]
    ars_infos: BTreeMap<ArIdentity, ArInfo<G1>>,
}

fn handle_extend_ip_list(eil: ExtendIpList) {
    let mut existing_db = {
        if eil.ips_with_metadata.exists() {
            match read_json_from_file::<_, Vec<IpsWithMetadata>>(eil.ips_with_metadata.clone()) {
                Ok(v) => v,
                Err(x) => {
                    eprintln!("Could not decode file because {}", x);
                    return;
                }
            }
        } else {
            Vec::new()
        }
    };

    let metadata = match read_json_from_file(eil.metadata) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not decode metadata file because {}", x);
            return;
        }
    };

    let ip_info = match read_identity_provider(eil.ip) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not decode identity provider because {}", x);
            return;
        }
    };

    let all_ars_infos = match read_anonymity_revokers(eil.anonymity_revokers) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not decode anonymity revokers file because {}", x);
            return;
        }
    };

    let mut selected_ars = BTreeMap::new();
    for ar_id in eil.selected_ars {
        match ArIdentity::try_from(ar_id) {
            Err(err) => {
                eprintln!("{} is not a valid ArIdentity: {}", ar_id, err);
                return;
            }
            Ok(ar_id) => {
                if let Some(ar) = all_ars_infos.anonymity_revokers.get(&ar_id) {
                    let _ = selected_ars.insert(ar_id, ar.clone());
                } else {
                    eprintln!("Selected AR {} not found.", ar_id);
                    return;
                }
            }
        }
    }
    existing_db.push(IpsWithMetadata {
        ip_info,
        metadata,
        ars_infos: selected_ars,
    });
    if let Err(err) = write_json_to_file(eil.ips_with_metadata, &existing_db) {
        eprintln!("Could not write output due to {}", err);
    } else {
        println!("Done.")
    }
}

/// Read the identity object, select attributes to reveal and create a
/// transaction.
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
    let atts: Vec<usize> = match Checkboxes::new()
        .with_prompt("Select which attributes you wish to reveal")
        .items(&alist_items)
        .interact()
    {
        Ok(idxs) => idxs,
        Err(x) => {
            eprintln!("You need to select which attributes you want. {}", x);
            return;
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

    // We now generate or read account verification/signature key pair.
    let mut known_acc = false;
    let acc_data = {
        if let Some(acc_data_file) = cc.account {
            match read_json_from_file(acc_data_file) {
                Ok(acc_data) => {
                    known_acc = true;
                    acc_data
                }
                Err(e) => {
                    eprintln!(
                        "Could not read account data from provided file because {}",
                        e
                    );
                    return;
                }
            }
        } else {
            let mut csprng = thread_rng();
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

            AccountData {
                keys,
                existing: Left(SignatureThreshold(2)),
            }
        }
    };

    if !known_acc {
        println!(
            "Generated fresh verification and signature key of the account to file \
             account_keys.json"
        );
        write_json_to_file(&cc.keys_out, &acc_data).ok();
    }

    // finally we also read the credential holder information with secret keys
    // which we need to generate CDI.
    // This file should also contain the public keys of the identity provider who
    // signed the object.
    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = match read_id_use_data(&cc.private) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not read CHI object because {}", x);
            return;
        }
    };

    // We ask what regid index they would like to use.
    let x = match Input::new().with_prompt("Index").interact() {
        Ok(x) => x,
        Err(_) => 0, // default index
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

    let context = IPContext::new(&ip_info, &ars, &global_ctx);

    let cdi = create_credential(context, &id_object, &id_use_data, x, policy, &acc_data);

    let cdi = match cdi {
        Ok(cdi) => cdi,
        Err(x) => {
            eprintln!("Could not generate the credential because {}", x);
            return;
        }
    };

    let versioned_cdi = Versioned::new(VERSION_0, cdi);

    // Double check that the generated CDI is going to be successfully validated.
    // let checked = verify_cdi(&global_ctx, &ip_info, &cdi);
    // if let Err(e) = checked {
    //     eprintln!(
    //         "Something went terribly wrong and the generated CDI is not valid
    // because {}",         e
    //     );
    //     return;
    // };

    // Now simply output the credential object in the transaction format
    // accepted by the simple-client for sending transactions.

    if let Some(json_file) = cc.out {
        match write_json_to_file(json_file, &versioned_cdi) {
            Ok(_) => println!("Wrote transaction payload to JSON file."),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                output_json(&versioned_cdi);
            }
        }
    }
    if let Some(bin_file) = cc.bin_out {
        match File::create(&bin_file) {
            // This is a bit stupid, we should write directly to the sink.
            Ok(mut file) => match file.write_all(&to_bytes(&versioned_cdi)) {
                Ok(_) => println!("Wrote binary data to provided file."),
                Err(e) => {
                    eprintln!("Could not write binary to file because {}", e);
                }
            },
            Err(e) => {
                eprintln!("Could not write binary to file because {}", e);
            }
        }
    }
}

/// Create a new CHI object (essentially new idCredPub and idCredSec).
fn handle_create_chi(cc: CreateChi) {
    let mut csprng = thread_rng();
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };
    if let Some(filepath) = cc.out {
        match write_json_to_file(filepath, &ah_info) {
            Ok(()) => println!("Wrote CHI to file."),
            Err(_) => {
                eprintln!("Could not write to file. The generated information is");
                output_json(&ah_info);
            }
        }
    } else {
        println!("Generated account holder information.");
        output_json(&ah_info)
    }
}

/// Act as the identity provider. Read the pre-identity object and load the
/// private information of the identity provider, check and sign the
/// pre-identity object to generate the identity object to send back to the
/// account holder.
fn handle_act_as_ip(aai: IpSignPio) {
    let pio = match read_pre_identity_object(&aai.pio) {
        Ok(pio) => pio,
        Err(e) => {
            eprintln!("Could not read file because {}", e);
            return;
        }
    };
    let (ip_info, ip_sec_key) = match read_json_from_file::<_, IpData<Bls12>>(&aai.ip_data) {
        Ok(ip_data) => (ip_data.public_ip_info, ip_data.ip_secret_key),
        Err(x) => {
            eprintln!("Could not read identity issuer information because {}", x);
            return;
        }
    };

    let valid_to = match read_validto() {
        Ok(ym) => ym,
        Err(e) => {
            eprintln!("Could not read credential expiry because {}", e);
            return;
        }
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(aai.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    // all known anonymity revokers.
    let ars = {
        if let Ok(ars) = read_anonymity_revokers(aai.anonymity_revokers) {
            ars.anonymity_revokers
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let created_at = YearMonth::now();

    let tags = {
        match Checkboxes::new()
            .with_prompt("Select attributes:")
            .items(&ATTRIBUTE_NAMES)
            .interact()
        {
            Ok(idxs) => idxs,
            Err(x) => {
                eprintln!("You have to choose some attributes. Terminating. {}", x);
                return;
            }
        }
    };

    let alist = {
        let mut alist: BTreeMap<AttributeTag, ExampleAttribute> = BTreeMap::new();
        for idx in tags {
            match Input::new().with_prompt(ATTRIBUTE_NAMES[idx]).interact() {
                Err(e) => {
                    eprintln!("You need to provide integer input: {}", e);
                    return;
                }
                Ok(s) => {
                    let _ = alist.insert(AttributeTag(idx as u8), s);
                }
            }
        }
        alist
    };

    let attributes = AttributeList {
        valid_to,
        created_at,
        max_accounts: 238,
        alist,
        _phantom: Default::default(),
    };
    let context = IPContext::new(&ip_info, &ars, &global_ctx);
    let vf = verify_credentials(&pio, context, &attributes, &ip_sec_key);

    match vf {
        Ok(signature) => {
            let id_object = IdentityObject {
                pre_identity_object: pio,
                alist: attributes,
                signature,
            };
            let ver_id_object = Versioned::new(VERSION_0, id_object);
            let signature = &ver_id_object.value.signature;
            println!("Successfully checked pre-identity data.");
            if let Some(signed_out_path) = aai.out_file {
                if write_json_to_file(signed_out_path.clone(), &ver_id_object).is_ok() {
                    println!(
                        "Wrote signed identity object to file {}",
                        signed_out_path.display()
                    );
                } else {
                    println!(
                        "Could not write Identity object to file. The signature is: {}",
                        base16_encode_string(signature)
                    );
                }
            } else {
                println!("The signature is: {}", base16_encode_string(signature));
            }
        }
        Err(r) => eprintln!("Could not verify pre-identity object {:?}", r),
    }
}

fn handle_start_ip(sip: StartIp) {
    let chi = {
        if let Ok(chi) = read_json_from_file(&sip.chi) {
            chi
        } else {
            eprintln!("Could not read credential holder information.");
            return;
        }
    };
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::generate(&mut csprng);

    // the chosen account credential information
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    // now choose an identity provider.
    let ips = {
        if let Ok(ips) = read_identity_providers(sip.identity_providers) {
            ips
        } else {
            eprintln!("Cannot read identity providers from the database. Terminating.");
            return;
        }
    };

    // names of identity providers the user can choose from, together with the
    // names of anonymity revokers associated with them
    let mut ips_names = Vec::with_capacity(ips.identity_providers.len());
    for (_, v) in ips.identity_providers.iter() {
        ips_names.push(format!(
            "Identity provider {}, {}",
            &v.ip_identity, v.ip_description.name
        ))
    }

    let ip_info = {
        if let Ok(ip_info_idx) = Select::new()
            .with_prompt("Choose identity provider")
            .items(&ips_names)
            .default(0)
            .interact()
        {
            ips.identity_providers
                .get(&IpIdentity(ip_info_idx as u32))
                .unwrap()
                .clone()
        } else {
            eprintln!("You have to choose an identity provider. Terminating.");
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

    let mrs: Vec<&str> = ars
        .anonymity_revokers
        .values()
        .map(|x| x.ar_description.name.as_str())
        .collect();

    let ar_info = Checkboxes::new()
        .with_prompt("Choose anonymity revokers")
        .items(&mrs)
        .interact()
        .unwrap();
    let num_ars = ar_info.len();
    if ar_info.is_empty() {
        eprintln!("You need to select an AR.");
        return;
    }
    let keys = ars.anonymity_revokers.keys().collect::<Vec<_>>();
    let mut choice_ars = BTreeMap::new();
    for idx in ar_info.into_iter() {
        choice_ars.insert(
            *keys[idx],
            ars.anonymity_revokers
                .get(keys[idx])
                .expect("AR should exist by construction.")
                .clone(),
        );
    }

    let threshold = {
        if let Ok(threshold) = Select::new()
            .with_prompt("Revocation threshold")
            .items(&(1..=num_ars).collect::<Vec<usize>>())
            .default(1)
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
        }
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(sip.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    let context = IPContext::new(&ip_info, &choice_ars, &global_ctx);
    // and finally generate the pre-identity object
    // we also retrieve the randomness which we must keep private.
    // This randomness must be used
    let (pio, randomness) = generate_pio(&context, threshold, &aci)
        .expect("Generating the pre-identity object should succeed.");

    // the only thing left is to output all the information

    let id_use_data = IdObjectUseData { aci, randomness };
    let ver_id_use_data = Versioned::new(VERSION_0, id_use_data);
    if let Some(aci_out_path) = sip.private {
        if write_json_to_file(aci_out_path, &ver_id_use_data).is_ok() {
            println!("Wrote ACI and randomness to file.");
        } else {
            println!("Could not write ACI data to file. Outputting to standard output.");
            output_json(&ver_id_use_data);
        }
    } else {
        output_json(&ver_id_use_data);
    }

    let ver_pio = Versioned::new(VERSION_0, pio);
    if let Some(pio_out_path) = sip.public {
        if write_json_to_file(pio_out_path, &ver_pio).is_ok() {
            println!("Wrote PIO data to file.");
        } else {
            println!("Could not write PIO data to file. Outputting to standard output.");
            output_json(&ver_pio);
        }
    } else {
        output_json(&ver_pio);
    }
}

/// Generate identity providers with public and private information as well as
/// anonymity revokers. For now we generate identity providers with names
/// IP_PREFIX-i.json and its associated anonymity revoker has name
/// AR_PRFEFIX-i.json.
fn handle_generate_ips(gip: GenerateIps) {
    let mut csprng = thread_rng();
    let num: usize = gip.num;
    let num_ars: u32 = gip.num_ars;

    // First generate anonymity revokers with ids 1..num-ars.
    println!("Generating {} anonymity revokers.", num_ars);
    let mut ar_identities = Vec::with_capacity(num_ars as usize);

    // we also read the global context from another json file (called
    // global.context). We need the generator from there.
    let global_ctx = {
        if let Some(gc) = read_global_context(gip.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };
    {
        let ar_base = global_ctx.generator;
        let mut all_ars = ArInfos {
            anonymity_revokers: BTreeMap::new(),
        };

        for i in 1..=num_ars {
            let ar_secret_key = SecretKey::generate(&ar_base, &mut csprng);
            let ar_public_key = PublicKey::from(&ar_secret_key);
            let ar_identity = ArIdentity::try_from(i).unwrap();
            let public_ar_info = ArInfo {
                ar_identity,
                ar_description: mk_ar_description(i),
                ar_public_key,
            };
            ar_identities.push(ar_identity);
            let (ar_pub_fname, ar_fname) = mk_ar_filename(&gip.output_dir, i);
            let ar_data = ArData {
                public_ar_info,
                ar_secret_key,
            };
            println!("writing AR({}) in file {:?}", i, ar_fname);
            if let Err(err) = write_json_to_file(&ar_fname, &ar_data) {
                eprintln!("Could not write anonymity revoker {}: {}", i, err);
                return;
            }
            println!("writing public AR({}) in file {:?}", i, ar_fname);
            let ver_public_ar_info = Versioned::new(VERSION_0, ar_data.public_ar_info.clone());
            if let Err(err) = write_json_to_file(&ar_pub_fname, &ver_public_ar_info) {
                eprintln!("Could not write anonymity revoker {}: {}", i, err);
                return;
            }
            let _ = all_ars
                .anonymity_revokers
                .insert(ar_identity, ar_data.public_ar_info);
        }

        let mut ars_path = gip.output_dir.clone();
        ars_path.push("anonymity_revokers.json");
        let ver_all_ars = Versioned::new(VERSION_0, all_ars);
        if let Err(err) = write_json_to_file(ars_path.clone(), &ver_all_ars) {
            eprintln!("Could not write out anonymity revokers: {}", err);
            return;
        } else {
            println!("Wrote out anonymity revokers to {}", ars_path.display())
        }
    }

    println!("Generating {} identity providers.", num);
    let mut all_idps = IpInfos {
        identity_providers: BTreeMap::new(),
    };
    for id in 0..num {
        // generate an identity provider and for each
        // identity provider three anonymity revokers
        let (ip_fname_pub, ip_fname) = mk_ip_filename(&gip.output_dir, id);

        // TODO: hard-coded length of the key for now, but should be changed
        // based on the maximum length of the attribute list
        let id_secret_key =
            ps_sig::secret::SecretKey::<Bls12>::generate(gip.key_capacity, &mut csprng);
        let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

        let ip_id = IpIdentity(id as u32);
        let ip_info = IpInfo {
            ip_identity:    ip_id,
            ip_description: mk_ip_description(id),
            ip_verify_key:  id_public_key,
        };
        let full_info = IpData {
            ip_secret_key:  id_secret_key,
            public_ip_info: ip_info,
        };
        println!("writing ip_{} in file {}", id, ip_fname.display());
        if let Err(err) = write_json_to_file(&ip_fname, &full_info) {
            eprintln!("Could not write out identity provider: {}", err);
            return;
        }
        let versioned_ip_info_public = Versioned::new(VERSION_0, full_info.public_ip_info.clone());
        println!(
            "writing ip_{} public data in file {}",
            id,
            ip_fname_pub.display()
        );
        if let Err(err) = write_json_to_file(&ip_fname_pub, &versioned_ip_info_public) {
            eprintln!("Could not write out identity provider: {}", err);
            return;
        }
        all_idps
            .identity_providers
            .insert(ip_id, full_info.public_ip_info);
    }
    let mut ips_path = gip.output_dir;
    ips_path.push("identity_providers.json");
    let ver_all_idps = Versioned::new(VERSION_0, all_idps);
    if let Err(err) = write_json_to_file(ips_path, &ver_all_idps) {
        eprintln!("Could not write out list of identity providers: {}", err);
        return;
    }
    println!("Done.");
}

/// Generate the global context.
fn handle_generate_global(gl: GenerateGlobal) {
    let mut csprng = thread_rng();
    let gc = GlobalContext::<ExampleCurve>::generate(&mut csprng);
    let vgc = Versioned::new(VERSION_0, gc);
    if let Err(err) = write_json_to_file(&gl.output_file, &vgc) {
        eprintln!("Could not write global parameters because {}.", err);
    }
}
