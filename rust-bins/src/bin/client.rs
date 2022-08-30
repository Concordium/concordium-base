use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{
    types::{Amount, CredentialIndex, KeyIndex, KeyPair, TransactionTime},
    *,
};
use dialoguer::{Input, MultiSelect, Select};
use dodis_yampolskiy_prf as prf;
use ed25519_dalek as ed25519;
use either::Either::{Left, Right};
use elgamal::{PublicKey, SecretKey};
use id::{
    account_holder::*,
    constants::{ArCurve, IpPairing},
    curve_arithmetic::*,
    identity_provider::*,
    secret_sharing::*,
    types::*,
};
use key_derivation::{words_to_seed, ConcordiumHdWallet, Net};
use pairing::bls12_381::{Bls12, G1};
use rand::*;
use serde_json::{json, to_value};
use std::{
    cmp::max,
    collections::btree_map::BTreeMap,
    convert::TryFrom,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

use pedersen_scheme::Value as PedersenValue;

static IP_NAME_PREFIX: &str = "identity_provider-";
static AR_NAME_PREFIX: &str = "AR-";

fn mk_ip_filename(path: &Path, n: usize) -> (PathBuf, PathBuf) {
    let mut public = path.to_path_buf();
    public.push(format!("{}{}.pub.json", IP_NAME_PREFIX, n));
    let mut private = path.to_path_buf();
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
fn mk_ar_filename(path: &Path, n: u32) -> (PathBuf, PathBuf) {
    let mut public = path.to_path_buf();
    public.push(format!("{}{}.pub.json", AR_NAME_PREFIX, n));
    let mut private = path.to_path_buf();
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
struct CreateHdWallet {
    #[structopt(
        long = "out",
        help = "Optional file to write the hd wallet to. If not provided, the hd wallet JSON will \
                be written to standard output."
    )]
    out:     Option<PathBuf>,
    #[structopt(long = "testnet")]
    testnet: bool,
}

#[derive(StructOpt)]
struct GenerateIdRecoveryRequest {
    #[structopt(
        long = "ip-info",
        help = "File with information about the identity provider."
    )]
    ip_info:      PathBuf,
    #[structopt(
        long = "request-out",
        help = "File to write the request to that is to be sent to the identity provider."
    )]
    request_file: PathBuf,
    #[structopt(
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:       PathBuf,
    #[structopt(long = "chi", help = "File with input credential holder information.")]
    chi:          PathBuf,
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
        long = "cryptographic-parameters",
        help = "File with cryptographic parameters."
    )]
    global:  PathBuf,
}

#[derive(StructOpt)]
struct CreateChi {
    #[structopt(long = "out")]
    out:                     Option<PathBuf>,
    #[structopt(
        long = "hd-wallet",
        help = "File with hd wallet.",
        requires = "identity-index"
    )]
    hd_wallet:               Option<PathBuf>,
    #[structopt(
        long = "identity-provider-index",
        help = "Identity provider index.",
        requires = "hd-wallet"
    )]
    identity_provider_index: Option<u32>,
    #[structopt(
        long = "identity-index",
        help = "Identity index.",
        requires = "hd-wallet"
    )]
    identity_index:          Option<u32>,
}

#[derive(StructOpt)]
struct CreateIdUseData {
    #[structopt(long = "out")]
    out:                     Option<PathBuf>,
    #[structopt(
        long = "hd-wallet",
        help = "File with hd wallet.",
        requires = "identity-index"
    )]
    hd_wallet:               Option<PathBuf>,
    #[structopt(
        long = "identity-provider-index",
        help = "Identity provider index.",
        requires = "hd-wallet"
    )]
    identity_provider_index: Option<u32>,
    #[structopt(
        long = "identity-index",
        help = "Identity index.",
        requires = "hd-wallet"
    )]
    identity_index:          Option<u32>,
}

#[derive(StructOpt)]
struct StartIp {
    #[structopt(long = "chi", help = "File with input credential holder information.")]
    chi:                PathBuf,
    #[structopt(long = "ips", help = "File with a list of identity providers.", default_value = IDENTITY_PROVIDERS)]
    identity_providers: PathBuf,
    #[structopt(
        long = "ip",
        help = "Which identity provider to choose. If not given an interactive choice will be \
                provided."
    )]
    identity_provider:  Option<u32>,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(long = "private", help = "File to write the private ACI data to.")]
    private:            Option<PathBuf>,
    #[structopt(
        long = "public",
        help = "File to write the public data to be sent to the identity provider."
    )]
    public:             Option<PathBuf>,
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
struct StartIpV1 {
    #[structopt(
        long = "id-use-data",
        help = "File with input credential holder information and blinding randomness."
    )]
    id_use_data:        PathBuf,
    #[structopt(long = "ips", help = "File with a list of identity providers.", default_value = IDENTITY_PROVIDERS)]
    identity_providers: PathBuf,
    #[structopt(
        long = "ip",
        help = "Which identity provider to choose. If not given an interactive choice will be \
                provided."
    )]
    identity_provider:  Option<u32>,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "public",
        help = "File to write the public data to be sent to the identity provider."
    )]
    public:             Option<PathBuf>,
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
struct GenerateIps {
    #[structopt(
        long = "num",
        help = "Number of identity providers to generate.",
        default_value = "5",
        env = "NUM_IPS"
    )]
    num:          usize,
    #[structopt(
        long = "num-ars",
        help = "Number of anonymity revokers to generate.",
        default_value = "5",
        env = "NUM_ARS"
    )]
    num_ars:      u32,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json",
        env = "GLOBAL_FILE"
    )]
    global:       PathBuf,
    #[structopt(
        long = "key-capacity",
        help = "Size of the identity provider key. The length of this key limits the number of \
                attributes the identity provider can sign.",
        default_value = "30",
        env = "KEY_CAPACITY"
    )]
    key_capacity: usize,
    #[structopt(
        long = "out-dir",
        help = "Directory to write the generate identity providers to.",
        default_value = "database",
        env = "OUT_DIR"
    )]
    output_dir:   PathBuf,
}

#[derive(StructOpt)]
struct GenerateGlobal {
    #[structopt(
        long = "out-file",
        help = "File to write the generated global parameters to.",
        default_value = "database/global.json",
        env = "OUT_FILE"
    )]
    output_file:    PathBuf,
    #[structopt(
        long = "string",
        help = "Genesis string to add to the global context.",
        default_value = "genesis_string",
        env = "GENESIS_STRING"
    )]
    genesis_string: String,
    #[structopt(
        long = "seed",
        help = "Seed file to use when generating group generators.",
        env = "SEED_FILE"
    )]
    seed_file:      Option<PathBuf>,
}

#[derive(StructOpt)]
struct IpSignPio {
    #[structopt(
        long = "pio",
        help = "File with input pre-identity object information."
    )]
    pio:                PathBuf,
    #[structopt(
        long = "ip-data",
        help = "File with all information about the identity provider (public and private)."
    )]
    ip_data:            PathBuf,
    #[structopt(long = "out", help = "File to write the signed identity object to.")]
    out_file:           Option<PathBuf>,
    #[structopt(
        long = "bin-out",
        help = "File to output the binary transaction payload to (regarding the initial account)."
    )]
    bin_out:            Option<PathBuf>,
    #[structopt(
        long = "initial-cdi-out",
        help = "File to output the JSON transaction payload to (regarding the initial account)."
    )]
    out_icdi:           Option<PathBuf>,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global:             PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "expiry",
        help = "Expiry time of the initial credential message. In seconds from __now__.",
        required = true
    )]
    expiry:             u64,
    #[structopt(
        long = "id-object-expiry",
        help = "Expiry time of the identity object message. As YYYYMM."
    )]
    id_expiry:          Option<YearMonth>,
    #[structopt(
        long = "no-attributes",
        help = "Do not select any attributes to reveal."
    )]
    no_attributes:      bool,
}

#[derive(StructOpt)]
struct IpSignPioV1 {
    #[structopt(
        long = "pio",
        help = "File with input pre-identity object information."
    )]
    pio:                PathBuf,
    #[structopt(
        long = "ip-data",
        help = "File with all information about the identity provider (public and private)."
    )]
    ip_data:            PathBuf,
    #[structopt(long = "out", help = "File to write the signed identity object to.")]
    out_file:           Option<PathBuf>,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json"
    )]
    global:             PathBuf,
    #[structopt(
        long = "ars",
        help = "File with a list of anonymity revokers..",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "id-object-expiry",
        help = "Expiry time of the identity object message. As YYYYMM."
    )]
    id_expiry:          Option<YearMonth>,
    #[structopt(
        long = "no-attributes",
        help = "Do not select any attributes to reveal."
    )]
    no_attributes:      bool,
}

#[derive(StructOpt)]
struct CreateCredential {
    #[structopt(long = "hd-wallet", help = "File with hd wallet.")]
    hd_wallet:          Option<PathBuf>,
    #[structopt(
        long = "identity-index",
        help = "The index of the identity to create the credential from.",
        requires = "hd-wallet"
    )]
    identity_index:     Option<u32>,
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
                object.",
        required_unless = "hd-wallet",
        conflicts_with = "hd-wallet"
    )]
    private:            Option<PathBuf>,
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
    out:                Option<PathBuf>,
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
    #[structopt(
        long = "index",
        help = "Index of the account/credential to be created."
    )]
    index:              Option<u8>,
}

#[derive(StructOpt)]
struct VerifyCredential {
    #[structopt(
        long = "credential",
        help = "File with the JSON encoded credential object."
    )]
    credential:         PathBuf,
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
        long = "ars",
        help = "File with a list of anonymity revokers.",
        default_value = "database/anonymity_revokers.json"
    )]
    anonymity_revokers: PathBuf,
    #[structopt(
        long = "expiry",
        help = "Expiry time of the credential message. NB: This is seconds since the unix epoch.",
        required_unless = "account",
        conflicts_with = "account"
    )]
    expiry:             Option<TransactionTime>,
    #[structopt(
        long = "account",
        help = "Address of the account onto which the credential will be deployed."
    )]
    account:            Option<AccountAddress>,
}

#[derive(StructOpt)]
struct ExtendIpList {
    #[structopt(
        long = "ips-meta-file",
        help = "File with identity providers with metadata.",
        default_value = "identity-providers-with-metadata.json"
    )]
    ips_with_metadata:  PathBuf,
    #[structopt(
        long = "ip",
        help = "File with public information about the new identity provider"
    )]
    ip:                 PathBuf,
    #[structopt(
        long = "metadata",
        help = "File with metadata that should be included with the identity provider."
    )]
    metadata:           PathBuf,
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
    selected_ars:       Vec<u32>,
}

#[derive(StructOpt)]
/// Construct a genesis account from a multitude of files. In the main genesis
/// process the credentials will be created by the desktop wallet, and baker
/// keys by another tool. These all need to be combined into a single account.
struct MakeAccount {
    #[structopt(
        long = "credential",
        help = "List of credentials that make the account. The order is significant. Indices will \
                be assigned according to it."
    )]
    credentials: Vec<PathBuf>,
    #[structopt(long = "amount", help = "Balance of the account. Specified in GTU.")]
    balance:     Amount,
    #[structopt(name = "threshold", long = "threshold", help = "Account threshold.")]
    threshold:   u8,
    #[structopt(
        name = "baker-keys",
        long = "baker-keys",
        help = "If the account is a baker, its baker keys and baker id.",
        requires_all = &["stake"]
    )]
    baker_keys:  Option<PathBuf>,
    #[structopt(
        name = "stake",
        long = "stake",
        help = "If a baker, its initial stake in GTU.",
        requires_all = &["baker-keys"]
    )]
    stake:       Option<Amount>,
    #[structopt(
        name = "no-restake",
        long = "no-restake",
        help = "If a baker, do not restake earnings automatically.",
        requires_all = &["baker-keys", "stake"]
    )]
    no_restake:  bool,
    #[structopt(long = "out", help = "The file to output the account data into.")]
    out:         PathBuf,
}

// This is the type of credentials that is output by the desktop wallet for
// genesis creation.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct GenesisCredentialInput {
    credential:        AccountCredentialWithoutProofs<ArCurve, ExampleAttribute>,
    generated_address: AccountAddress,
}

#[derive(StructOpt)]
#[structopt(
    about = "Prototype client showcasing ID layer interactions.",
    author = "Concordium",
    version = "2.1.0"
)]
enum IdClient {
    #[structopt(
        name = "create-hd-wallet",
        about = "Create hd-wallet from a list of 24 BIP39 words."
    )]
    CreateHdWallet(CreateHdWallet),
    #[structopt(
        name = "create-chi",
        about = "Create new credential holder information."
    )]
    CreateChi(CreateChi),
    #[structopt(
        name = "create-id-use-data",
        about = "Create new id use data, either deterministically from a hd wallet, or using \
                 system randomness."
    )]
    CreateIdUseData(CreateIdUseData),
    #[structopt(
        name = "start-ip",
        about = "Generate data to send to the identity provider to sign and verify."
    )]
    StartIp(StartIp),
    #[structopt(
        name = "start-ip-v1",
        about = "Generate data to send to the identity provider to sign and verify."
    )]
    StartIpV1(StartIpV1),
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
        about = "Act as the identity provider, checking and signing a version 0 pre-identity \
                 object."
    )]
    IpSignPio(IpSignPio),
    #[structopt(
        name = "ip-sign-pio-v1",
        about = "Act as the identity provider, checking and signing a version 1 pre-identity \
                 object."
    )]
    IpSignPioV1(IpSignPioV1),
    #[structopt(
        name = "create-credential",
        about = "Take the identity object, select attributes to reveal and create a credential \
                 object to deploy on chain."
    )]
    CreateCredential(CreateCredential),
    #[structopt(name = "verify-credential", about = "Verify the given credential.")]
    VerifyCredential(VerifyCredential),
    #[structopt(
        name = "extend-ip-list",
        about = "Extend the list of identity providers as served by the wallet-proxy."
    )]
    ExtendIpList(ExtendIpList),
    #[structopt(
        name = "create-genesis-account",
        about = "Create a genesis account from credentials and possibly baker information."
    )]
    MakeAccount(MakeAccount),
    #[structopt(name = "recover-identity", about = "Generate id recovery request.")]
    GenerateIdRecoveryRequest(GenerateIdRecoveryRequest),
    #[structopt(
        name = "validate-recovery-request",
        about = "Validate id recovery request."
    )]
    ValidateIdRecoveryRequest(ValidateIdRecoveryRequest),
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
        CreateHdWallet(chw) => handle_create_hd_wallet(chw),
        CreateIdUseData(iud) => handle_create_id_use_data(iud),
        StartIp(ip) => handle_start_ip(ip),
        StartIpV1(ip) => handle_start_ip_v1(ip),
        GenerateIps(ips) => handle_generate_ips(ips),
        GenerateGlobal(gl) => handle_generate_global(gl),
        IpSignPio(isp) => handle_act_as_ip(isp),
        IpSignPioV1(isp) => handle_act_as_ip_v1(isp),
        CreateCredential(cc) => handle_create_credential(cc),
        ExtendIpList(eil) => handle_extend_ip_list(eil),
        VerifyCredential(vcred) => handle_verify_credential(vcred),
        MakeAccount(macc) => handle_make_account(macc),
        GenerateIdRecoveryRequest(girr) => handle_recovery(girr),
        ValidateIdRecoveryRequest(vir) => handle_validate_recovery(vir),
    }
}

/// Construct an account out of multiple credentials and possibly baker keys.
/// This is used to construct the accounts that must go into the genesis block
/// from individual credentials.
fn handle_make_account(macc: MakeAccount) {
    if macc.credentials.is_empty() {
        eprintln!("No credentials specified. Terminating.");
        return;
    }
    let mut credentials: Vec<GenesisCredentialInput> = Vec::with_capacity(macc.credentials.len());
    for cred_file in macc.credentials.iter() {
        match read_json_from_file(cred_file) {
            Ok(c) => credentials.push(c),
            Err(e) => eprintln!("Could not parse credential: {}. Terminating.", e),
        }
    }
    let addr = credentials[0].generated_address;
    // the credentials will be given indices 0..
    let versioned_credentials = Versioned::new(
        VERSION_0,
        (0..)
            .zip(credentials.into_iter().map(|x| x.credential))
            .collect::<BTreeMap<u8, _>>(),
    );
    // if the baker keys are specified the account will be a baker, so we construct
    // the baker structure suitable for inclusion in genesis.
    let out = match macc.baker_keys {
        Some(keys_file) => {
            let mut keys = match read_json_from_file(keys_file) {
                Ok(serde_json::Value::Object(mp)) => mp,
                Ok(_) => {
                    eprintln!(
                        "The baker key file does not have the correct format. Expected an object."
                    );
                    return;
                }
                Err(e) => {
                    eprintln!("Could not read baker keys: {}", e);
                    return;
                }
            };
            keys.insert("stake".to_string(), json!(macc.stake.unwrap())); // unwrap is safe because of `required_all` directive
            keys.insert("restakeEarnings".to_string(), json!(!macc.no_restake));
            json!({
                "address": addr,
                "balance": macc.balance,
                "accountThreshold": macc.threshold,
                "credentials": versioned_credentials,
                "baker": keys,
            })
        } // and if no baker keys are given we simply combine the credentials.
        None => json!({
            "address": addr,
            "balance": macc.balance,
            "accountThreshold": macc.threshold,
            "credentials": versioned_credentials,
        }),
    };
    if let Err(e) = write_json_to_file(&macc.out, &out) {
        eprintln!("Could not output credentials: {}", e);
    }
}

fn handle_verify_credential(vcred: VerifyCredential) {
    let ip_info = match read_ip_info(vcred.ip_info) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read identity provider info because {}", err);
            return;
        }
    };

    // we also read the global context from another json file (called
    // global.context). We need commitment keys and other data in there.
    let global_ctx = {
        if let Some(gc) = read_global_context(vcred.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    let all_ars_infos = match read_anonymity_revokers(vcred.anonymity_revokers) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not decode anonymity revokers file due to {}", x);
            return;
        }
    };

    let credential = match read_credential(vcred.credential) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error reading credential: {}", e);
            return;
        }
    };

    let new_or_existing = match (vcred.expiry, vcred.account) {
        (None, None) => panic!("One of (expiry, address) is required."),
        (None, Some(addr)) => Right(addr),
        (Some(tt), None) => Left(tt),
        (Some(_), Some(_)) => panic!("Exactly one of (expiry, address) is required."),
    };

    if let Err(e) = id::chain::verify_cdi(
        &global_ctx,
        &ip_info,
        &all_ars_infos.anonymity_revokers,
        &credential,
        &new_or_existing,
    ) {
        eprintln!("Credential verification failed due to {}", e)
    } else {
        eprintln!("Credential verifies.")
    }
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct IpsWithMetadata {
    #[serde(rename = "metadata")]
    metadata:  IpMetadata,
    #[serde(rename = "ipInfo")]
    ip_info:   IpInfo<Bls12>,
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

enum SomeIdentityObject<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    IdoV0(IdentityObject<P, C, AttributeType>),
    IdoV1(IdentityObjectV1<P, C, AttributeType>),
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    HasIdentityObjectFields<P, C, AttributeType> for SomeIdentityObject<P, C, AttributeType>
{
    fn get_common_pio_fields(&self) -> CommonPioFields<P, C> {
        match self {
            SomeIdentityObject::IdoV0(ido) => ido.get_common_pio_fields(),
            SomeIdentityObject::IdoV1(ido) => ido.get_common_pio_fields(),
        }
    }

    fn get_attribute_list(&self) -> &AttributeList<C::Scalar, AttributeType> {
        match self {
            SomeIdentityObject::IdoV0(ido) => ido.get_attribute_list(),
            SomeIdentityObject::IdoV1(ido) => ido.get_attribute_list(),
        }
    }

    fn get_signature(&self) -> &ps_sig::Signature<P> {
        match self {
            SomeIdentityObject::IdoV0(ido) => ido.get_signature(),
            SomeIdentityObject::IdoV1(ido) => ido.get_signature(),
        }
    }
}

/// Read the identity object, select attributes to reveal and create a
/// transaction.
fn handle_create_credential(cc: CreateCredential) {
    let id_object = {
        match read_id_object(cc.id_object.clone()) {
            Ok(v) => SomeIdentityObject::IdoV0(v),
            Err(_) => match read_id_object_v1(cc.id_object) {
                Ok(v) => SomeIdentityObject::IdoV1(v),
                Err(x) => {
                    eprintln!("Could not read identity object because {}", x);
                    return;
                }
            },
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
    let alist = &id_object.get_attribute_list().alist;

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
        valid_to:   id_object.get_attribute_list().valid_to,
        created_at: id_object.get_attribute_list().created_at,
        policy_vec: revealed_attributes,
        _phantom:   Default::default(),
    };

    // We ask what regid index they would like to use.
    let acc_num = match cc.index {
        Some(x) => x,
        None => Input::new()
            .with_prompt("Account/credential index: ")
            .interact()
            .unwrap_or(0), // 0 is the default index
    };

    // finally we also need the credential holder information with secret keys
    // which we need to generate CDI.
    let (id_use_data, acc_data, maybe_context): (
        IdObjectUseData<Bls12, ExampleCurve>,
        CredentialData,
        Option<CredentialContext>,
    ) = match cc.private {
        Some(path) => {
            let id_use_data = match read_id_use_data(&path) {
                Ok(v) => v,
                Err(x) => {
                    eprintln!("Could not read ID use data object because: {}", x);
                    return;
                }
            };
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
            (id_use_data, acc_data, None)
        }
        None => {
            let wallet: ConcordiumHdWallet = match read_json_from_file(&cc.hd_wallet.unwrap()) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Could not read file because {}", e);
                    return;
                }
            };
            let identity_provider_index = ip_info.ip_identity.0;
            let identity_index = match cc.identity_index {
                Some(x) => x,
                None => Input::new()
                    .with_prompt("Identity index")
                    .interact()
                    .unwrap_or(0), // 0 is the default index
            };
            let prf_key: prf::SecretKey<ArCurve> =
                match wallet.get_prf_key(identity_provider_index, identity_index) {
                    Ok(prf) => prf,
                    Err(e) => {
                        eprintln!("Could not get prf key because {}", e);
                        return;
                    }
                };

            let id_cred_sec_scalar =
                match wallet.get_id_cred_sec(identity_provider_index, identity_index) {
                    Ok(scalar) => scalar,
                    Err(e) => {
                        eprintln!("Could not get idCredSec because {}", e);
                        return;
                    }
                };

            let randomness =
                match wallet.get_blinding_randomness(identity_provider_index, identity_index) {
                    Ok(scalar) => scalar,
                    Err(e) => {
                        eprintln!("Could not get blinding randomness because {}", e);
                        return;
                    }
                };

            let id_cred_sec: PedersenValue<ArCurve> = PedersenValue::new(id_cred_sec_scalar);
            let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
            let cred_holder_info = CredentialHolderInfo::<ArCurve> { id_cred };

            let aci = AccCredentialInfo {
                cred_holder_info,
                prf_key,
            };
            let id_use_data = IdObjectUseData { aci, randomness };
            let secret = match wallet.get_account_signing_key(
                identity_provider_index,
                identity_index,
                u32::from(acc_num),
            ) {
                Ok(scalar) => scalar,
                Err(e) => {
                    eprintln!("Could not get account signing key because {}", e);
                    return;
                }
            };
            let cred_data = {
                let mut keys = std::collections::BTreeMap::new();
                let public = ed25519::PublicKey::from(&secret);
                keys.insert(KeyIndex(0), KeyPair { secret, public });

                CredentialData {
                    keys,
                    threshold: SignatureThreshold(1),
                }
            };
            let context = CredentialContext {
                wallet,
                identity_provider_index,
                identity_index,
                credential_index: u32::from(acc_num),
            };
            (id_use_data, cred_data, Some(context))
        }
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

    let new_or_existing = match (cc.expiry, cc.account) {
        (None, None) => panic!("One of (expiry, address) is required."),
        (None, Some(addr)) => Right(addr),
        (Some(seconds), None) => Left(TransactionTime {
            seconds: chrono::Utc::now().timestamp() as u64 + seconds,
        }),
        (Some(_), Some(_)) => panic!("Exactly one of (expiry, address) is required."),
    };

    let cdi = match maybe_context {
        Some(credential_context) => create_credential(
            context,
            &id_object,
            &id_use_data,
            acc_num,
            policy,
            &acc_data,
            &credential_context,
            &new_or_existing,
        ),
        None => create_credential(
            context,
            &id_object,
            &id_use_data,
            acc_num,
            policy,
            &acc_data,
            &SystemAttributeRandomness,
            &new_or_existing,
        ),
    };

    let (cdi, commitments_randomness) = match cdi {
        Ok(cdi) => cdi,
        Err(x) => {
            eprintln!("Could not generate the credential because {}", x);
            return;
        }
    };

    let address = account_address_from_registration_id(&cdi.values.cred_id);

    let cdi_no_proofs = AccountCredentialWithoutProofs::Normal {
        cdv:         cdi.values.clone(),
        commitments: cdi.proofs.id_proofs.commitments.clone(),
    };
    let cdi = AccountCredential::Normal { cdi };

    let (versioned_credentials, randomness_map) = {
        let ki = cc.key_index.map_or(KeyIndex(0), KeyIndex);
        let mut credentials = BTreeMap::new();
        let mut randomness = BTreeMap::new();
        // we insert a credential without proofs, to be compatible with the genesis
        // tool, and concordium-client import.
        credentials.insert(ki, cdi_no_proofs);
        randomness.insert(ki, &commitments_randomness);
        (Versioned::new(VERSION_0, credentials), randomness)
    };

    let enc_key = id_use_data.aci.prf_key.prf_exponent(acc_num).unwrap();

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
        output_possibly_encrypted(&cc.keys_out, &js).ok();
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
        output_possibly_encrypted(&cc.keys_out, &account_data_json).ok();
    }

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
        // if it is an existing account then just write the credential.
        // otherwise write the credential message that can be sent to the chain.
        let cdi_json_value = match new_or_existing {
            Left(tt) => to_value(&Versioned::new(VERSION_0, AccountCredentialMessage {
                message_expiry: tt,
                credential:     cdi,
            }))
            .expect("Cannot fail."),
            Right(_) => to_value(&Versioned::new(VERSION_0, cdi)).expect("Cannot fail"),
        };
        match write_json_to_file(json_file, &cdi_json_value) {
            Ok(_) => println!("Wrote transaction payload to JSON file."),
            Err(e) => {
                eprintln!("Could not JSON write to file because {}", e);
                output_json(&cdi_json_value);
            }
        }
    }
}

fn handle_create_hd_wallet(chw: CreateHdWallet) {
    let bip39_map = bip39_map();

    let words_str = {
        println!("Please enter existing phrase below.");
        let input_words = match read_words_from_terminal(24, true, &bip39_map) {
            Ok(words) => words,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        };

        input_words.join(" ")
    };
    let net = if chw.testnet {
        Net::Testnet
    } else {
        Net::Mainnet
    };
    let wallet = ConcordiumHdWallet {
        seed: words_to_seed(&words_str),
        net,
    };

    if let Some(filepath) = chw.out {
        match output_possibly_encrypted(&filepath, &wallet) {
            Ok(_) => println!("Wrote hd wallet to file."),
            Err(_) => {
                eprintln!("Could not write to file. The generated wallet is");
                output_json(&wallet);
            }
        }
    } else {
        println!("Generated hd wallet.");
        output_json(&wallet)
    }
}

/// Create a new CHI object (essentially new idCredPub and idCredSec).
fn handle_create_chi(cc: CreateChi) {
    let mut csprng = thread_rng();
    let ah_info = if let (Some(path), Some(identity_provider_index), Some(identity_index)) =
        (cc.hd_wallet, cc.identity_provider_index, cc.identity_index)
    {
        let wallet: ConcordiumHdWallet = match read_json_from_file(&path) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("Could not read file because {}", e);
                return;
            }
        };
        let id_cred_sec_scalar =
            match wallet.get_id_cred_sec(identity_provider_index, identity_index) {
                Ok(scalar) => scalar,
                Err(e) => {
                    eprintln!("Could not get idCredSec because {}", e);
                    return;
                }
            };

        let id_cred_sec: PedersenValue<ArCurve> = PedersenValue::new(id_cred_sec_scalar);
        let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
        CredentialHolderInfo::<ExampleCurve> { id_cred }
    } else {
        CredentialHolderInfo::<ExampleCurve> {
            id_cred: IdCredentials::generate(&mut csprng),
        }
    };
    if let Some(filepath) = cc.out {
        match output_possibly_encrypted(&filepath, &ah_info) {
            Ok(_) => println!("Wrote CHI to file."),
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

// Create a new CHI object (essentially new idCredPub and idCredSec).
fn handle_create_id_use_data(iud: CreateIdUseData) {
    let id_use_data = {
        if let (Some(path), Some(identity_provider_index), Some(identity_index)) = (
            iud.hd_wallet,
            iud.identity_provider_index,
            iud.identity_index,
        ) {
            let wallet: ConcordiumHdWallet = match read_json_from_file(&path) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Could not read file because {}", e);
                    return;
                }
            };
            let prf_key: prf::SecretKey<ArCurve> =
                match wallet.get_prf_key(identity_provider_index, identity_index) {
                    Ok(prf) => prf,
                    Err(e) => {
                        eprintln!("Could not get prf key because {}", e);
                        return;
                    }
                };

            let id_cred_sec_scalar =
                match wallet.get_id_cred_sec(identity_provider_index, identity_index) {
                    Ok(scalar) => scalar,
                    Err(e) => {
                        eprintln!("Could not get idCredSec because {}", e);
                        return;
                    }
                };

            let randomness =
                match wallet.get_blinding_randomness(identity_provider_index, identity_index) {
                    Ok(scalar) => scalar,
                    Err(e) => {
                        eprintln!("Could not get blinding randomness because {}", e);
                        return;
                    }
                };

            let id_cred_sec: PedersenValue<ArCurve> = PedersenValue::new(id_cred_sec_scalar);
            let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
            let cred_holder_info = CredentialHolderInfo::<ArCurve> { id_cred };

            let aci = AccCredentialInfo {
                cred_holder_info,
                prf_key,
            };
            IdObjectUseData { aci, randomness }
        } else {
            let mut csprng = thread_rng();
            let cred_holder_info = CredentialHolderInfo::<ExampleCurve> {
                id_cred: IdCredentials::generate(&mut csprng),
            };
            let prf_key = prf::SecretKey::generate(&mut csprng);

            let aci = AccCredentialInfo {
                cred_holder_info,
                prf_key,
            };

            let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng);
            IdObjectUseData { aci, randomness }
        }
    };

    let ver_id_use_data = Versioned::new(VERSION_0, id_use_data);

    if let Some(filepath) = iud.out {
        match output_possibly_encrypted(&filepath, &ver_id_use_data) {
            Ok(_) => println!("Wrote ID use data to file."),
            Err(_) => {
                eprintln!("Could not write to file. The generated ID use data is");
                output_json(&ver_id_use_data);
            }
        }
    } else {
        println!("Generated ID use data.");
        output_json(&ver_id_use_data)
    }
}

/// Act as the identity provider. Read the version 0 pre-identity object and
/// load the private information of the identity provider, check and sign the
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
    let (ip_info, ip_sec_key, ip_cdi_secret_key) =
        match decrypt_input::<_, IpData<Bls12>>(&aai.ip_data) {
            Ok(ip_data) => (
                ip_data.public_ip_info,
                ip_data.ip_secret_key,
                ip_data.ip_cdi_secret_key,
            ),
            Err(x) => {
                eprintln!("Could not read identity issuer information because: {}", x);
                return;
            }
        };

    let valid_to = match aai.id_expiry {
        Some(exp) => exp,
        None => match read_validto() {
            Ok(ym) => ym,
            Err(e) => {
                eprintln!("Could not read credential expiry because: {}", e);
                return;
            }
        },
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
        if !aai.no_attributes {
            match MultiSelect::new()
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
        } else {
            Vec::new()
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
    let context = IpContext::new(&ip_info, &ars, &global_ctx);
    let message_expiry = TransactionTime {
        seconds: chrono::Utc::now().timestamp() as u64 + aai.expiry,
    };
    let vf = verify_credentials(
        &pio,
        context,
        &attributes,
        message_expiry,
        &ip_sec_key,
        &ip_cdi_secret_key,
    );

    match vf {
        Ok((signature, icdi)) => {
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
            let icdi_message = AccountCredentialMessage::<IpPairing, ArCurve, _> {
                message_expiry,
                credential: AccountCredential::Initial { icdi },
            };
            let versioned_icdi = Versioned::new(VERSION_0, icdi_message);
            if let Some(json_file) = aai.out_icdi {
                match write_json_to_file(json_file, &versioned_icdi) {
                    Ok(_) => println!("Wrote transaction payload to JSON file."),
                    Err(e) => {
                        eprintln!("Could not JSON write to file because {}", e);
                        output_json(&versioned_icdi);
                    }
                }
            }
            if let Some(bin_file) = aai.bin_out {
                match File::create(&bin_file) {
                    // This is a bit stupid, we should write directly to the sink.
                    Ok(mut file) => match file.write_all(&to_bytes(&versioned_icdi)) {
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
        Err(r) => eprintln!("Could not verify pre-identity object {:?}", r),
    }
}

/// Act as the identity provider. Read the version 0 pre-identity object and
/// load the private information of the identity provider, check and sign the
/// pre-identity object to generate the identity object to send back to the
/// account holder.
fn handle_act_as_ip_v1(aai: IpSignPioV1) {
    let pio = match read_pre_identity_object_v1(&aai.pio) {
        Ok(pio) => pio,
        Err(e) => {
            eprintln!("Could not read file because {}", e);
            return;
        }
    };
    let (ip_info, ip_sec_key) = match decrypt_input::<_, IpData<Bls12>>(&aai.ip_data) {
        Ok(ip_data) => (ip_data.public_ip_info, ip_data.ip_secret_key),
        Err(x) => {
            eprintln!("Could not read identity issuer information because: {}", x);
            return;
        }
    };

    let valid_to = match aai.id_expiry {
        Some(exp) => exp,
        None => match read_validto() {
            Ok(ym) => ym,
            Err(e) => {
                eprintln!("Could not read credential expiry because: {}", e);
                return;
            }
        },
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
        if !aai.no_attributes {
            match MultiSelect::new()
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
        } else {
            Vec::new()
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
    let context = IpContext::new(&ip_info, &ars, &global_ctx);
    let vf = verify_credentials_v1(&pio, context, &attributes, &ip_sec_key);

    match vf {
        Ok(signature) => {
            let id_object = IdentityObjectV1 {
                pre_identity_object: pio,
                alist: attributes,
                signature,
            };
            let ver_id_object = Versioned::new(VERSION_0, id_object);
            let signature = &ver_id_object.value.signature;
            println!("Successfully checked pre-identity data.");
            if let Some(signed_out_path) = aai.out_file {
                if let Err(e) = write_json_to_file(signed_out_path.clone(), &ver_id_object) {
                    println!(
                        "Could not write Identity object to file due to {}. The signature is: {}",
                        e,
                        base16_encode_string(signature)
                    );
                } else {
                    println!(
                        "Wrote signed identity object to file {}",
                        signed_out_path.display()
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
        match decrypt_input(sip.chi) {
            Ok(chi) => chi,
            Err(e) => {
                eprintln!("Could not read credential holder information: {}", e);
                return;
            }
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
        if let Some(ip) = sip.identity_provider {
            match ips.identity_providers.get(&IpIdentity(ip)) {
                Some(ip) => ip.clone(),
                None => {
                    eprintln!("Identity provider with identity {} does not exist.", ip);
                    return;
                }
            }
        } else if let Ok(ip_info_idx) = Select::new()
            .with_prompt("Choose identity provider")
            .items(&ips_names)
            .default(0)
            .interact()
        {
            ips.identity_providers
                .iter()
                .nth(ip_info_idx)
                .unwrap()
                .1
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
    let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(&mut csprng);
    let id_use_data = IdObjectUseData { aci, randomness };
    let (pio, _) = generate_pio(&context, threshold, &id_use_data, &initial_acc_data)
        .expect("Generating the pre-identity object should succeed.");

    // the only thing left is to output all the information

    let ver_id_use_data = Versioned::new(VERSION_0, id_use_data);
    if let Some(aci_out_path) = sip.private {
        if output_possibly_encrypted(&aci_out_path, &ver_id_use_data).is_ok() {
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

fn handle_start_ip_v1(sip: StartIpV1) {
    let id_use_data = match read_id_use_data(sip.id_use_data) {
        Ok(v) => v,
        Err(x) => {
            eprintln!("Could not read ID use data object because: {}", x);
            return;
        }
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
        if let Some(ip) = sip.identity_provider {
            match ips.identity_providers.get(&IpIdentity(ip)) {
                Some(ip) => ip.clone(),
                None => {
                    eprintln!("Identity provider with identity {} does not exist.", ip);
                    return;
                }
            }
        } else if let Ok(ip_info_idx) = Select::new()
            .with_prompt("Choose identity provider")
            .items(&ips_names)
            .default(0)
            .interact()
        {
            ips.identity_providers
                .iter()
                .nth(ip_info_idx)
                .unwrap()
                .1
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
    let (pio, _) = generate_pio_v1(&context, threshold, &id_use_data)
        .expect("Generating the pre-identity object should succeed.");

    // the only thing left is to output all the information

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
        let ar_base = global_ctx.on_chain_commitment_key.g;
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
        let id_secret_key = ps_sig::SecretKey::<Bls12>::generate(gip.key_capacity, &mut csprng);
        let id_public_key = ps_sig::PublicKey::from(&id_secret_key);

        let keypair = ed25519::Keypair::generate(&mut csprng);
        let ip_cdi_verify_key = keypair.public;
        let ip_cdi_secret_key = keypair.secret;

        let ip_id = IpIdentity(id as u32);
        let ip_info = IpInfo {
            ip_identity: ip_id,
            ip_description: mk_ip_description(id),
            ip_verify_key: id_public_key,
            ip_cdi_verify_key,
        };
        let full_info = IpData {
            ip_secret_key: id_secret_key,
            public_ip_info: ip_info,
            ip_cdi_secret_key,
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
    let gc = match gl.seed_file {
        None => GlobalContext::<id::constants::ArCurve>::generate(gl.genesis_string),
        Some(f) => match std::fs::read(f) {
            Ok(data) => GlobalContext::<id::constants::ArCurve>::generate_from_seed(
                gl.genesis_string,
                NUM_BULLETPROOF_GENERATORS,
                &data,
            ),
            Err(e) => {
                eprintln!("Could not read seed file {}", e);
                return;
            }
        },
    };
    let vgc = Versioned::new(VERSION_0, gc);
    if let Err(err) = write_json_to_file(&gl.output_file, &vgc) {
        eprintln!("Could not write global parameters because {}.", err);
    }
}

fn handle_recovery(girr: GenerateIdRecoveryRequest) {
    let ip_info = match read_ip_info(girr.ip_info) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read identity provider info because {}", err);
            return;
        }
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(girr.global) {
            gc
        } else {
            eprintln!("Cannot read global context from database. Terminating.");
            return;
        }
    };

    let chi: CredentialHolderInfo<ExampleCurve> = {
        match decrypt_input(girr.chi) {
            Ok(chi) => chi,
            Err(e) => {
                eprintln!("Could not read credential holder information: {}", e);
                return;
            }
        }
    };
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let request =
        generate_id_recovery_request(&ip_info, &global_ctx, &chi.id_cred.id_cred_sec, timestamp);
    let json = Versioned {
        version: Version::from(0),
        value:   request,
    };
    if let Err(err) = write_json_to_file(&girr.request_file, &json) {
        eprintln!("Could not write id recovery request to to {}.", err);
    }
}

fn handle_validate_recovery(vir: ValidateIdRecoveryRequest) {
    let ip_info = match read_ip_info(vir.ip_info) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read identity provider info because {}", err);
            return;
        }
    };

    let global_ctx = {
        if let Some(gc) = read_global_context(vir.global) {
            gc
        } else {
            eprintln!("Cannot read global context from database. Terminating.");
            return;
        }
    };

    let request = match read_recovery_request(&vir.request) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Could not read recovery request because {}", err);
            return;
        }
    };

    let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
    println!("ID recovery validation result: {}", result);
}
