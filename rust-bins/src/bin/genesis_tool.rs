use aggregate_sig as agg;
use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{
    base16_encode_string,
    serde_impls::KeyPairDef,
    types::{Amount, KeyIndex},
    *,
};
use dodis_yampolskiy_prf::secret as prf;
use ecvrf as vrf;
use ed25519_dalek as ed25519;
use id::{
    account_holder::*, constants::*, ffi::*, identity_provider::*, secret_sharing::Threshold,
    types::*,
};
use rand::{rngs::ThreadRng, *};
use serde_json::json;
use std::{
    collections::btree_map::BTreeMap,
    io::{Error, ErrorKind},
    path::PathBuf,
};
use structopt::StructOpt;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<BaseField, ExampleAttribute>;

#[derive(StructOpt)]
#[structopt(
    version = "0.4",
    author = "Concordium",
    about = "Generate accounts for inclusion in genesis."
)]
enum GenesisTool {
    #[structopt(name = "create-accounts", about = "Create new accounts.")]
    CreateAccounts {
        #[structopt(long = "num", help = "Number of accounts to generate.")]
        num: usize,
        #[structopt(
            long = "template",
            help = "Template on how to name accounts; they will be named TEMPLATE-$N.json.",
            value_name = "TEMPLATE",
            default_value = "account"
        )]
        template: String,
        #[structopt(
            long = "balance",
            help = "Initial balance on each of the accounts, in GTU.",
            default_value = "1000000"
        )]
        balance: Amount,
        #[structopt(
            long = "stake",
            help = "Initial stake of the bakers, in GTU. If this is set then all accounts will be \
                    bakers."
        )]
        stake: Option<Amount>,
        #[structopt(
            long = "restake",
            help = "Restake earnings automatically. This only has effect if 'stake' is set."
        )]
        restake: bool,
        #[structopt(flatten)]
        common: CommonOptions,
    },
}

#[derive(StructOpt)]
struct CommonOptions {
    #[structopt(
        long = "ip-data",
        help = "File with all information about the identity provider (public and private)."
    )]
    ip_data: PathBuf,
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
    #[structopt(
        long = "num-keys",
        help = "The number of keys each account should have. Threshold is set to max(1, K-1).",
        default_value = "3"
    )]
    num_keys: usize,
    #[structopt(
        long = "out-dir",
        help = "Directory to write the generated files into.",
        default_value = "."
    )]
    out_dir: PathBuf,
}

fn main() -> std::io::Result<()> {
    let gt = {
        let app = GenesisTool::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        GenesisTool::from_clap(&matches)
    };

    let common = match gt {
        GenesisTool::CreateAccounts { ref common, .. } => common,
    };

    let mut csprng = thread_rng();

    // Load identity provider and anonymity revokers.
    let ip_data = read_json_from_file::<_, IpData<IpPairing>>(&common.ip_data)?;

    let global_ctx = read_global_context(&common.global).ok_or_else(|| {
        Error::new(
            ErrorKind::Other,
            "Cannot read global context information database. Terminating.",
        )
    })?;

    let ars_infos = read_anonymity_revokers(&common.anonymity_revokers)?;

    let context = IPContext::new(
        &ip_data.public_ip_info,
        &ars_infos.anonymity_revokers,
        &global_ctx,
    );
    let threshold = Threshold((ars_infos.anonymity_revokers.len() - 1) as u8);

    if common.num_keys == 0 && common.num_keys > 255 {
        return Err(Error::new(
            ErrorKind::Other,
            "num_keys should be a positive integer <= 255.",
        ));
    }

    // Roughly one year
    let generate_account = |csprng: &mut ThreadRng| {
        let ah_info = CredentialHolderInfo::<ArCurve> {
            id_cred: IdCredentials::generate(csprng),
        };

        // Choose prf key.
        let prf_key = prf::SecretKey::generate(csprng);

        // Expire in 1 year from now.
        let created_at = YearMonth::now();
        let valid_to = {
            let mut now = YearMonth::now();
            now.year += 1;
            now
        };

        // no attributes
        let alist = BTreeMap::new();
        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key,
        };

        let attributes = ExampleAttributeList {
            valid_to,
            created_at,
            max_accounts: 238,
            alist,
            _phantom: Default::default(),
        };

        let mut initial_keys = BTreeMap::new();
        for idx in 0..common.num_keys {
            initial_keys.insert(
                KeyIndex(idx as u8),
                crypto_common::serde_impls::KeyPairDef::generate(csprng),
            );
        }

        let initial_threshold = SignatureThreshold(
            if common.num_keys == 1 {
                1
            } else {
                common.num_keys as u8 - 1
            },
        );

        let initial_acc_data = InitialAccountData {
            keys:      initial_keys,
            threshold: initial_threshold,
        };

        let (pio, randomness) = generate_pio(&context, threshold, &aci, &initial_acc_data)
            .expect("Generating the pre-identity object should succeed.");

        let ver_ok = verify_credentials(
            &pio,
            context,
            &attributes,
            &ip_data.ip_secret_key,
            &ip_data.ip_cdi_secret_key,
        );

        let (ip_sig, _) = ver_ok.expect("There is an error in signing");

        let mut keys = BTreeMap::new();
        for idx in 0..common.num_keys {
            keys.insert(KeyIndex(idx as u8), KeyPairDef::generate(csprng));
        }

        let threshold = SignatureThreshold(
            if common.num_keys == 1 {
                1
            } else {
                common.num_keys as u8 - 1
            },
        );

        let acc_data = CredentialData { keys, threshold };

        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist:               attributes,
            signature:           ip_sig,
        };

        let id_object_use_data = IdObjectUseData { aci, randomness };

        let icdi = create_initial_cdi(
            &ip_data.public_ip_info,
            id_object.pre_identity_object.pub_info_for_ip,
            &id_object.alist,
            &ip_data.ip_cdi_secret_key,
        );

        let address = AccountAddress::new(&icdi.values.reg_id);

        let versioned_credentials = {
            let mut credentials = BTreeMap::new();
            credentials.insert(KeyIndex(0), AccountCredential::Initial::<IpPairing, _, _> {
                icdi,
            });
            Versioned::new(VERSION_0, credentials)
        };
        let acc_keys = {
            let mut creds = BTreeMap::new();
            creds.insert(KeyIndex(0), acc_data);
            creds
        };

        // unwrap is safe here since we've generated the credential already, and that
        // does the same computation.
        let enc_key = id_object_use_data
            .aci
            .prf_key
            .prf_exponent(id::constants::INITIAL_CREDENTIAL_INDEX)
            .unwrap();
        let secret_key = elgamal::SecretKey {
            generator: *global_ctx.elgamal_generator(),
            scalar:    enc_key,
        };

        // output private account data
        let account_data_json = json!({
            "address": address,
            "encryptionSecretKey": secret_key,
            "encryptionPublicKey": elgamal::PublicKey::from(&secret_key),
            "accountKeys": acc_keys,
            "credentials": versioned_credentials,
            "aci": id_object_use_data.aci,
        });
        (account_data_json, versioned_credentials, acc_keys, address)
    };

    let mk_out_path = |s| {
        let mut path = common.out_dir.clone();
        path.push(s);
        path
    };

    match gt {
        GenesisTool::CreateAccounts {
            num,
            ref template,
            balance,
            stake,
            restake,
            ..
        } => {
            let num_accounts = num;
            let prefix = template;

            let mut bakers = Vec::new();

            if let Some(stake) = stake {
                if stake > balance {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Stake can not be more than the initial balance of the account.",
                    ));
                }
            }

            let mut accounts = Vec::with_capacity(num_accounts);
            for acc_num in 0..num_accounts {
                let (account_data_json, credential_json, account_keys, address_json) =
                    generate_account(&mut csprng);

                if let Some(stake) = stake {
                    // vrf keypair
                    let vrf_key = vrf::Keypair::generate(&mut csprng);
                    // signature keypair
                    let sign_key = ed25519::Keypair::generate(&mut csprng);

                    let agg_sign_key = agg::SecretKey::<IpPairing>::generate(&mut csprng);
                    let agg_verify_key = agg::PublicKey::from_secret(agg_sign_key);

                    // Output baker vrf and election keys in a json file.
                    let baker_data_json = json!({
                        "bakerId": acc_num,
                        "electionPrivateKey": base16_encode_string(&vrf_key.secret),
                        "electionVerifyKey": base16_encode_string(&vrf_key.public),
                        "signatureSignKey": base16_encode_string(&sign_key.secret),
                        "signatureVerifyKey": base16_encode_string(&sign_key.public),
                        "aggregationSignKey": base16_encode_string(&agg_sign_key),
                        "aggregationVerifyKey": base16_encode_string(&agg_verify_key),
                    });

                    let public_baker_data = json!({
                        "bakerId": acc_num,
                        "electionVerifyKey": base16_encode_string(&vrf_key.public),
                        "signatureVerifyKey": base16_encode_string(&sign_key.public),
                        "aggregationVerifyKey": base16_encode_string(&agg_verify_key),
                        "stake": stake,
                        "restakeEarnings": restake,
                    });

                    let public_account_data = json!({
                        "schemeId": "Ed25519",
                        "accountKeys": account_keys,
                        "address": address_json,
                        "balance": balance,
                        "credential": credential_json,
                        "baker": public_baker_data
                    });

                    if let Err(err) = write_json_to_file(
                        mk_out_path(format!("baker-{}-credentials.json", acc_num)),
                        &baker_data_json,
                    ) {
                        eprintln!(
                            "Could not output baker credential for baker {}, because {}.",
                            acc_num, err
                        );
                    }
                    accounts.push(public_account_data);
                    bakers.push(public_baker_data);
                } else {
                    let public_account_data = json!({
                        "schemeId": "Ed25519",
                        "accountKeys": account_keys,
                        "address": address_json,
                        "balance": balance,
                        "credential": credential_json,
                    });
                    accounts.push(public_account_data);
                }

                if let Err(err) = write_json_to_file(
                    mk_out_path(format!("{}-{}.json", prefix, acc_num)),
                    &json!(account_data_json),
                ) {
                    eprintln!(
                        "Could not output beta-account-{}.json file because {}.",
                        acc_num, err
                    )
                }
            }
            // finally output all of the public account data in one file. This is used to
            // generate genesis.
            if let Err(err) =
                write_json_to_file(mk_out_path(format!("{}s.json", prefix)), &json!(accounts))
            {
                eprintln!("Could not output beta-accounts.json file because {}.", err)
            };
            if stake.is_some() {
                // finally output all of the bakers in one file. This is used to generate
                // genesis.
                if let Err(err) =
                    write_json_to_file(mk_out_path("bakers.json".to_owned()), &json!(bakers))
                {
                    eprintln!("Could not output bakers.json file because {}.", err)
                }
            }
        }
    }
    Ok(())
}
