use aggregate_sig as agg;
use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{base16_encode_string, types::Amount, *};
use curve_arithmetic::Pairing;
use dodis_yampolskiy_prf::secret as prf;
use ecvrf as vrf;
use ed25519_dalek as ed25519;
use either::Either::Left;
use id::{account_holder::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*};
use pairing::bls12_381::{Bls12, G1};
use rand::{rngs::ThreadRng, *};
use serde_json::json;
use std::{collections::btree_map::BTreeMap, path::PathBuf};
use structopt::StructOpt;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

#[derive(StructOpt)]
#[structopt(
    version = "0.31830988618",
    author = "Concordium",
    about = "Generate bakers with accounts for inclusion in genesis or just beta accounts."
)]
enum GenesisTool {
    #[structopt(name = "create-bakers", about = "Create new bakers.")]
    CreateBakers {
        #[structopt(long = "num", help = "Number of bakers to generate.")]
        num: usize,
        #[structopt(
            long = "num-finalizers",
            help = "The amount of finalizers to generate. Defaults to all bakers."
        )]
        num_finalizers: Option<usize>,
        #[structopt(
            long = "balance",
            help = "Balance on each of the baker accounts, in GTU.",
            default_value = "3500000"
        )]
        balance: Amount,
        #[structopt(flatten)]
        common: CommonOptions,
    },
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

fn main() {
    let gt = {
        let app = GenesisTool::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        GenesisTool::from_clap(&matches)
    };

    let common = match gt {
        GenesisTool::CreateBakers { ref common, .. } => common,
        GenesisTool::CreateAccounts { ref common, .. } => common,
    };

    let mut csprng = thread_rng();

    // Load identity provider and anonymity revokers.
    let (ip_info, ip_secret_key, ip_cdi_secret_key) =
        match read_json_from_file::<_, IpData<Bls12>>(&common.ip_data) {
            Ok(IpData {
                public_ip_info,
                ip_secret_key,
                ip_cdi_secret_key,
            }) => (public_ip_info, ip_secret_key, ip_cdi_secret_key),
            Err(e) => {
                eprintln!("Could not parse identity issuer JSON because: {}", e);
                return;
            }
        };

    let global_ctx = {
        if let Some(gc) = read_global_context(&common.global) {
            gc
        } else {
            eprintln!("Cannot read global context information database. Terminating.");
            return;
        }
    };

    let ars_infos = {
        if let Ok(ars) = read_anonymity_revokers(&common.anonymity_revokers) {
            ars
        } else {
            eprintln!("Cannot read anonymity revokers from the database. Terminating.");
            return;
        }
    };

    let context = IPContext::new(&ip_info, &ars_infos.anonymity_revokers, &global_ctx);
    let threshold = Threshold((ars_infos.anonymity_revokers.len() - 1) as u8);

    if common.num_keys == 0 && common.num_keys > 255 {
        eprintln!("num_keys should be a positive integer <= 255.");
        return;
    }

    // Roughly one year
    let generate_account = |csprng: &mut ThreadRng| {
        let ah_info = CredentialHolderInfo::<ExampleCurve> {
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
            initial_keys.insert(KeyIndex(idx as u8), ed25519::Keypair::generate(csprng));
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
            &ip_secret_key,
            &ip_cdi_secret_key,
        );

        let (ip_sig, _) = ver_ok.expect("There is an error in signing");

        let policy = Policy {
            valid_to,
            created_at,
            policy_vec: BTreeMap::new(),
            _phantom: Default::default(),
        };

        let mut keys = BTreeMap::new();
        for idx in 0..common.num_keys {
            keys.insert(KeyIndex(idx as u8), ed25519::Keypair::generate(csprng));
        }

        let threshold = SignatureThreshold(
            if common.num_keys == 1 {
                1
            } else {
                common.num_keys as u8 - 1
            },
        );

        let acc_data = AccountData {
            keys,
            existing: Left(threshold),
        };

        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist:               attributes,
            signature:           ip_sig,
        };

        let id_object_use_data = IdObjectUseData { aci, randomness };

        let acc_num = 53;

        let cdi = create_credential(
            context,
            &id_object,
            &id_object_use_data,
            acc_num,
            policy,
            &acc_data,
        )
        .expect("We should have constructed valid data.");

        let address = AccountAddress::new(&cdi.values.reg_id);

        let versioned_cdi = Versioned::new(VERSION_0, cdi);

        let acc_keys = AccountKeys {
            keys: acc_data
                .keys
                .iter()
                .map(|(&idx, kp)| (idx, VerifyKey::from(kp)))
                .collect(),
            threshold,
        };

        // unwrap is safe here since we've generated the credential already, and that
        // does the same computation.
        let enc_key = id_object_use_data
            .aci
            .prf_key
            .prf_exponent(acc_num)
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
            "accountData": acc_data,
            "credential": versioned_cdi,
            "aci": id_object_use_data.aci,
        });
        (account_data_json, versioned_cdi, acc_keys, address)
    };

    let mk_out_path = |s| {
        let mut path = common.out_dir.clone();
        path.push(s);
        path
    };

    match gt {
        GenesisTool::CreateBakers {
            num,
            num_finalizers,
            balance,
            ..
        } => {
            let num_bakers = num;
            let num_finalizers = num_finalizers.unwrap_or(num_bakers);

            let mut bakers = Vec::with_capacity(num_bakers);
            for baker in 0..num_bakers {
                let (account_data_json, credential_json, account_keys, address_json) =
                    generate_account(&mut csprng);
                if let Err(err) = write_json_to_file(
                    mk_out_path(format!("baker-{}-account.json", baker)),
                    &account_data_json,
                ) {
                    eprintln!(
                        "Could not output account data for baker {}, because {}.",
                        baker, err
                    );
                }

                // vrf keypair
                let vrf_key = vrf::Keypair::generate(&mut csprng);
                // signature keypair
                let sign_key = ed25519::Keypair::generate(&mut csprng);

                let agg_sign_key = agg::SecretKey::<Bls12>::generate(&mut csprng);
                let agg_verify_key = agg::PublicKey::from_secret(agg_sign_key);

                // Output baker vrf and election keys in a json file.
                let baker_data_json = json!({
                    "electionPrivateKey": base16_encode_string(&vrf_key.secret),
                    "electionVerifyKey": base16_encode_string(&vrf_key.public),
                    "signatureSignKey": base16_encode_string(&sign_key.secret),
                    "signatureVerifyKey": base16_encode_string(&sign_key.public),
                    "aggregationSignKey": base16_encode_string(&agg_sign_key),
                    "aggregationVerifyKey": base16_encode_string(&agg_verify_key),
                });

                if let Err(err) = write_json_to_file(
                    mk_out_path(format!("baker-{}-credentials.json", baker)),
                    &baker_data_json,
                ) {
                    eprintln!(
                        "Could not output baker credential for baker {}, because {}.",
                        baker, err
                    );
                }

                // Finally store a json value storing public data for this baker.
                let public_baker_data = json!({
                    "electionVerifyKey": base16_encode_string(&vrf_key.public),
                    "signatureVerifyKey": base16_encode_string(&sign_key.public),
                    "aggregationVerifyKey": base16_encode_string(&agg_verify_key),
                    "finalizer": baker < num_finalizers,
                    "account": json!({
                        "address": address_json,
                        "accountKeys": account_keys,
                        "balance": balance,
                        "credential": credential_json
                    })
                });
                bakers.push(public_baker_data);
            }

            // finally output all of the bakers in one file. This is used to generate
            // genesis.
            if let Err(err) =
                write_json_to_file(mk_out_path("bakers.json".to_owned()), &json!(bakers))
            {
                eprintln!("Could not output bakers.json file because {}.", err)
            }
        }
        GenesisTool::CreateAccounts {
            num,
            ref template,
            balance,
            ..
        } => {
            let num_accounts = num;
            let prefix = template;

            let mut accounts = Vec::with_capacity(num_accounts);
            for acc_num in 0..num_accounts {
                let (account_data_json, credential_json, account_keys, address_json) =
                    generate_account(&mut csprng);
                let public_account_data = json!({
                    "schemeId": "Ed25519",
                    "accountKeys": account_keys,
                    "address": address_json,
                    "balance": balance,
                    "credential": credential_json
                });
                accounts.push(public_account_data);

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
            }
        }
    }
}
