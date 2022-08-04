use aggregate_sig as agg;
use clap::AppSettings;
use client_server_helpers::*;
use crypto_common::{
    base16_encode_string,
    encryption::{encrypt, Password},
    types::{Amount, KeyIndex},
    *,
};
use dodis_yampolskiy_prf as prf;
use ecvrf as vrf;
use ed25519_dalek as ed25519;
use id::{account_holder::*, constants::*, secret_sharing::Threshold, types::*};
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
        num:                 usize,
        #[structopt(
            long = "template",
            help = "Template on how to name accounts; they will be named TEMPLATE-$N.json.",
            value_name = "TEMPLATE",
            default_value = "account",
            env = "TEMPLATE"
        )]
        template:            String,
        #[structopt(
            long = "balance",
            help = "Initial balance on each of the accounts, in GTU.",
            default_value = "1000000",
            env = "INITIAL_BALANCE"
        )]
        balance:             Amount,
        #[structopt(
            long = "stake",
            help = "Initial stake of the bakers, in GTU. If this is set then all accounts will be \
                    bakers.",
            env = "INITIAL_STAKE"
        )]
        stake:               Option<Amount>,
        #[structopt(
            long = "restake",
            help = "Restake earnings automatically. This only has effect if 'stake' is set.",
            env = "RESTAKE_EARNINGS"
        )]
        restake:             bool,
        #[structopt(
            long = "baker-credentials-password",
            help = "Output bakers keys with the provided password. Only has effect if 'stake' is \
                    set.",
            env = "BAKER_KEYS_PASSWORD"
        )]
        baker_keys_password: Option<Password>,
        #[structopt(flatten)]
        common:              CommonOptions,
    },
}

#[derive(StructOpt)]
struct CommonOptions {
    #[structopt(
        long = "ip-info",
        help = "File with (versioned) public information about the identity provider.",
        env = "IP_INFO_FILE"
    )]
    ip_info:  PathBuf,
    #[structopt(
        long = "global",
        help = "File with global parameters.",
        default_value = "database/global.json",
        env = "GLOBAL_FILE"
    )]
    global:   PathBuf,
    #[structopt(
        long = "ar-info",
        help = "File with the (versioned) public keys of the anonymity revoker.",
        default_value = "database/anonymity_revoker-0.pub.json",
        env = "AR_INFO_FILE"
    )]
    ar_info:  PathBuf,
    #[structopt(
        long = "num-keys",
        help = "The number of keys each account should have. Threshold is set to max(1, K-1).",
        default_value = "3",
        env = "NUM_KEYS"
    )]
    num_keys: usize,
    #[structopt(
        long = "out-dir",
        help = "Directory to write the generated files into.",
        default_value = ".",
        env = "OUT_DIR"
    )]
    out_dir:  PathBuf,
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
    let ip_info = read_json_from_file::<_, Versioned<IpInfo<IpPairing>>>(&common.ip_info)?.value;

    let global_ctx = read_global_context(&common.global).ok_or_else(|| {
        Error::new(
            ErrorKind::Other,
            "Cannot read global context information database. Terminating.",
        )
    })?;

    let ar_info = read_json_from_file::<_, Versioned<ArInfo<ArCurve>>>(&common.ar_info)?.value;

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
                crypto_common::types::KeyPair::generate(csprng),
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

        let acc_data = build_pub_info_for_ip(
            &global_ctx,
            &aci.cred_holder_info.id_cred.id_cred_sec,
            &aci.prf_key,
            &initial_acc_data,
        )
        .expect("Could not generate account.");

        let policy = Policy {
            valid_to:   attributes.valid_to,
            created_at: attributes.created_at,
            policy_vec: BTreeMap::<_, ExampleAttribute>::new(),
            _phantom:   Default::default(),
        };

        let ar_data = {
            let mut ar_data = BTreeMap::new();
            ar_data.insert(ar_info.ar_identity, ChainArData {
                enc_id_cred_pub_share: ar_info
                    .ar_public_key
                    .encrypt_exponent(csprng, &aci.prf_key.to_value()),
            });
            ar_data
        };

        let cred_counter = 0;

        // only a single dummy anonymity revoker.
        let threshold = Threshold(1);

        let chosen_ars = {
            let mut chosen_ars = BTreeMap::new();
            chosen_ars.insert(ar_info.ar_identity, ar_info.clone());
            chosen_ars
        };

        let (_, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
            &aci.cred_holder_info.id_cred.id_cred_sec,
            &chosen_ars,
            threshold,
            &global_ctx.on_chain_commitment_key,
        );

        let (commitments, _) = compute_commitments(
            &global_ctx.on_chain_commitment_key,
            &attributes,
            &aci.prf_key,
            cred_counter,
            &cmm_id_cred_sec_sharing_coeff,
            cmm_coeff_randomness,
            &policy,
            &SystemAttributeRandomness,
            csprng,
        )
        .expect("Could not compute commitments.");

        let cdv = CredentialDeploymentValues {
            cred_key_info: acc_data.vk_acc,
            cred_id: acc_data.reg_id,
            ip_identity: ip_info.ip_identity,
            threshold,
            ar_data,
            policy,
        };

        let address = account_address_from_registration_id(&cdv.cred_id);

        // we output a credential without proofs but with commitments.
        // This is enough for inclusion in genesis, since we do not care
        // about proofs, assuming everything in genesis is trusted.
        let cdvc = AccountCredentialWithoutProofs::Normal { cdv, commitments };

        let versioned_credentials = {
            let mut credentials = BTreeMap::new();
            credentials.insert(KeyIndex(0), cdvc);
            Versioned::new(VERSION_0, credentials)
        };
        let acc_keys = AccountKeys::from(initial_acc_data);

        // unwrap is safe here since we've generated the credential already, and that
        // does the same computation.
        let enc_key = aci
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
            "aci": aci,
        });
        (account_data_json, versioned_credentials, address)
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
            ref baker_keys_password,
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
                let (account_data_json, credential_json, address_json) =
                    generate_account(&mut csprng);

                if let Some(stake) = stake {
                    // vrf keypair
                    let vrf_key = vrf::Keypair::generate(&mut csprng);
                    // signature keypair
                    let sign_key = ed25519::Keypair::generate(&mut csprng);

                    let agg_sign_key = agg::SecretKey::<IpPairing>::generate(&mut csprng);
                    let agg_verify_key = agg::PublicKey::from_secret(&agg_sign_key);

                    let public_baker_data = json!({
                        "bakerId": acc_num,
                        "electionVerifyKey": base16_encode_string(&vrf_key.public),
                        "signatureVerifyKey": base16_encode_string(&sign_key.public),
                        "aggregationVerifyKey": base16_encode_string(&agg_verify_key),
                        "stake": stake,
                        "restakeEarnings": restake,
                    });

                    let public_account_data = json!({
                        "address": address_json,
                        "balance": balance,
                        "accountThreshold": 1, // only a single credential
                        "credentials": credential_json,
                        "baker": public_baker_data
                    });

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

                    // If the password is provided then encrypt, otherwise output in plaintext.
                    let baker_credentials_out = if let Some(pass) = baker_keys_password.as_ref() {
                        let plaintext = serde_json::to_vec(&baker_data_json)
                            .expect("Cannot convert to JSON, should not happen.");
                        let encrypted = encrypt(pass, &plaintext, &mut csprng);
                        serde_json::to_value(&encrypted).expect("JSON serialization must succeed.")
                    } else {
                        baker_data_json
                    };
                    if let Err(err) = write_json_to_file(
                        mk_out_path(format!("baker-{}-credentials.json", acc_num)),
                        &baker_credentials_out,
                    ) {
                        eprintln!(
                            "Could not output baker credential for baker {}, because {}.",
                            acc_num, err
                        );
                    };
                    accounts.push(public_account_data);
                    bakers.push(public_baker_data);
                } else {
                    let public_account_data = json!({
                        "schemeId": "Ed25519",
                        "address": address_json,
                        "balance": balance,
                        "accountThreshold": 1, // only a single credential
                        "credentials": credential_json,
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
