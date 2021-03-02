use anyhow::{bail, ensure};
use crypto_common::{
    base16_encode_string, types::TransactionTime, SerdeDeserialize, SerdeSerialize, Versioned,
    VERSION_0,
};
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
use id::{
    constants::{ArCurve, IpPairing},
    ffi::AttributeKind,
    identity_provider::{
        create_initial_cdi, sign_identity_object, validate_request as ip_validate_request,
    },
    types::*,
};
use log::{error, info, warn};
use reqwest::Client;
use serde_json::{from_str, json, to_value};
use std::{
    collections::HashMap,
    convert::Infallible,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use url::Url;
use warp::{http::StatusCode, hyper::header::LOCATION, Filter, Rejection, Reply};

type ExampleAttributeList = AttributeList<id::constants::BaseField, AttributeKind>;

/// Structure used to receive the correct command line arguments.
#[derive(Debug, StructOpt)]
struct IdentityProviderServiceConfiguration {
    #[structopt(
        long = "global-context",
        help = "File with global context.",
        env = "GLOBAL_CONTEXT",
        default_value = "global.json"
    )]
    global_context_file: PathBuf,
    #[structopt(
        long = "identity-provider",
        help = "File with the identity provider as JSON.",
        default_value = "identity_provider.json",
        env = "IDENTITY_PROVIDER"
    )]
    identity_provider_file: PathBuf,
    #[structopt(
        long = "anonymity-revokers",
        help = "File with the list of anonymity revokers as JSON.",
        default_value = "anonymity_revokers.json",
        env = "ANONYMITY_REVOKERS"
    )]
    anonymity_revokers_file: PathBuf,
    #[structopt(
        long = "port",
        default_value = "8100",
        help = "Port on which the server will listen on.",
        env = "IDENTITY_PROVIDER_SERVICE_PORT"
    )]
    port: u16,
    #[structopt(
        long = "retrieve-base",
        help = "Base URL where the wallet can retrieve the identity object.",
        env = "RETRIEVE_BASE"
    )]
    retrieve_url: url::Url,
    #[structopt(
        long = "id-verification-url",
        help = "URL of the identity verifier.",
        default_value = "http://localhost:8101/api/verify",
        env = "ID_VERIFICATION_URL"
    )]
    id_verification_url: url::Url,
    #[structopt(
        long = "wallet-proxy-base",
        help = "URL of the wallet-proxy.",
        env = "WALLET_PROXY_BASE"
    )]
    wallet_proxy_base: url::Url,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// The identity object request sent by the wallet in the body of the POST
/// request. The 'Deserialize' instance is automatically derived to parse the
/// expected format.
struct IdentityObjectRequest {
    #[serde(rename = "idObjectRequest")]
    id_object_request: Versioned<PreIdentityObject<IpPairing, ArCurve>>,
    #[serde(rename = "redirectURI")]
    redirect_uri: String,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
/// Status of the identity. Identities are identified via their `idCredPub`.
enum IdentityStatus {
    /// The identity is pending verification and initial account creation.
    Pending,
    /// The identity was rejected.
    Error,
    /// The identity is ready.
    Done,
}

/// The object that the wallet expects to be returned when polling for the
/// identity object.
#[derive(SerdeSerialize)]
struct IdentityTokenContainer {
    /// The status of the submission.
    status: IdentityStatus,
    /// The response, if available, otherwise Null.
    token: serde_json::Value,
    /// Details of the response in the form of a free-form text.
    detail: String,
}

/// The state the server maintains in-between the requests, consisting of
/// the resolved configuration. In particular in this prototype the private keys
/// are maintain in-memory.
struct ServerConfig {
    ip_data:               IpData<IpPairing>,
    global:                GlobalContext<ArCurve>,
    ars:                   ArInfos<ArCurve>,
    id_verification_url:   url::Url,
    retrieve_url:          url::Url,
    submit_credential_url: url::Url,
}

/// A mockup of a database to store all the data.
/// In production this would be a real database, here we store everything as
/// files on disk and synchronize access to disk via a lock. On deletion files
/// are moved into a 'backup_root' folder.
#[derive(Clone)]
struct DB {
    /// Root directory where all the data is stored.
    root: std::path::PathBuf,
    /// Root of the backup directory where we store "deleted" files.
    backup_root: std::path::PathBuf,
    /// And a hashmap of pending entries. Pending entries are also stored in the
    /// filesystem, but we cache them here since they have to be accessed
    /// often. We put it behind a mutex to sync all accesses, to the hashmap
    /// as well as to the filesystem, which is implicit. In a real database
    /// this would be done differently.
    pending: Arc<Mutex<HashMap<String, PendingEntry>>>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "lowercase")]
/// When the initial account transaction is submitted we use this type to keep
/// track of its status.
enum PendingStatus {
    /// The transaction was submitted, and is currently in the state indicated
    /// by the submission status.
    Submitted {
        submission_id: String,
        status:        SubmissionStatus,
    },
    /// The transaction could not be submitted due to, most likely, network
    /// issues. It should be retried.
    CouldNotSubmit,
}

#[derive(SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Successful response from the wallet proxy.
/// It contains a JSON body with a single field `submissionId`.
struct InitialAccountReponse {
    submission_id: String,
}

///
#[derive(SerdeSerialize, SerdeDeserialize, Clone)]
struct PendingEntry {
    pub status: PendingStatus,
    pub value:  serde_json::Value,
}

impl ServerConfig {
    /// Resolve the configuration from the command-line arguments, checking that
    /// all values have the correct formats.
    pub fn from_opts(config: &IdentityProviderServiceConfiguration) -> anyhow::Result<Self> {
        let ip_data_contents = fs::read_to_string(&config.identity_provider_file)?;
        let ar_info_contents = fs::read_to_string(&config.anonymity_revokers_file)?;
        let global_context_contents = fs::read_to_string(&config.global_context_file)?;
        let ip_data = from_str(&ip_data_contents)?;
        let versioned_global = from_str::<Versioned<_>>(&global_context_contents)?;
        let versioned_ar_infos = from_str::<Versioned<_>>(&ar_info_contents)?;
        ensure!(
            versioned_global.version == VERSION_0,
            "Unsupported global parameters version."
        );
        ensure!(
            versioned_ar_infos.version == VERSION_0,
            "Unsupported anonymity revokers version."
        );
        let mut submit_credential_url = config.wallet_proxy_base.clone();
        submit_credential_url.set_path("v0/submitCredential/");
        Ok(ServerConfig {
            ip_data,
            global: versioned_global.value,
            ars: versioned_ar_infos.value,
            id_verification_url: config.id_verification_url.clone(),
            retrieve_url: config.retrieve_url.clone(),
            submit_credential_url,
        })
    }
}

impl DB {
    /// Create a new database using the given root and backup_root paths.
    /// The 'backup_root' path is used to place deleted entries.
    ///
    /// This function will attempt to reconstruct the in-memory pending table if
    /// it finds any pending entries.
    pub fn new(root: std::path::PathBuf, backup_root: std::path::PathBuf) -> anyhow::Result<Self> {
        // Create the 'database' directories for storing IdentityObjects and
        // AnonymityRevocationRecords.
        fs::create_dir_all(root.join("revocation"))?;
        fs::create_dir_all(root.join("identity"))?;
        fs::create_dir_all(root.join("pending"))?;
        fs::create_dir_all(root.join("requests"))?;
        let mut hm = HashMap::new();
        for file in fs::read_dir(root.join("pending"))? {
            if let Ok(file) = file {
                if file.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    let name = file
                        .file_name()
                        .into_string()
                        .expect("Base16 strings are valid strings.");
                    let contents = fs::read_to_string(file.path())?;
                    let entry = from_str::<PendingEntry>(&contents)?;
                    hm.insert(name, entry);
                }
            }
        }
        let pending = Arc::new(Mutex::new(hm));
        Ok(Self {
            root,
            backup_root,
            pending,
        })
    }

    /// Write the validated request, so that it can be retrieved and used to
    /// create the identity object when the identity verifier calls with an
    /// attribute list and a verification result.
    pub fn write_request_record(
        &self,
        key: &str,
        identity_object_request: &IdentityObjectRequest,
    ) -> anyhow::Result<()> {
        let _lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            let file = std::fs::File::create(self.root.join("requests").join(key))?;
            serde_json::to_writer(file, identity_object_request)?;
        }
        Ok(())
    }

    /// Read a validated request under the given key.
    pub fn read_request_record(&self, key: &str) -> anyhow::Result<IdentityObjectRequest> {
        let contents = {
            let _lock = self
                .pending
                .lock()
                .expect("Cannot acquire a lock, which means something is very wrong.");
            fs::read_to_string(self.root.join("requests").join(key))?
        }; // drop the lock at this point
           // It is more efficient to read the whole thing, and then deserialize
        Ok(from_str::<IdentityObjectRequest>(&contents)?)
    }

    /// Write the anonymity revocation record under the given key.
    /// The key should be a valid filename.
    pub fn write_revocation_record(
        &self,
        key: &str,
        record: AnonymityRevocationRecord<ArCurve>,
    ) -> anyhow::Result<()> {
        let _lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            // FIXME: We should be careful to not overwrite here.
            let file = std::fs::File::create(self.root.join("revocation").join(key))?;
            serde_json::to_writer(file, &Versioned {
                version: VERSION_0,
                value:   record,
            })?;
        } // close the file
          // and now drop the lock as well.
        Ok(())
    }

    /// Write the identity object under the given key. The key should be
    /// a valid filename.
    pub fn write_identity_object(
        &self,
        key: &str,
        obj: &Versioned<IdentityObject<IpPairing, ArCurve, AttributeKind>>,
        init_credential: &Versioned<AccountCredential<IpPairing, ArCurve, AttributeKind>>,
    ) -> anyhow::Result<()> {
        let _lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            let file = std::fs::File::create(self.root.join("identity").join(key))?;
            let stored_obj = json!({
                "identityObject": obj,
                "accountAddress": AccountAddress::new(&obj.value.pre_identity_object.pub_info_for_ip.reg_id),
                "credential": init_credential
            });
            serde_json::to_writer(file, &stored_obj)?;
        }
        Ok(())
    }

    /// Try to read the identity object under the given key, if it exists.
    pub fn read_identity_object(&self, key: &str) -> anyhow::Result<serde_json::Value> {
        // ensure the key is valid base16 characters, which also ensures we are only
        // reading in the subdirectory FIXME: This is an inefficient way of
        // doing it.
        if hex::decode(key).is_err() {
            bail!("Invalid key.")
        }

        let contents = {
            let _lock = self
                .pending
                .lock()
                .expect("Cannot acquire a lock, which means something is very wrong.");
            fs::read_to_string(self.root.join("identity").join(key))?
        }; // drop the lock at this point
           // It is more efficient to read the whole thing, and then deserialize
        Ok(from_str::<serde_json::Value>(&contents)?)
    }

    /// Store the pending entry. This is only used in case of server-restart to
    /// pupulate the pending table.
    pub fn write_pending(
        &self,
        key: &str,
        status: PendingStatus,
        value: serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            let file = std::fs::File::create(self.root.join("pending").join(key))?;
            let value = PendingEntry { status, value };
            serde_json::to_writer(file, &value)?;
            lock.insert(key.to_string(), value);
        }
        Ok(())
    }

    pub fn mark_finalized(&self, key: &str) {
        let mut lock = self.pending.lock().unwrap();
        lock.remove(key);
        let pending_path = self.root.join("pending").join(key);
        std::fs::remove_file(pending_path).unwrap();
    }

    pub fn delete_all(&self, key: &str) {
        let mut lock = self.pending.lock().unwrap();
        let ar_record_path = self.root.join("revocation").join(key);
        let id_path = self.root.join("identity").join(key);
        let pending_path = self.root.join("pending").join(key);

        std::fs::rename(
            ar_record_path,
            self.backup_root.join("revocation").join(key),
        )
        .unwrap();
        std::fs::rename(id_path, self.backup_root.join("identity").join(key)).unwrap();
        std::fs::remove_file(pending_path).unwrap();
        lock.remove(key);
    }

    pub fn is_pending(&self, key: &str) -> bool { self.pending.lock().unwrap().get(key).is_some() }
}

#[derive(SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "lowercase")]
/// Status of a submission as returned by the wallet-proxy.
enum SubmissionStatus {
    /// Submission is absent, most likely it was invalid.
    Absent,
    /// Submission is received, but not yet committed to any blocks.
    Received,
    /// Submission is committed to one or more blocks.
    Committed,
    /// Submission is finalized in a block.
    Finalized,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// The part of the response we care about. Since the transaction
/// will either be in a block, or not, and if it is, then the account will have
/// been created.
struct SubmissionStatusResponse {
    status: SubmissionStatus,
}

/// Parameters of the get request.
#[derive(SerdeDeserialize)]
struct GetParameters {
    #[serde(rename = "state")]
    state: String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
}

/// Query the status of the transaction and update the status in the database if
/// finalized, or if unable to submit the transaction successfully.
async fn followup(
    client: Client,
    db: DB,
    submission_url: url::Url,
    mut query_url_base: url::Url,
    key: String,
) {
    let v = {
        let hm = db.pending.lock().unwrap();
        hm.get(&key).cloned()
    }; // release lock
    if let Some(v) = v {
        match &v.status {
            PendingStatus::CouldNotSubmit => {
                match submit_account_creation(&client, submission_url.clone(), &v.value).await {
                    Ok(new_status) => {
                        let mut hm = db.pending.lock().unwrap();
                        if let Some(point) = hm.get_mut(&key) {
                            point.status = new_status;
                        }
                    }
                    Err(_) => {
                        db.delete_all(&key);
                        warn!("Account creation transaction rejected.");
                    }
                }
            }
            PendingStatus::Submitted { submission_id, .. } => {
                query_url_base.set_path(&format!("v0/submissionStatus/{}", submission_id));
                match client.get(query_url_base.clone()).send().await {
                    Ok(response) => {
                        match response.status() {
                            StatusCode::OK => {
                                match response.json::<SubmissionStatusResponse>().await {
                                    Ok(ss) => {
                                        match ss.status {
                                            SubmissionStatus::Finalized => {
                                                db.mark_finalized(&key);
                                                info!("Account creation transaction finalized.");
                                            }
                                            SubmissionStatus::Absent => error!(
                                                "An account creation transaction has gone \
                                                 missing. This indicates a configuration error."
                                            ),
                                            // do nothing, wait for the next call
                                            SubmissionStatus::Received => {}
                                            SubmissionStatus::Committed => {}
                                        }
                                    }
                                    Err(e) => error!(
                                        "Received unexpected response when querying submission \
                                         status: {}.",
                                        e
                                    ),
                                }
                            }
                            other => error!(
                                "Received unexpected response when querying submission status: {}.",
                                other
                            ),
                        }
                    }
                    Err(e) => {
                        error!(
                            "Could not query submission status for {} due to: {}.",
                            key, e
                        );
                        // and do nothing
                    }
                }
            }
        }
    }
}

/// Checks the status of an initial account creation. A pending token is
/// returned if the account transaction has not finalized yet. If the
/// transaction is finalized then the identity object is returned.
async fn get_identity_token(
    server_config: Arc<ServerConfig>,
    retrieval_db: DB,
    client: Client,
    id_cred_pub: String,
) -> Result<impl Reply, Rejection> {
    // Check status of initial account creation transaction and update the file
    // database accordingly.
    let query_url_base = server_config.submit_credential_url.clone();
    followup(
        client,
        retrieval_db.clone(),
        server_config.submit_credential_url.clone(),
        query_url_base,
        id_cred_pub.clone(),
    )
    .await;

    // If the initial account creation transaction is still not finalized, then we
    // return a pending object to the caller to indicate that the identity is
    // not ready yet.
    if retrieval_db.is_pending(&id_cred_pub) {
        info!("Identity object is pending.");
        let identity_token_container = IdentityTokenContainer {
            status: IdentityStatus::Pending,
            detail: "Pending initial account creation.".to_string(),
            token:  serde_json::Value::Null,
        };
        Ok(warp::reply::json(&identity_token_container))
    } else {
        match retrieval_db.read_identity_object(&id_cred_pub) {
            Ok(identity_object) => {
                info!("Identity object found");

                let identity_token_container = IdentityTokenContainer {
                    status: IdentityStatus::Done,
                    token:  identity_object,
                    detail: "".to_string(),
                };
                Ok(warp::reply::json(&identity_token_container))
            }
            Err(_e) => {
                info!("Identity object does not exist or the request is malformed.");
                let error_identity_token_container = IdentityTokenContainer {
                    status: IdentityStatus::Error,
                    detail: "Identity object does not exist".to_string(),
                    token:  serde_json::Value::Null,
                };
                Ok(warp::reply::json(&error_identity_token_container))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let app = IdentityProviderServiceConfiguration::clap()
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .global_setting(clap::AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let opt = Arc::new(IdentityProviderServiceConfiguration::from_clap(&matches));

    info!("Reading the provided IP, AR and global context configurations.");

    let server_config = Arc::new(ServerConfig::from_opts(&opt)?);

    // Client used to make HTTP requests to both the id verifier,
    // as well as to submit the initial account creation.
    // We reuse it between requests since it is expensive to create.
    let client = Client::new();
    let followup_client = client.clone();

    // Create the 'database' directories for storing IdentityObjects and
    // AnonymityRevocationRecords.
    let db = DB::new(
        std::path::Path::new("database").to_path_buf(),
        std::path::Path::new("database-deleted").to_path_buf(),
    )?;
    info!("Configurations have been loaded successfully.");

    let retrieval_db = db.clone();
    let server_config_retrieve = Arc::clone(&server_config);

    // The endpoint for querying the identity object.
    let retrieve_identity = warp::get()
        .and(warp::path!("api" / "identity" / String))
        .and_then(move |id_cred_pub: String| {
            get_identity_token(
                server_config_retrieve.clone(),
                retrieval_db.clone(),
                followup_client.clone(),
                id_cred_pub,
            )
        });

    let server_config_validate = Arc::clone(&server_config);
    let server_config_validate_query = Arc::clone(&server_config);
    let server_config_forward = Arc::clone(&server_config);

    let db_arc = Arc::new(db);
    let verify_db = Arc::clone(&db_arc);
    let create_db = Arc::clone(&db_arc);

    // Endpoint for starting the identity creation flow. It will validate the
    // request and forward the user to the identity verification service.
    let verify_request = warp::post()
        .and(warp::filters::body::content_length_limit(50 * 1024))
        .and(warp::path!("api" / "identity"))
        .and(extract_and_validate_request(server_config_validate))
        .or(warp::get().and(warp::path!("api" / "identity")).and(
            extract_and_validate_request_query(server_config_validate_query),
        ))
        .unify()
        .and_then(move |idi| {
            save_validated_request(Arc::clone(&verify_db), idi, server_config_forward.clone())
        });

    // Endpoint for creating identities. The identity verification service will
    // forward the user to this endpoint after they have created a list of
    // verified attributes.
    let create_identity = warp::get()
        .and(warp::path!("api" / "identity" / "create" / String))
        .and_then(move |id_cred_pub: String| {
            create_signed_identity_object(
                Arc::clone(&server_config),
                Arc::clone(&create_db),
                client.clone(),
                id_cred_pub,
            )
        });

    info!("Booting up HTTP server. Listening on port {}.", opt.port);
    let server = verify_request
        .or(retrieve_identity)
        .or(create_identity)
        .recover(handle_rejection);
    warp::serve(server).run(([0, 0, 0, 0], opt.port)).await;
    Ok(())
}

/// A helper macro to check whether the expression is an error, an in that case
/// fail with internal server error.
macro_rules! ok_or_500 (
    ($e: expr, $s: expr) => {
        if $e.is_err() {
            error!($s);
            return Err(warp::reject::custom(IdRequestRejection::InternalError))
        }
    };
);

/// Save the validated request object to the database, and forward the calling
/// user to the identity verification process.
async fn save_validated_request(
    db: Arc<DB>,
    identity_object_request: IdentityObjectRequest,
    server_config: Arc<ServerConfig>,
) -> Result<impl Reply, Rejection> {
    let base_16_encoded_id_cred_pub = base16_encode_string(
        &identity_object_request
            .id_object_request
            .value
            .pub_info_for_ip
            .id_cred_pub,
    );

    // Sign the id_cred_pub so that the identity verifier can verify that the given
    // id_cred_pub matches a valid identity creation request.
    let public_key: PublicKey = server_config.ip_data.public_ip_info.ip_cdi_verify_key;
    let expanded_secret_key: ExpandedSecretKey =
        ExpandedSecretKey::from(&server_config.ip_data.ip_cdi_secret_key);
    let message = hex::decode(&base_16_encoded_id_cred_pub).unwrap();
    let signature_on_id_cred_pub = expanded_secret_key.sign(message.as_slice(), &public_key);
    let serialized_signature = base16_encode_string(&signature_on_id_cred_pub);

    ok_or_500!(
        db.write_request_record(&base_16_encoded_id_cred_pub, &identity_object_request),
        "Could not write the valid request to database."
    );

    let attribute_form_url = format!(
        "{}/{}/{}",
        server_config.id_verification_url.to_string(),
        base_16_encoded_id_cred_pub,
        serialized_signature
    );
    Ok(warp::reply::with_status(
        warp::reply::with_header(warp::reply(), LOCATION, attribute_form_url),
        StatusCode::FOUND,
    ))
}

/// Submit an account creation transaction. Return Ok if either the submission
/// was successful or if it failed due to reasons unrelated to the request
/// itself, e.g., we could not reach the server. Return Err(_) if the submission
/// is malformed for some reason.
async fn submit_account_creation(
    client: &Client,
    url: url::Url,
    submission: &serde_json::Value,
) -> Result<PendingStatus, String> {
    // Submit and wait for the submission ID.
    match client.put(url).json(submission).send().await {
        Ok(response) => {
            match response.status() {
                StatusCode::BAD_GATEWAY => {
                    // internal server error, retry later.
                    Ok(PendingStatus::CouldNotSubmit)
                }
                StatusCode::BAD_REQUEST => {
                    Err("Failed validation of the reuse of malformed initial account.".to_string())
                }
                StatusCode::OK => match response.json::<InitialAccountReponse>().await {
                    Ok(v) => {
                        let initial_status = PendingStatus::Submitted {
                            submission_id: v.submission_id,
                            status:        SubmissionStatus::Received,
                        };
                        Ok(initial_status)
                    }
                    Err(_) => Ok(PendingStatus::CouldNotSubmit),
                },
                other => {
                    error!("Unexpected response from the Wallet Proxy: {}", other);
                    // internal server error, retry later.
                    Ok(PendingStatus::CouldNotSubmit)
                }
            }
        }
        Err(e) => {
            // This almost certainly means we could not reach the server, or the server is
            // configured wrong. This should be considered an internal error and
            // we must retry.
            error!("Could not reach the wallet proxy due to: {}", e);
            Ok(PendingStatus::CouldNotSubmit)
        }
    }
}

#[derive(Debug)]
/// An internal error type used by this server to manage error handling.
enum IdRequestRejection {
    /// Request was made with an unsupported version of the identity object.
    UnsupportedVersion,
    /// The request had invalid proofs.
    InvalidProofs,
    /// The identity verifier could not validate the supporting evidence, e.g.,
    /// passport.
    IdVerifierFailure,
    /// Internal server error occurred.
    InternalError,
    /// Registration ID was reused, leading to initial account creation failure.
    ReuseOfRegId,
    /// Malformed request.
    Malformed,
    /// Missing validated request for the given id_cred_pub
    NoValidRequest,
}

impl warp::reject::Reject for IdRequestRejection {}

#[derive(SerdeSerialize)]
/// Response in case of an error. This is going to be encoded as a JSON body
/// with fields 'code' and 'message'.
struct ErrorResponse {
    code:    u16,
    message: &'static str,
}

/// Helper function to make the reply.
fn mk_reply(message: &'static str, code: StatusCode) -> impl warp::Reply {
    let msg = ErrorResponse {
        message,
        code: code.as_u16(),
    };
    warp::reply::with_status(warp::reply::json(&msg), code)
}

async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
    if err.is_not_found() {
        let code = StatusCode::NOT_FOUND;
        let message = "Not found.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::UnsupportedVersion) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Unsupported version.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::InvalidProofs) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Invalid proofs.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::IdVerifierFailure) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "ID verifier rejected..";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::InternalError) = err.find() {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        let message = "Internal server error";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::ReuseOfRegId) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Reuse of RegId";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::Malformed) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Malformed request.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRequestRejection::NoValidRequest) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "No validated request was found for the given id_cred_pub.";
        Ok(mk_reply(message, code))
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        let code = StatusCode::BAD_REQUEST;
        let message = "Malformed body.";
        Ok(mk_reply(message, code))
    } else {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        let message = "Internal error.";
        Ok(mk_reply(message, code))
    }
}

/// Checks for a validated request and checks with the identity verifier if
/// there is a verified attribute list for this person. If there is an attribute
/// list, then it is used to create the identity object that is then signed and
/// saved. If successful a re-direct to the URL where the identity object is
/// available is returned.
async fn create_signed_identity_object(
    server_config: Arc<ServerConfig>,
    db: Arc<DB>,
    client: Client,
    id_cred_pub_input: String,
) -> Result<impl Reply, Rejection> {
    // Read the validated request from the database.
    let identity_object_input = match db.read_request_record(&id_cred_pub_input) {
        Ok(request) => request,
        Err(e) => {
            error!(
                "Unable to read validated request for id_cred_pub {}, {}",
                id_cred_pub_input, e
            );
            return Err(warp::reject::custom(IdRequestRejection::NoValidRequest));
        }
    };

    let base16_encoded_id_cred_pub = base16_encode_string(
        &identity_object_input
            .id_object_request
            .value
            .pub_info_for_ip
            .id_cred_pub,
    );
    let request = identity_object_input.id_object_request.value;

    // Identity verification process between the identity provider and the identity
    // verifier. In this example the identity verifier is queried and will
    // return the attribute list that the user submitted to the identity verifier.
    // If there is no attribute list, then it corresponds to the user not having
    // been verified, and the request will fail.
    let attribute_list_url = format!(
        "{}{}{}",
        server_config.id_verification_url.clone(),
        "/attributes/",
        base16_encoded_id_cred_pub
    );
    let attribute_list = match client
        .get(Url::parse(&attribute_list_url).unwrap())
        .send()
        .await
    {
        Ok(attribute_list) => match attribute_list.json().await {
            Ok(attribute_list) => attribute_list,
            Err(e) => {
                error!("Could not deserialize response from the verifier {}.", e);
                return Err(warp::reject::custom(IdRequestRejection::IdVerifierFailure));
            }
        },
        Err(e) => {
            error!(
                "Could not retrieve attribute list from the verifier: {}.",
                e
            );
            return Err(warp::reject::custom(IdRequestRejection::InternalError));
        }
    };

    // At this point the identity has been verified, and the identity provider
    // constructs the identity object and signs it. An anonymity revocation
    // record and the identity object are persisted, so that they can be
    // retrieved when needed. The constructed response contains a redirect to a
    // webservice that returns the identity object constructed here.

    // This is hardcoded for the proof-of-concept.
    // Expiry is a year from now.
    let now = YearMonth::now();
    let valid_to_next_year = YearMonth {
        year:  now.year + 1,
        month: now.month,
    };

    let alist = ExampleAttributeList {
        valid_to:     valid_to_next_year,
        created_at:   now,
        alist:        attribute_list,
        max_accounts: 200,
        _phantom:     Default::default(),
    };

    let signature = match sign_identity_object(
        &request,
        &server_config.ip_data.public_ip_info,
        &alist,
        &server_config.ip_data.ip_secret_key,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            error!("Could not sign the identity object {}.", e);
            return Err(warp::reject::custom(IdRequestRejection::InternalError));
        }
    };

    let base16_encoded_id_cred_pub = base16_encode_string(&request.pub_info_for_ip.id_cred_pub);

    ok_or_500!(
        save_revocation_record(&db, &request, &alist),
        "Could not write the revocation record to database."
    );

    let id = IdentityObject {
        pre_identity_object: request,
        alist,
        signature,
    };

    let versioned_id = Versioned::new(VERSION_0, id);

    let message_expiry = TransactionTime {
        seconds: chrono::offset::Utc::now().timestamp() as u64 + 300, // 5min expiry.
    };

    // As a last step we submit the initial account creation to the chain.
    // TODO: We should check beforehand that the regid is fresh and that
    // no account with this regid already exists, since that will lead to failure of
    // account creation.
    let initial_cdi = create_initial_cdi(
        &server_config.ip_data.public_ip_info,
        versioned_id
            .value
            .pre_identity_object
            .pub_info_for_ip
            .clone(),
        &versioned_id.value.alist,
        message_expiry,
        &server_config.ip_data.ip_cdi_secret_key,
    );

    let versioned_credential =
        Versioned::new(VERSION_0, AccountCredential::<IpPairing, _, _>::Initial {
            icdi: initial_cdi,
        });

    // Store the created IdentityObject.
    // This is stored so it can later be retrieved by querying via the idCredPub.
    ok_or_500!(
        db.write_identity_object(
            &base16_encoded_id_cred_pub,
            &versioned_id,
            &versioned_credential
        ),
        "Could not write to database."
    );

    let submission = AccountCredentialMessage {
        message_expiry,
        credential: versioned_credential.value,
    };

    // The proxy expects a versioned submission, so that is what we construction.
    let versioned_submission = Versioned::new(VERSION_0, submission);
    // Submit and wait for the submission ID.
    let submission_value = to_value(versioned_submission).unwrap();

    match submit_account_creation(
        &client,
        server_config.submit_credential_url.clone(),
        &submission_value,
    )
    .await
    {
        Ok(status) => {
            ok_or_500!(
                db.write_pending(&base16_encoded_id_cred_pub, status, submission_value),
                "Could not write submission status."
            );
        }
        Err(_) => return Err(warp::reject::custom(IdRequestRejection::ReuseOfRegId)),
    };
    // If we reached here it means we at least have a pending request. We respond
    // with a URL where they will be able to retrieve the ID object.

    // The callback_location has to point to the location where the wallet can
    // retrieve the identity object when it is available.
    let mut retrieve_url = server_config.retrieve_url.clone();
    retrieve_url.set_path(&format!("api/identity/{}", base16_encoded_id_cred_pub));
    let callback_location =
        identity_object_input.redirect_uri.clone() + "#code_uri=" + retrieve_url.as_str();

    info!("Identity was successfully created. Returning URI where it can be retrieved.");

    Ok(warp::reply::with_status(
        warp::reply::with_header(warp::reply(), LOCATION, callback_location),
        StatusCode::FOUND,
    ))
}

/// A common function that validates the cryptographic proofs in the request.
fn validate_worker(
    server_config: &Arc<ServerConfig>,
    input: IdentityObjectRequest,
) -> Result<IdentityObjectRequest, IdRequestRejection> {
    if input.id_object_request.version != VERSION_0 {
        return Err(IdRequestRejection::UnsupportedVersion);
    }
    let request = &input.id_object_request.value;
    let context = IPContext {
        ip_info:        &server_config.ip_data.public_ip_info,
        ars_infos:      &server_config.ars.anonymity_revokers,
        global_context: &server_config.global,
    };
    match ip_validate_request(request, context) {
        Ok(()) => {
            info!("Request is valid.");
            Ok(input)
        }
        Err(e) => {
            warn!("Request is invalid {}.", e);
            Err(IdRequestRejection::InvalidProofs)
        }
    }
}

/// Validate that the received request is well-formed.
/// This check that all the cryptographic values are valid, and that the zero
/// knowledge proofs in the request are valid.
///
/// The return value is either
///
/// - Ok(ValidatedRequest) if the request is valid or
/// - Err(msg) where `msg` is a string describing the error.
fn extract_and_validate_request(
    server_config: Arc<ServerConfig>,
) -> impl Filter<Extract = (IdentityObjectRequest,), Error = Rejection> + Clone {
    warp::body::json().and_then(move |input: IdentityObjectRequest| {
        let server_config = server_config.clone();
        async move {
            info!("Queried for creating an identity");

            match validate_worker(&server_config, input) {
                Ok(r) => Ok(r),
                Err(e) => {
                    warn!("Request is invalid {:#?}.", e);
                    Err(warp::reject::custom(e))
                }
            }
        }
    })
}

/// Validate that the received request is well-formed.
/// This check that all the cryptographic values are valid, and that the zero
/// knowledge proofs in the request are valid.
///
/// The return value is either
///
/// - Ok(ValidatedRequest) if the request is valid or
/// - Err(msg) where `msg` is a string describing the error.
fn extract_and_validate_request_query(
    server_config: Arc<ServerConfig>,
) -> impl Filter<Extract = (IdentityObjectRequest,), Error = Rejection> + Clone {
    warp::query().and_then(move |input: GetParameters| {
        let server_config = server_config.clone();
        async move {
            info!("Queried for creating an identity");

            let id_object_request = match from_str::<serde_json::Value>(&input.state)
                .ok()
                .and_then(|mut v| match v.get_mut("idObjectRequest") {
                    Some(v) => Some(v.take()),
                    None => None,
                })
                .and_then(|v| serde_json::from_value::<Versioned<_>>(v).ok())
            {
                Some(v) => v,
                None => return Err(warp::reject::custom(IdRequestRejection::Malformed)),
            };
            match validate_worker(&server_config, IdentityObjectRequest {
                id_object_request,
                redirect_uri: input.redirect_uri,
            }) {
                Ok(v) => {
                    info!("Request is valid.");
                    Ok(v)
                }
                Err(e) => {
                    warn!("Request is invalid {:#?}.", e);
                    Err(warp::reject::custom(e))
                }
            }
        }
    })
}

/// Creates and saves the revocation record to the file system (which should be
/// a database, but for the proof-of-concept we use the file system).
fn save_revocation_record<A: Attribute<id::constants::BaseField>>(
    db: &DB,
    pre_identity_object: &PreIdentityObject<IpPairing, ArCurve>,
    alist: &AttributeList<id::constants::BaseField, A>,
) -> anyhow::Result<()> {
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub:  pre_identity_object.pub_info_for_ip.id_cred_pub,
        ar_data:      pre_identity_object.ip_ar_data.clone(),
        max_accounts: alist.max_accounts,
    };
    let base16_id_cred_pub = base16_encode_string(&ar_record.id_cred_pub);
    db.write_revocation_record(&base16_id_cred_pub, ar_record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test;

    #[test]
    fn test_successful_validation_and_response() {
        // Given
        let request = include_str!("../../data/valid_request.json");
        let ip_data_contents = include_str!("../../data/identity_provider.json");
        let ar_info_contents = include_str!("../../data/anonymity_revokers.json");
        let global_context_contents = include_str!("../../data/global.json");

        let ip_data: IpData<IpPairing> = from_str(&ip_data_contents)
            .expect("File did not contain a valid IpData object as JSON.");
        let ar_info: Versioned<ArInfos<ArCurve>> = from_str(&ar_info_contents)
            .expect("File did not contain a valid ArInfos object as JSON");
        assert_eq!(ar_info.version, VERSION_0, "Unsupported ArInfo version.");
        let ars = ar_info.value;
        let global_context: Versioned<GlobalContext<ArCurve>> = from_str(&global_context_contents)
            .expect("File did not contain a valid GlobalContext object as JSON");
        assert_eq!(global_context.version, VERSION_0);
        let global = global_context.value;

        let server_config = Arc::new(ServerConfig {
            ip_data,
            global,
            ars,
            id_verification_url: url::Url::parse("http://localhost/verify").unwrap(),
            retrieve_url: url::Url::parse("http://localhost/retrieve").unwrap(),
            submit_credential_url: url::Url::parse("http://localhost/submitCredential").unwrap(),
        });

        tokio_test::block_on(async {
            let v = serde_json::from_str::<serde_json::Value>(request).unwrap();
            let matches = test::request()
                .method("POST")
                .json(&v)
                .matches(&extract_and_validate_request(server_config.clone()))
                .await;
            // Then
            assert!(matches, "The filter does not match the example request.");
        });
    }

    #[test]
    fn test_verify_failed_validation() {
        // Given
        let request = include_str!("../../data/fail_validation_request.json");
        let ip_data_contents = include_str!("../../data/identity_provider.json");
        let ar_info_contents = include_str!("../../data/anonymity_revokers.json");
        let global_context_contents = include_str!("../../data/global.json");

        let ip_data: IpData<IpPairing> = from_str(&ip_data_contents)
            .expect("File did not contain a valid IpData object as JSON.");
        let ar_info: Versioned<ArInfos<ArCurve>> = from_str(&ar_info_contents)
            .expect("File did not contain a valid ArInfos object as JSON");
        assert_eq!(ar_info.version, VERSION_0, "Unsupported ArInfo version.");
        let ars = ar_info.value;
        let global_context: Versioned<GlobalContext<ArCurve>> = from_str(&global_context_contents)
            .expect("File did not contain a valid GlobalContext object as JSON");
        assert_eq!(global_context.version, VERSION_0);
        let global = global_context.value;

        let server_config = Arc::new(ServerConfig {
            ip_data,
            global,
            ars,
            id_verification_url: url::Url::parse("http://localhost/verify").unwrap(),
            retrieve_url: url::Url::parse("http://localhost/retrieve").unwrap(),
            submit_credential_url: url::Url::parse("http://localhost/submitCredential").unwrap(),
        });

        tokio_test::block_on(async {
            let v = serde_json::from_str::<serde_json::Value>(request).unwrap();
            let matches = test::request()
                .method("POST")
                .json(&v)
                .filter(&extract_and_validate_request(server_config.clone()))
                .await;
            if let Err(e) = matches {
                if let Some(IdRequestRejection::InvalidProofs) = e.find() {
                } else {
                    assert!(false, "Request should fail due to invalid proofs.")
                }
            } else {
                assert!(false, "Invalid request should not pass the filter.")
            }
        });
    }
}
