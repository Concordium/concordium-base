use anyhow::ensure;
use crypto_common::{
    base16_encode_string, to_bytes, types::TransactionTime, SerdeDeserialize, SerdeSerialize,
    Versioned, VERSION_0,
};
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
use id::{
    constants::{ArCurve, AttributeKind, IpPairing},
    identity_provider::{
        create_initial_cdi, sign_identity_object, sign_identity_object_v1,
        validate_id_recovery_request, validate_request as ip_validate_request,
        validate_request_v1 as ip_validate_request_v1,
    },
    types::*,
};
use log::{error, info, warn};
use reqwest::Client;
use serde_json::{from_str, json, to_value};
use sha2::{Digest, Sha256};
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
        help = "URL of the identity verifier. This is the URL where the user will be redirected \
                to.",
        default_value = "http://localhost:8101/api/verify",
        env = "ID_VERIFICATION_URL"
    )]
    id_verification_url: url::Url,
    #[structopt(
        long = "id-verification-query-url",
        help = "URL of the identity verifier. This is where the provider will query for the \
                result of verification. If not given it defaults to `id-verification-url`. This \
                is intended to use in situations where the identity provider has a private \
                connection to the verifier to retrieve data, e.g., where the verifier and the \
                provider run in different docker containers on the same machine.",
        env = "ID_VERIFICATION_QUERY_URL"
    )]
    id_verification_query_url: Option<url::Url>,
    #[structopt(
        long = "wallet-proxy-base",
        help = "URL of the wallet-proxy.",
        env = "WALLET_PROXY_BASE"
    )]
    wallet_proxy_base: url::Url,
    #[structopt(
        long = "recovery-timestamp-delta",
        help = "Number of seconds that the recovery request timestamp should be close to the IDPs \
                current time when requesting for recovery. Example: If delta is 60, the IDP will \
                accept recovery request timestamps within [current_time - 60, current_time + 60]. ",
        env = "RECOVERY-TIMESTAMP-DELTA",
        default_value = "60"
    )]
    timestamp_delta: u64,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// The identity object request sent by the wallet in the body of the POST
/// request. The 'Deserialize' instance is automatically derived to parse the
/// expected format.
struct IdentityObjectRequest {
    #[serde(rename = "idObjectRequest")]
    id_object_request: Versioned<PreIdentityObject<IpPairing, ArCurve>>,
    #[serde(rename = "redirectURI")]
    redirect_uri:      String,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// The version 1 identity object request sent by the wallet. The 'Deserialize'
/// instance is automatically derived to parse the expected format.
struct IdentityObjectRequestV1 {
    #[serde(rename = "idObjectRequest")]
    id_object_request: Versioned<PreIdentityObjectV1<IpPairing, ArCurve>>,
    #[serde(rename = "redirectURI")]
    redirect_uri:      String,
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
#[derive(SerdeSerialize, SerdeDeserialize)]
struct IdentityTokenContainer {
    /// The status of the submission.
    status: IdentityStatus,
    /// The response, if available, otherwise Null.
    token:  serde_json::Value,
    /// Details of the response in the form of a free-form text.
    detail: String,
}

/// The state the server maintains in-between the requests, consisting of
/// the resolved configuration. In particular in this prototype the private keys
/// are maintain in-memory.
struct ServerConfig {
    ip_data: IpData<IpPairing>,
    global: GlobalContext<ArCurve>,
    ars: ArInfos<ArCurve>,
    id_verification_url: url::Url,
    id_verification_query_url: url::Url,
    retrieve_url: url::Url,
    submit_credential_url: url::Url,
    recovery_timestamp_delta: u64,
}

/// A mockup of a database to store all the data.
/// In production this would be a real database, here we store everything as
/// files on disk and synchronize access to disk via a lock. On deletion files
/// are moved into a 'backup_root' folder.
#[derive(Clone)]
struct DB {
    /// Root directory where all the data is stored.
    root:        std::path::PathBuf,
    /// Root of the backup directory where we store "deleted" files.
    backup_root: std::path::PathBuf,
    /// And a hashmap of pending entries. Pending entries are also stored in the
    /// filesystem, but we cache them here since they have to be accessed
    /// often. We put it behind a mutex to sync all accesses, to the hashmap
    /// as well as to the filesystem, which is implicit. In a real database
    /// this would be done differently.
    pending:     Arc<Mutex<HashMap<String, PendingEntry>>>,
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

#[derive(SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WithExpiry {
    pub expiry: YearMonth,
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
            id_verification_query_url: config
                .id_verification_query_url
                .as_ref()
                .cloned()
                .unwrap_or_else(|| config.id_verification_url.clone()),
            retrieve_url: config.retrieve_url.clone(),
            submit_credential_url,
            recovery_timestamp_delta: config.timestamp_delta,
        })
    }
}

/// Helper function for checking hex strings.
fn ensure_safe_key(key: &str) -> anyhow::Result<()> {
    ensure!(key.len() < 200, "Key too long.");
    // ensure the key is valid base16 characters, which also ensures we are only
    // reading in the subdirectory
    ensure!(hex::decode(key).is_ok(), "Invalid hex string.");
    Ok(())
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
        for file in fs::read_dir(root.join("pending"))?.flatten() {
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

    /// Write the validated version 1 request, so that it can be retrieved and
    /// used to create the version 1 identity object when the identity
    /// verifier calls with an attribute list and a verification result.
    pub fn write_request_record_v1(
        &self,
        key: &str,
        identity_object_request: &IdentityObjectRequestV1,
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
        ensure_safe_key(key)?;
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

    /// Read a validated version 1 request under the given key.
    pub fn read_request_record_v1(&self, key: &str) -> anyhow::Result<IdentityObjectRequestV1> {
        ensure_safe_key(key)?;
        let contents = {
            let _lock = self
                .pending
                .lock()
                .expect("Cannot acquire a lock, which means something is very wrong.");
            fs::read_to_string(self.root.join("requests").join(key))?
        }; // drop the lock at this point
           // It is more efficient to read the whole thing, and then deserialize
        Ok(from_str::<IdentityObjectRequestV1>(&contents)?)
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
        init_credential: &Versioned<AccountCredentialMessage<IpPairing, ArCurve, AttributeKind>>,
    ) -> anyhow::Result<()> {
        let _lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            let file = std::fs::File::create(self.root.join("identity").join(key))?;
            let stored_obj = json!({
                "identityObject": obj,
                "accountAddress": account_address_from_registration_id(&obj.value.pre_identity_object.pub_info_for_ip.reg_id),
                "credential": init_credential
            });
            serde_json::to_writer(file, &stored_obj)?;
        }
        Ok(())
    }

    /// Write the version 1 identity object under the given key. The key should
    /// be a valid filename.
    pub fn write_identity_object_v1(
        &self,
        key: &str,
        obj: &Versioned<IdentityObjectV1<IpPairing, ArCurve, AttributeKind>>,
    ) -> anyhow::Result<()> {
        let _lock = self
            .pending
            .lock()
            .expect("Cannot acquire a lock, which means something is very wrong.");
        {
            let file = std::fs::File::create(self.root.join("identity").join(key))?;
            let stored_obj = json!({ "identityObject": obj });
            serde_json::to_writer(file, &stored_obj)?;
        }
        Ok(())
    }

    /// Try to read the identity object under the given key, if it exists.
    pub fn read_identity_object(&self, key: &str) -> anyhow::Result<serde_json::Value> {
        ensure_safe_key(key)?;

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
        if lock.remove(key).is_some() {
            let pending_path = self.root.join("pending").join(key);
            if let Err(e) = std::fs::remove_file(pending_path) {
                error!("Could not delete pending file: {}", e);
            }
        } else {
            log::debug!(
                "{} could not be marked as finalized, as it has already been removed from the \
                 pending list.",
                key
            );
        }
    }

    pub fn delete_all(&self, key: &str) {
        let mut lock = self.pending.lock().unwrap();
        if lock.remove(key).is_some() {
            let ar_record_path = self.root.join("revocation").join(key);
            let id_path = self.root.join("identity").join(key);
            let pending_path = self.root.join("pending").join(key);

            if let Err(e) = std::fs::rename(
                ar_record_path,
                self.backup_root.join("revocation").join(key),
            ) {
                error!("Could not back up the revocation record: {}", e);
            }
            if let Err(e) = std::fs::rename(id_path, self.backup_root.join("identity").join(key)) {
                error!("Could not back up the identity object: {}", e);
            }
            if let Err(e) = std::fs::remove_file(pending_path) {
                error!("Could not delete pending file: {}.", e)
            }
        } else {
            log::debug!(
                "{} could not be deleted, as it has already been removed from the pending list.",
                key
            );
        }
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
    state:        String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
}

/// Parameters of the get request.
#[derive(SerdeDeserialize)]
struct RecoveryGetParameters {
    #[serde(rename = "state")]
    state: String,
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
    id_cred_pub_hash: String,
) -> Result<impl Reply, Rejection> {
    // Check status of initial account creation transaction and update the file
    // database accordingly.
    let query_url_base = server_config.submit_credential_url.clone();
    followup(
        client,
        retrieval_db.clone(),
        server_config.submit_credential_url.clone(),
        query_url_base,
        id_cred_pub_hash.clone(),
    )
    .await;

    // If the initial account creation transaction is still not finalized, then we
    // return a pending object to the caller to indicate that the identity is
    // not ready yet.
    if retrieval_db.is_pending(&id_cred_pub_hash) {
        info!("Identity object is pending.");
        let identity_token_container = IdentityTokenContainer {
            status: IdentityStatus::Pending,
            detail: "Pending initial account creation.".to_string(),
            token:  serde_json::Value::Null,
        };
        Ok(warp::reply::json(&identity_token_container))
    } else {
        match retrieval_db.read_identity_object(&id_cred_pub_hash) {
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

/// Returns the version 1 identity object in the version 1 flow. No initial
/// account involved.
async fn get_identity_token_v1(
    retrieval_db: DB,
    id_cred_pub_hash: String,
) -> Result<impl Reply, Rejection> {
    match retrieval_db.read_identity_object(&id_cred_pub_hash) {
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
    let client_v1 = client.clone();

    // Create the 'database' directories for storing IdentityObjects and
    // AnonymityRevocationRecords.
    let db = DB::new(
        std::path::Path::new("database").to_path_buf(),
        std::path::Path::new("database-deleted").to_path_buf(),
    )?;
    info!("Configurations have been loaded successfully.");

    let retrieval_db = db.clone();
    let retrieval_db_v1 = db.clone();
    let recovery_db = db.clone();
    let server_config_retrieve = Arc::clone(&server_config);

    // The endpoint for querying the identity object.
    let retrieve_identity = warp::get()
        .and(warp::path!("api" / "v0" / "identity" / String))
        .and_then(move |id_cred_pub_hash: String| {
            get_identity_token(
                server_config_retrieve.clone(),
                retrieval_db.clone(),
                followup_client.clone(),
                id_cred_pub_hash,
            )
        });

    // The endpoint for querying the version 1 identity object.
    let retrieve_identity_v1 = warp::get()
        .and(warp::path!("api" / "v1" / "identity" / String))
        .and_then(move |id_cred_pub_hash: String| {
            get_identity_token_v1(retrieval_db_v1.clone(), id_cred_pub_hash)
        });

    let server_config_validate = Arc::clone(&server_config);
    let server_config_validate_query = Arc::clone(&server_config);
    let server_config_validate_query_v1 = Arc::clone(&server_config);
    let server_config_forward = Arc::clone(&server_config);
    let server_config_forward_v1 = Arc::clone(&server_config);
    let server_config_create_v1 = Arc::clone(&server_config);
    let server_config_validate_recovery = Arc::clone(&server_config);
    let server_config_fail = Arc::clone(&server_config);

    let db_arc = Arc::new(db);
    let verify_db = Arc::clone(&db_arc);
    let verify_db_v1 = Arc::clone(&db_arc);
    let create_db = Arc::clone(&db_arc);
    let create_db_v1 = Arc::clone(&db_arc);
    let fail_db = Arc::clone(&db_arc);

    // Endpoint for starting the identity creation flow. It will validate the
    // request and forward the user to the identity verification service.
    let verify_request = warp::post()
        .and(warp::filters::body::content_length_limit(50 * 1024))
        .and(warp::path!("api" / "v0" / "identity"))
        .and(extract_and_validate_request(server_config_validate))
        .or(warp::get().and(warp::path!("api" / "v0" / "identity")).and(
            extract_and_validate_request_query(server_config_validate_query),
        ))
        .unify()
        .and_then(move |idi| {
            save_validated_request(Arc::clone(&verify_db), idi, server_config_forward.clone())
        });

    // Endpoint for starting the version 1 identity creation flow, without the
    // creation of an initial account. It will validate the request and forward
    // the user to the identity verification service.
    let verify_request_v1 = warp::get()
        .and(warp::path!("api" / "v1" / "identity"))
        .and(extract_and_validate_request_query_v1(
            server_config_validate_query_v1,
        ))
        .and_then(move |idi| {
            save_validated_request_v1(
                Arc::clone(&verify_db_v1),
                idi,
                server_config_forward_v1.clone(),
            )
        });

    // Endpoint for creating identities. The identity verification service will
    // forward the user to this endpoint after they have created a list of
    // verified attributes.
    let create_identity = warp::get()
        .and(warp::path!("api" / "v0" / "identity" / "create" / String))
        .and(warp::query::<WithExpiry>())
        .and_then(move |id_cred_pub_hash: String, parameters: WithExpiry| {
            create_signed_identity_object(
                Arc::clone(&server_config),
                Arc::clone(&create_db),
                client.clone(),
                id_cred_pub_hash,
                parameters.expiry,
            )
        });

    // Endpoint for creating identities. The identity verification service will
    // forward the user to this endpoint after they have created a list of
    // verified attributes.
    let create_identity_v1 = warp::get()
        .and(warp::path!("api" / "v1" / "identity" / "create" / String))
        .and(warp::query::<WithExpiry>())
        .and_then(move |id_cred_pub_hash: String, parameters: WithExpiry| {
            create_signed_identity_object_v1(
                Arc::clone(&server_config_create_v1),
                Arc::clone(&create_db_v1),
                client_v1.clone(),
                id_cred_pub_hash,
                parameters.expiry,
            )
        });

    // Endpoint for creating failed identities. The identity verification service
    // will forward the user to this endpoint after they have created a list of
    // verified attributes, and chosen to fail the identity.
    // N.B. This is used for testing
    let fail_identity = warp::get()
        .and(warp::path!("api" / String / "identity" / "fail" / String))
        .and(warp::query())
        .and_then(
            move |version: String, id_cred_pub_hash: String, query: HashMap<String, String>| {
                let delay = match query.get("delay").and_then(|d| d.parse::<i64>().ok()) {
                    Some(d) => d,
                    None => {
                        warn!("No delay query parameter present at identity/fail");
                        10
                    }
                };

                create_failed_identity(
                    Arc::clone(&server_config_fail),
                    Arc::clone(&fail_db),
                    id_cred_pub_hash,
                    version,
                    delay,
                )
            },
        );

    // The endpoint for querying a intentionally failed identity object.
    // N.B. This is used for testing
    let retrieve_failed_identity = warp::get()
        .and(warp::path!("api" / "identity" / "retrieve_failed" / i64))
        .and_then(retrieve_failed_identity_token);

    let recover_identity =
        warp::get()
            .and(warp::path!("api" / "v1" / "recover"))
            .and(validate_recovery_request(
                server_config_validate_recovery,
                recovery_db,
            ));

    // A broken Endpoint for starting the identity creation flow
    // It will always return an error.
    // N.B. This is used for testing
    let broken_endpoint = warp::get()
        .and(warp::path!("api" / "broken" / "identity"))
        .and_then(get_broken_reply);

    info!("Booting up HTTP server. Listening on port {}.", opt.port);
    let server = verify_request
        .or(retrieve_identity)
        .or(retrieve_failed_identity)
        .or(create_identity)
        .or(fail_identity)
        .or(verify_request_v1)
        .or(retrieve_identity_v1)
        .or(create_identity_v1)
        .or(recover_identity)
        .or(broken_endpoint)
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
    let id_cred_pub = &identity_object_request
        .id_object_request
        .value
        .pub_info_for_ip
        .id_cred_pub;

    let id_cred_pub_hash = Sha256::digest(&to_bytes(id_cred_pub));
    let base_16_encoded_id_cred_pub_hash =
        base16_encode_string::<[u8; 32]>(&id_cred_pub_hash.into());

    // Sign the id_cred_pub so that the identity verifier can verify that the given
    // id_cred_pub matches a valid identity creation request.
    let public_key: PublicKey = server_config.ip_data.public_ip_info.ip_cdi_verify_key;
    let expanded_secret_key: ExpandedSecretKey =
        ExpandedSecretKey::from(&server_config.ip_data.ip_cdi_secret_key);
    let signature_on_id_cred_pub =
        expanded_secret_key.sign(id_cred_pub_hash.as_slice(), &public_key);
    let serialized_signature = base16_encode_string(&signature_on_id_cred_pub);

    ok_or_500!(
        db.write_request_record(&base_16_encoded_id_cred_pub_hash, &identity_object_request),
        "Could not write the valid request to database."
    );

    let attribute_form_url = format!(
        "{}/v0/{}/{}",
        server_config.id_verification_url, base_16_encoded_id_cred_pub_hash, serialized_signature
    );
    Ok(warp::reply::with_status(
        warp::reply::with_header(warp::reply(), LOCATION, attribute_form_url),
        StatusCode::FOUND,
    ))
}

/// Save the validated version 1 request object to the database, and forward the
/// calling user to the identity verification process.
async fn save_validated_request_v1(
    db: Arc<DB>,
    identity_object_request: IdentityObjectRequestV1,
    server_config: Arc<ServerConfig>,
) -> Result<impl Reply, Rejection> {
    let id_cred_pub = &identity_object_request.id_object_request.value.id_cred_pub;

    let id_cred_pub_hash = Sha256::digest(&to_bytes(id_cred_pub));
    let base_16_encoded_id_cred_pub_hash =
        base16_encode_string::<[u8; 32]>(&id_cred_pub_hash.into());

    // Sign the id_cred_pub so that the identity verifier can verify that the given
    // id_cred_pub matches a valid identity creation request.
    let public_key: PublicKey = server_config.ip_data.public_ip_info.ip_cdi_verify_key;
    let expanded_secret_key: ExpandedSecretKey =
        ExpandedSecretKey::from(&server_config.ip_data.ip_cdi_secret_key);
    let signature_on_id_cred_pub =
        expanded_secret_key.sign(id_cred_pub_hash.as_slice(), &public_key);
    let serialized_signature = base16_encode_string(&signature_on_id_cred_pub);

    ok_or_500!(
        db.write_request_record_v1(&base_16_encoded_id_cred_pub_hash, &identity_object_request),
        "Could not write the valid request to database."
    );

    let attribute_form_url = format!(
        "{}/v1/{}/{}",
        server_config.id_verification_url, base_16_encoded_id_cred_pub_hash, serialized_signature
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

#[derive(Debug)]
/// An internal error type used by this server to manage error handling.
enum IdRecoveryRejection {
    /// Recovery request was made with an unsupported version of the identity
    /// object.
    UnsupportedVersion,
    /// The recovery request proof was invalid.
    InvalidProofs,
    /// Malformed request.
    Malformed,
    /// The recovery request timestamp was invalid.
    InvalidTimestamp,
    /// The recovery request was valid, but the ID object was not found in the
    /// database.
    NonExistingIdObject,
}

impl warp::reject::Reject for IdRequestRejection {}
impl warp::reject::Reject for IdRecoveryRejection {}

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
        let message = "ID verifier rejected.";
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
    } else if let Some(IdRecoveryRejection::InvalidProofs) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Invalid ID recovery proof.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRecoveryRejection::NonExistingIdObject) = err.find() {
        let code = StatusCode::NOT_FOUND;
        let message = "ID object not found in database.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRecoveryRejection::InvalidTimestamp) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Invalid timestamp.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRecoveryRejection::Malformed) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Malformed ID recovery request.";
        Ok(mk_reply(message, code))
    } else if let Some(IdRecoveryRejection::UnsupportedVersion) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Unsupported version.";
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
    id_cred_pub_hash: String,
    expiry: YearMonth,
) -> Result<impl Reply, Rejection> {
    // Read the validated request from the database.
    let identity_object_input = match db.read_request_record(&id_cred_pub_hash) {
        Ok(request) => request,
        Err(e) => {
            error!(
                "Unable to read validated request for id_cred_pub {}, {}",
                id_cred_pub_hash, e
            );
            return Err(warp::reject::custom(IdRequestRejection::NoValidRequest));
        }
    };

    let request = identity_object_input.id_object_request.value;

    // Identity verification process between the identity provider and the identity
    // verifier. In this example the identity verifier is queried and will
    // return the attribute list that the user submitted to the identity verifier.
    // If there is no attribute list, then it corresponds to the user not having
    // been verified, and the request will fail.
    let attribute_list_url = format!(
        "{}{}{}",
        server_config.id_verification_query_url.clone(),
        "/attributes/",
        id_cred_pub_hash
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

    let alist = ExampleAttributeList {
        valid_to:     expiry,
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

    let submission = AccountCredentialMessage {
        message_expiry,
        credential: versioned_credential.value,
    };
    // The proxy expects a versioned submission, so that is what we construct.
    let versioned_submission = Versioned::new(VERSION_0, submission);

    // Store the created IdentityObject.
    // This is stored so it can later be retrieved by querying via the idCredPub.
    ok_or_500!(
        db.write_identity_object(
            &id_cred_pub_hash, // TODO: should be hashed
            &versioned_id,
            &versioned_submission
        ),
        "Could not write to database."
    );

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
                db.write_pending(&id_cred_pub_hash, status, submission_value),
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
    retrieve_url.set_path(&format!("api/v0/identity/{}", id_cred_pub_hash));
    let callback_location =
        identity_object_input.redirect_uri.clone() + "#code_uri=" + retrieve_url.as_str();

    info!("Identity was successfully created. Returning URI where it can be retrieved.");

    Ok(warp::reply::with_status(
        warp::reply::with_header(warp::reply(), LOCATION, callback_location),
        StatusCode::FOUND,
    ))
}

/// Checks for a validated request and checks with the identity verifier if
/// there is a verified attribute list for this person. If there is an attribute
/// list, then it is used to create the identity object that is then signed and
/// saved. If successful a re-direct to the URL where the identity object is
/// available is returned. This is for the version 1 flow, where no initial
/// account is created.
async fn create_signed_identity_object_v1(
    server_config: Arc<ServerConfig>,
    db: Arc<DB>,
    client: Client,
    id_cred_pub_hash: String,
    expiry: YearMonth,
) -> Result<impl Reply, Rejection> {
    // Read the validated request from the database.
    let identity_object_input = match db.read_request_record_v1(&id_cred_pub_hash) {
        Ok(request) => request,
        Err(e) => {
            error!(
                "Unable to read validated request for id_cred_pub {}, {}",
                id_cred_pub_hash, e
            );
            return Err(warp::reject::custom(IdRequestRejection::NoValidRequest));
        }
    };

    let request = identity_object_input.id_object_request.value;

    // Identity verification process between the identity provider and the identity
    // verifier. In this example the identity verifier is queried and will
    // return the attribute list that the user submitted to the identity verifier.
    // If there is no attribute list, then it corresponds to the user not having
    // been verified, and the request will fail.
    let attribute_list_url = format!(
        "{}{}{}",
        server_config.id_verification_query_url.clone(),
        "/attributes/",
        id_cred_pub_hash
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

    let alist = ExampleAttributeList {
        valid_to:     expiry,
        created_at:   now,
        alist:        attribute_list,
        max_accounts: 200,
        _phantom:     Default::default(),
    };

    let signature = match sign_identity_object_v1(
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

    ok_or_500!(
        save_revocation_record_v1(&db, &request, &alist),
        "Could not write the revocation record to database."
    );

    let id = IdentityObjectV1 {
        pre_identity_object: request,
        alist,
        signature,
    };

    let versioned_id = Versioned::new(VERSION_0, id);

    // Store the created IdentityObject.
    // This is stored so it can later be retrieved by querying via the idCredPub.
    ok_or_500!(
        db.write_identity_object_v1(&id_cred_pub_hash, &versioned_id),
        "Could not write to database."
    );

    // If we reached here it means we at least have a pending request. We respond
    // with a URL where they will be able to retrieve the ID object.

    // The callback_location has to point to the location where the wallet can
    // retrieve the identity object when it is available.
    let mut retrieve_url = server_config.retrieve_url.clone();
    retrieve_url.set_path(&format!("api/v1/identity/{}", id_cred_pub_hash));
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
    let context = IpContext {
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

/// A common function that validates the cryptographic proofs in a version 1
/// request.
fn validate_worker_v1(
    server_config: &Arc<ServerConfig>,
    input: IdentityObjectRequestV1,
) -> Result<IdentityObjectRequestV1, IdRequestRejection> {
    if input.id_object_request.version != VERSION_0 {
        return Err(IdRequestRejection::UnsupportedVersion);
    }
    let request = &input.id_object_request.value;
    let context = IpContext {
        ip_info:        &server_config.ip_data.public_ip_info,
        ars_infos:      &server_config.ars.anonymity_revokers,
        global_context: &server_config.global,
    };
    match ip_validate_request_v1(request, context) {
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
/// - Ok(IdentityObjectRequest) if the request is valid or
/// - Err(e) where `e` is a [Rejection] describing the error.
fn extract_and_validate_request_query(
    server_config: Arc<ServerConfig>,
) -> impl Filter<Extract = (IdentityObjectRequest,), Error = Rejection> + Clone {
    warp::query().and_then(move |input: GetParameters| {
        let server_config = server_config.clone();
        async move {
            info!("Queried for creating an identity");

            let id_object_request = match from_str::<serde_json::Value>(&input.state)
                .map_err(|e| format!("{:#?}", e))
                .and_then(|mut v| match v.get_mut("idObjectRequest") {
                    Some(v) => Ok(v.take()),
                    None => Err(String::from("`idObjectRequest` field does not exist")),
                })
                .and_then(|v| {
                    serde_json::from_value::<Versioned<_>>(v).map_err(|e| format!("{:#?}", e))
                }) {
                Ok(v) => v,
                Err(e) => {
                    return {
                        warn!("`idObjectRequest` missing or malformed: {}", e);
                        Err(warp::reject::custom(IdRequestRejection::Malformed))
                    }
                }
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

/// Validate that the received version 1 request is well-formed.
/// This check that all the cryptographic values are valid, and that the zero
/// knowledge proofs in the request are valid.
///
/// The return value is either
///
/// - Ok(IdentityObjectRequestV1) if the request is valid or
/// - Err(e) where `e` is a [Rejection] describing the error.
fn extract_and_validate_request_query_v1(
    server_config: Arc<ServerConfig>,
) -> impl Filter<Extract = (IdentityObjectRequestV1,), Error = Rejection> + Clone {
    warp::query().and_then(move |input: GetParameters| {
        let server_config = server_config.clone();
        async move {
            info!("Queried for creating an identity");

            let id_object_request = match from_str::<serde_json::Value>(&input.state)
                .map_err(|e| format!("{:#?}", e))
                .and_then(|mut v| match v.get_mut("idObjectRequest") {
                    Some(v) => Ok(v.take()),
                    None => Err(String::from("`idObjectRequest` field does not exist")),
                })
                .and_then(|v| {
                    serde_json::from_value::<Versioned<_>>(v).map_err(|e| format!("{:#?}", e))
                }) {
                Ok(v) => v,
                Err(e) => {
                    return {
                        warn!("`idObjectRequest` missing or malformed: {}", e);
                        Err(warp::reject::custom(IdRequestRejection::Malformed))
                    }
                }
            };
            match validate_worker_v1(&server_config, IdentityObjectRequestV1 {
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

/// Validate an ID recovery request and return the identity object, if the
/// request is valid.
fn validate_recovery_request(
    server_config: Arc<ServerConfig>,
    db: DB,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::query().and_then(move |input: RecoveryGetParameters| {
        let server_config = server_config.clone();
        let db = db.clone();
        async move {
            info!("Queried for identity recovery");
            let id_recovery_request: Versioned<IdRecoveryRequest<ArCurve>> =
                match from_str::<serde_json::Value>(&input.state)
                    .map_err(|e| format!("{:#?}", e))
                    .and_then(|mut v| match v.get_mut("idRecoveryRequest") {
                        Some(v) => Ok(v.take()),
                        None => Err(String::from("`idRecoveryRequest` field does not exist")),
                    })
                    .and_then(|v| {
                        serde_json::from_value::<Versioned<_>>(v).map_err(|e| format!("{:#?}", e))
                    }) {
                    Ok(v) => v,
                    Err(e) => {
                        return {
                            warn!("`idRecoveryRequest` missing or malformed: {}", e);
                            Err(warp::reject::custom(IdRecoveryRejection::Malformed))
                        }
                    }
                };
            if id_recovery_request.version != VERSION_0 {
                return Err(warp::reject::custom(
                    IdRecoveryRejection::UnsupportedVersion,
                ));
            }

            let timestamp = id_recovery_request.value.timestamp;

            let now = chrono::offset::Utc::now().timestamp() as u64;
            let delta = server_config.recovery_timestamp_delta;
            if timestamp < now - delta || timestamp > now + delta {
                warn!("Timestamp of id ownership proof out of sync.");
                return Err(warp::reject::custom(IdRecoveryRejection::InvalidTimestamp));
            }

            let pok_result = validate_id_recovery_request(
                &server_config.ip_data.public_ip_info,
                &server_config.global,
                &id_recovery_request.value,
            );

            if pok_result {
                let id_cred_pub_hash =
                    Sha256::digest(&to_bytes(&id_recovery_request.value.id_cred_pub));
                let base_16_encoded_id_cred_pub_hash =
                    base16_encode_string::<[u8; 32]>(&id_cred_pub_hash.into());
                match db.read_identity_object(&base_16_encoded_id_cred_pub_hash) {
                    Ok(identity_object) => {
                        match identity_object.get("identityObject") {
                            Some(ido) => {
                                info!("Identity object found");
                                Ok(warp::reply::json(&ido))
                            }
                            None => {
                                warn!("`identityObject` field not found."); // This should not happen.
                                Err(warp::reject::custom(
                                    IdRecoveryRejection::NonExistingIdObject,
                                ))
                            }
                        }
                    }
                    Err(_e) => {
                        warn!("Identity object does not exist.");
                        Err(warp::reject::custom(
                            IdRecoveryRejection::NonExistingIdObject,
                        ))
                    }
                }
            } else {
                warn!("Id ownership proof did not verify");
                Err(warp::reject::custom(IdRecoveryRejection::InvalidProofs))
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
        threshold:    pre_identity_object.choice_ar_parameters.threshold,
    };
    let id_cred_pub_hash = Sha256::digest(&to_bytes(&ar_record.id_cred_pub));
    let base_16_encoded_id_cred_pub_hash =
        base16_encode_string::<[u8; 32]>(&id_cred_pub_hash.into());
    db.write_revocation_record(&base_16_encoded_id_cred_pub_hash, ar_record)
}

/// Given a version 1 pre-identity object, this function creates and saves the
/// revocation record to the file system (which should be a database, but for
/// the proof-of-concept we use the file system).
fn save_revocation_record_v1<A: Attribute<id::constants::BaseField>>(
    db: &DB,
    pre_identity_object: &PreIdentityObjectV1<IpPairing, ArCurve>,
    alist: &AttributeList<id::constants::BaseField, A>,
) -> anyhow::Result<()> {
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub:  pre_identity_object.id_cred_pub,
        ar_data:      pre_identity_object.ip_ar_data.clone(),
        max_accounts: alist.max_accounts,
        threshold:    pre_identity_object.choice_ar_parameters.threshold,
    };
    let id_cred_pub_hash = Sha256::digest(&to_bytes(&ar_record.id_cred_pub));
    let base_16_encoded_id_cred_pub_hash =
        base16_encode_string::<[u8; 32]>(&id_cred_pub_hash.into());
    db.write_revocation_record(&base_16_encoded_id_cred_pub_hash, ar_record)
}

/// Checks for a validated request.
/// If successful a re-direct to the URL, where the failed identity object will
/// available, is returned.
async fn create_failed_identity(
    server_config: Arc<ServerConfig>,
    db: Arc<DB>,
    id_cred_pub_hash: String,
    version: String,
    delay: i64,
) -> Result<impl Reply, Rejection> {
    // Read the validated request from the database to get the redirect URI.
    let redirect_uri = match if version.eq("v0") {
        db.read_request_record(&id_cred_pub_hash)
            .map(|r| r.redirect_uri)
    } else if version.eq("v1") {
        db.read_request_record_v1(&id_cred_pub_hash)
            .map(|r| r.redirect_uri)
    } else {
        return Err(warp::reject::custom(IdRequestRejection::UnsupportedVersion));
    } {
        Ok(request) => request,
        Err(e) => {
            error!(
                "Unable to read validated request for id_cred_pub {}, {}",
                id_cred_pub_hash, e
            );
            return Err(warp::reject::custom(IdRequestRejection::NoValidRequest));
        }
    };

    // The callback_location has to point to the location where the wallet can
    // retrieve the identity object when it is available.
    let mut retrieve_url = server_config.retrieve_url.clone();
    retrieve_url.set_path(&format!(
        "api/identity/retrieve_failed/{}",
        chrono::offset::Utc::now().timestamp() + delay
    ));
    let callback_location = redirect_uri + "#code_uri=" + retrieve_url.as_str();

    info!("Successfully created a failed identity. Returning URI where it can be retrieved.");

    Ok(warp::reply::with_status(
        warp::reply::with_header(warp::reply(), LOCATION, callback_location),
        StatusCode::FOUND,
    ))
}

/// A pending token is returned if the delay_until timestamp is still in the
/// future. Otherwise a failed identity object is returned.
async fn retrieve_failed_identity_token(delay_until: i64) -> Result<impl Reply, Rejection> {
    if chrono::offset::Utc::now().timestamp() < delay_until {
        info!("Failed Identity object is not past delay yet.");
        let identity_token_container = IdentityTokenContainer {
            status: IdentityStatus::Pending,
            detail: "Pending resolution.".to_string(),
            token:  serde_json::Value::Null,
        };
        Ok(warp::reply::json(&identity_token_container))
    } else {
        let error_identity_token_container = IdentityTokenContainer {
            status: IdentityStatus::Error,
            detail: "Identity object has failed".to_string(),
            token:  serde_json::Value::Null,
        };
        info!("Failed Identity object returned.");
        Ok(warp::reply::json(&error_identity_token_container))
    }
}

/// Builds the reply for the broken response.
async fn get_broken_reply() -> Result<impl Reply, Rejection> {
    log::info!("Broken Endpoint was triggered.");
    Ok(mk_reply(
        "Broken Endpoint was used",
        StatusCode::BAD_REQUEST,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test;

    fn get_server_config() -> ServerConfig {
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

        let id_url = url::Url::parse("http://localhost/verify").unwrap();
        ServerConfig {
            ip_data,
            global,
            ars,
            id_verification_url: id_url.clone(),
            id_verification_query_url: id_url,
            retrieve_url: url::Url::parse("http://localhost/retrieve").unwrap(),
            submit_credential_url: url::Url::parse("http://localhost/submitCredential").unwrap(),
            recovery_timestamp_delta: 60,
        }
    }

    #[test]
    fn test_successful_validation_and_response() {
        // Given
        let request = include_str!("../../data/valid_request.json");
        let server_config = Arc::new(get_server_config());

        tokio_test::block_on(async {
            let v = serde_json::from_str::<serde_json::Value>(request).unwrap();
            let matches = test::request()
                .method("POST")
                .json(&v)
                .matches(&extract_and_validate_request(server_config.clone()))
                .await;
            assert!(matches, "The filter does not match the example request.");
        });
    }

    #[test]
    fn test_verify_failed_validation() {
        // Given
        let request = include_str!("../../data/fail_validation_request.json");
        let server_config = Arc::new(get_server_config());

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

    #[test]
    fn test_broken_endpoint() {
        tokio_test::block_on(async {
            let response = test::request()
                .method("GET")
                .reply(&warp::get().and_then(get_broken_reply))
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn test_retrieve_failed_identity_token_before_delay_until() {
        tokio_test::block_on(async {
            let response = test::request()
                .method("GET")
                .path(&format!(
                    "/{}",
                    chrono::offset::Utc::now().timestamp() + 100
                ))
                .reply(
                    &warp::get()
                        .and(warp::path!(i64))
                        .and_then(retrieve_failed_identity_token),
                )
                .await;
            let body2: IdentityTokenContainer = serde_json::from_slice(response.body()).unwrap();
            assert!(matches!(body2.status, IdentityStatus::Pending));
        });
    }

    #[test]
    fn test_retrieve_failed_identity_token_after_delay_until() {
        tokio_test::block_on(async {
            let response = test::request()
                .method("GET")
                .path(&format!("/{}", chrono::offset::Utc::now().timestamp() - 1))
                .reply(
                    &warp::get()
                        .and(warp::path!(i64))
                        .and_then(retrieve_failed_identity_token),
                )
                .await;
            let body2: IdentityTokenContainer = serde_json::from_slice(response.body()).unwrap();
            assert!(matches!(body2.status, IdentityStatus::Error));
        });
    }

    // Destroy DB generated folders after test
    impl Drop for DB {
        fn drop(&mut self) {
            // ignore errors for drop
            let _ = fs::remove_dir_all(&self.root);
            let _ = fs::remove_dir_all(&self.backup_root);
        }
    }

    #[test]
    fn test_create_failed_identity() {
        // Given
        let request = include_str!("../../data/valid_request_v1.json");
        let server_config = Arc::new(get_server_config());

        let idi = serde_json::from_str::<IdentityObjectRequestV1>(request).unwrap();
        // This is the uri that should the callback from create_failed_identity:
        let callback_uri = format!(
            "{}#code_uri=http://localhost/api/identity/retrieve_failed/",
            &idi.redirect_uri
        );

        let id_cred_pub_hash_digest =
            Sha256::digest(&to_bytes(&idi.id_object_request.value.id_cred_pub));
        let id_cred_pub_hash = base16_encode_string::<[u8; 32]>(&id_cred_pub_hash_digest.into());

        let root = std::path::Path::new("test-database").to_path_buf();
        let backup_root = std::path::Path::new("test-database-deleted").to_path_buf();
        let db = Arc::new(DB::new(root, backup_root).unwrap());

        tokio_test::block_on(async {
            let save = save_validated_request_v1(Arc::clone(&db), idi, server_config.clone()).await;
            assert!(save.is_ok());

            let response = test::request()
                .method("GET")
                .reply(&warp::get().and_then(move || {
                    create_failed_identity(
                        server_config.clone(),
                        Arc::clone(&db),
                        id_cred_pub_hash.to_string(),
                        "v1".to_string(),
                        10,
                    )
                }))
                .await;
            assert_eq!(response.status(), StatusCode::FOUND);
            let location: &str = response
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(location.contains(&callback_uri));
        });
    }
}
