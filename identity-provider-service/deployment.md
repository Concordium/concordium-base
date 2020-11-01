Notes for the deployment of the identity provider service.

The identity provider service must be deployed together with the identity
verifier. Both of them can be built by doing `cargo build --release` inside the
`identity-provider-service` directory. This produces two binaries

- `identity-provider-service`
- `identity-verifier`

# identity-verifier

This only has one parameter, the port on which it listens on. It starts a server
listening on 0.0.0.0:$IDENTITY_VERIFIER_PORT

# identity-provider-service

This has the following parameters

- `--anonymity-revokers` which should be a filename of the file with anonymity
  revokers. The parameter can also be passed via the environment variable
  ANONYMITY_REVOKERS

  Concretely this should be the anonymity_revokers.json from genesis-data.

- `--identity-provider` which should be a filename of the file with the identity
  provider data. The parameter can also be passed via the environment variable
  IDENTITY_PROVIDER.

  This should point to `ip_private_keys/identity_provider-1.json` in genesis-data.

- `--global` points to a file with cryptographic parameters, should point to
  global.json in genesis_data. Can also be supplied by GLOBAL envar.

- `--port` (also envar IDENTITY_PROVIDER_SERVICE_PORT), the port on which the server will start listening.

- `--retrieve-base` (envar RETRIEVE_BASE), the URL where this server can be
  reached by the wallet. Example https://id-service.eu.staging.concordium.com

- `--id-verification-url` (envar ID_VERIFICATION_URL), the Url where the
  identity verifier can be reached, example `http://localhost:8101/api/verify`.
  The server will make POST requests to the URL.

- `--submit-credential-url` (envar SUBMIT_CREDENTIAL_URL), the Url where the
  wallet-proxy's  `submitCredential` endpoint can be found, example
  https://wallet-proxy.eu.staging.concordium.com/v0/submitCredential
