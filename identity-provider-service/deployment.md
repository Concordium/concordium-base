# Deployment of the identity provider service

Notes for the deployment of the identity provider service.

The identity provider service must be deployed together with the identity
verifier. Both of them can be built by doing `cargo build --release` inside the
`identity-provider-service` directory. This produces two binaries

- `identity-provider-service`
- `identity-verifier`

# identity-verifier

This has the following parameters

- `--port` which is the port the server will listen on. The parameter can also be passed via the environment variable 
  `IDENTITY_VERIFIER_PORT`
- `id-provider-url` which is the base URL where the identity provider service is running, i.e. without any additional
  path values. The parameter can also be passed via the environment variable `IDENTITY_PROVIDER_URL`. The server will
  forward clients to this URL, but won't make direct calls to the server by itself.
- `identity-provider-public` which should be a filename of the file with the public identity provider
  data. It should match the file provided to the identity-provider-service, i.e. contain the public part
  matching what is running on that service. The parameter can also be passed via the environment variable
  `IDENTITY_PROVIDER_PUBLIC`.

  This should point to `ip_private_keys/identity_provider-1.pub.json` in genesis-data.

# identity-provider-service

This has the following parameters

- `--anonymity-revokers` which should be a filename of the file with anonymity
  revokers. The parameter can also be passed via the environment variable
  `ANONYMITY_REVOKERS`.

  Concretely this should be the anonymity_revokers.json from genesis-data.

- `--identity-provider` which should be a filename of the file with the identity
  provider data. The parameter can also be passed via the environment variable
  `IDENTITY_PROVIDER`.

  This should point to `ip_private_keys/identity_provider-1.json` in genesis-data.

- `--global` points to a file with cryptographic parameters, should point to
  global.json in genesis_data. Can also be supplied by `GLOBAL_CONTEXT` environment variable.

- `--port` (also envar `IDENTITY_PROVIDER_SERVICE_PORT`), the port on which the server will start listening.

- `--retrieve-base` (envar `RETRIEVE_BASE`), the URL where this server can be
  reached by the wallet. Example https://id-service.testnet.concordium.com

- `--id-verification-url` (envar `ID_VERIFICATION_URL`), the Url where the
  identity verifier can be reached, example `http://localhost:8101/api/verify`.
  The server will redirect the user/wallet to a URL derived from this one. As a
  result this must be **publicly accessible**.

- `--id-verification-query-url` (env var `ID_VERIFICATION_QUERY_URL`), the URL where the
  identity verifier can be reached for GET queries for attributes, example `http://localhost:8101/api/verify`.
  Only the identity provider server will make GET requests to the URL, so this
  can be private. If not given it defaults to the value of
  `--id-verification-url`.


- `--wallet-proxy-base` (envar `WALLET_PROXY_BASE`), the base Url of the wallet
  proxy. Example https://wallet-proxy.testnet.concordium.com.
  This cannot have a path component, the way it is currently set-up. If that is
  necessary (e.g., if we want to deploy this behind a proxy) we need to change
  the use of this parameter a little bit.
