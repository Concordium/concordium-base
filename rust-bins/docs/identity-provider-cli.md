This page describes how to use the `identity_provider_cli` tool to sign identity objects, create initial account messages and anonymity revocation records.

# Steps to sign pre-identity object and produce identity object, initial account creation message and anonymity revocation record
The identity provider uses the binary `identity_provider_cli` to do the following steps:
1. Await request from user
2. When getting a request, say, `public.json` from the user, do
    ```bash
    ./identity_provider_cli ip-sign-pio --expiry 500 --pio public.json --ip-data identity_provider.json --out identity_object.json --initial-cdi-out initial_credential_creation.json --ar-record ar_record.json
    ```
    This will read the identity private keys from `identity_provider.json` and use them to produce the identity object together with the initial account message. They will be written to `identity_object.json` and `initial_credential_creation.json`, respectively. An anonymity revocation record will be written to `ar_record.json`.
3. Give back `identity_object.json` to the user, send `initial_credential_creation.json` to chain to create the initial account and store `ar_record.json`.