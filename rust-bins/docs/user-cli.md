This page describes how to use the `user_cli` tool to create an identity and an account interacticting with an identity provider using the tool `identity_provider_cli`.

# Steps to obtain an enterprise identity and account
The entity uses the binary `user_cli` to do the following steps:
1. Create secret account holder information and generate the data to be sent to the identity provider using the command
    ```bash
    ./user_cli start-ip --private private.json --public public.json --ip-info identity_provider.json --ars anonymity_revokers.json --initial-keys initial_account_keys.json
    ```
    This will ask the entity for a password to encrypt the account holder information that will be written to `private.json`. In case no password is provided, the data will not be encrypted. Public information needed by the identity provider will be written to `public.json`. The private keys of the initial account will be written to `initial_account_keys.json`.
2. Prove real-life identity to the identity provider and give them public.json. Await identity object from the identity provider.
3. Create a credential
    ```bash
    ./user_cli create-credential --expiry 500 --id-object id_object.json --ip-info identity_provider.json --out create_credential.json --private private.json --keys-out account_keys.json
    ```
    This will decrypt the `private.json` if it was encrypted in step 1 and encrypt the account keys that will be written to `account_keys.json`. The transaction payload for deploying the new account will be written to `create_credential.json`. The expiry is given in seconds from the current time.
