This page describes how to use the `user_cli` tool to request an identity object from an identity provider and create accounts from the identity returned by the identity provider.

# Prerequisites

- The `user_cli` tool.
- A file with cryptographic parameters for the chain. We'll refer to this file as `cryptographic-parameters.json` below.
- A file with the list of anonymity revokers supported by the identity provider. We refer to this file as `ars.json` below.
- A file with identity provider public keys. We refer to this file as `ip-info.json` below.
- For creating accounts from the identity the `concordium-client` tool and access to an up-to-date node.

There are two flows for creating identity requests and credentials from identity objects, the version 0 flow and the version 1 flow.
In the version 0 flow, the creation of an identity involves the creation of an initial account. In the version 1 flow, there is no initial account creation.
Account keys and other private data are derived deterministcally from a seed in the version 1 flow.

# The version 0 flow

The tool supports two modes in the version 0 flow. The `generate-request` mode which generates the request for the identity object that is to be sent to the identity provider, and the `create-credential` mode.
In this latter mode the tool requires the identity object returned by the identity provider and generates a credential that can be sent to the chain to create an account.

## Generate a version 0 request for the version 0 identity object

To generate a request to the identity provider together with some auxiliary data use the following command, modifying the paths as appropriate.
```console
user_cli generate-request --cryptographic-parameters cryptographic-parameters.json \
                          --ars ars.json \
                          --ip-info ip-info.json \
                          --initial-keys-out initial-keys.json \ # keys of the initial account together with its address.
                          --id-use-data-out id-use-data.json \ # data that enables use of the identity object
                          --request-out request.json # request to send to the identity provider
```
The above command will ask for some additional input. You have to choose anonymity revokers and revocation threshold. Use arrow keys to navigate through the lists and the space key to select and deselect list entries. 

It outputs the following files
- `initial-keys.json` data about the initial account, including its address and keys for signing transactions. DO NOT LOSE THIS FILE. It cannot be recovered.
- `id-use-data.json` contains data that enables the use of the identity object returned by the identity provider. DO NOT LOSE THIS FILE. It cannot be retrieved.
- `request.json` contains the request that should be sent to the identity provider.

The request should be sent to the identity provider through a trusted channel, together with any other required identity data. Assuming everything is in order when checking your identity, the identity provider should eventually return the identity object. We refer to it as `id-object.json` in the command below.

## Create accounts from a version 0 identity object

After obtaining the identity object from the identity provider you can create additional accounts on the chain. Accounts are created by deploying credentials. Note that the initial account already exists on the chain, since the initial account credential was deployed by the identity provider before this point.
The `user_cli` tool can only be used to create credentials. To deploy them to the chain, thus creating accounts, you need to use `concordium-client` and access to a node.

To create a credential use the following command.
```console
user_cli create-credential --id-use-data id-use-data.json \
                           --id-object id-object.json \
                           --keys-out account-keys.json \
                           --credential-out credential.json
```
You will have to select whether to reveal the LEI, which was optional when creating the identity object. Use the space key to select and deselect list entries. 

It outputs the following files
- `account-keys.json` which contains account keys of the account that will be created by the credential. DO NOT LOSE THIS FILE. It cannot be recovered.
- `credential.json` which contains the payload of the account creation transaction. **This must be sent to the chain, otherwise the account will not be created.**
By default this must be sent to the chain within 15min. A larger or shorter message expiry may be set with `--message-expiry` flag to the command.
Note that the credential number must be unique for each respective `id-object.json`. Duplicate credential numbers for the same `id-object.json` will be rejected when submitting to chain.

To create the account on the chain make sure you have access to a node, then do
```console
concordium-client transaction deploy-credential credential.json
```
where `credential.json` is the file obtained in the previous step.

# The version 1 flow

The tool supports three modes in the version 1 flow: the `generate-request-v1` mode, the `create-credential-v1` mode and the `recover-identity-flow`. The `generate-request-v1` generates the version 1 request for the version 1 identity object that is to be sent to the identity provider. In the `create-credential-v1` mode the tool requires the identity object returned by the identity provider and generates a credential that can be sent to the chain to create an account. The `recover-identity` request can generate an identity recovery request to be sent to the identity provider.

## Generate a version 1 request for the version 1 identity object

To generate a request to the identity provider use the following command, modifying the paths as appropriate.
```console
user_cli generate-request-v1 --cryptographic-parameters cryptographic-parameters.json \
                          --ars ars.json \
                          --ip-info ip-info.json \
                          --request-out request.json # request to send to the identity provider
```
The above command will ask for some additional input. You have to choose anonymity revokers and revocation threshold. Use arrow keys to navigate through the lists and the space key to select and deselect list entries. Afterwards, the user is asked whether the identity shall be used for Mainnet or Testnet. Afterwards, 24 BIP-39 will be generated and shown to the user, who is asked to write down the words and type them in again.

It outputs the following files
- `request.json` contains the request that should be sent to the identity provider.

The request should be sent to the identity provider through a trusted channel, together with any other required identity data. Assuming everything is in order when checking your identity, the identity provider should eventually return the identity object. We refer to it as `id-object.json` in the command below.

## Create accounts from a version 1 identity object

After obtaining the identity object from the identity provider you can create additional accounts on the chain. Accounts are created by deploying credentials.
The `user_cli` tool can only be used to create credentials. To deploy them to the chain, thus creating accounts, you need to use `concordium-client` and access to a node.

To create a credential use the following command.
```console
user_cli create-credential-v1 --cryptographic-parameters cryptographic-parameters.json \
                           --ars ars.json \
                           --ip-info ip-info.json \
                           --id-object id-object.json \
                           --keys-out account-keys.json \
                           --credential-out credential.json
```
You will have to select whether to reveal the LEI, which was optional when creating the identity object. Use the space key to select and deselect list entries. You will also be asked whether to create credential for Mainnet or Testnet. Afterwards you will be asked to type in the 24 words from earlier.

It outputs the following files
- `account-keys.json` which contains account keys of the account that will be created by the credential.
- `credential.json` which contains the payload of the account creation transaction. **This must be sent to the chain, otherwise the account will not be created.**
By default this must be sent to the chain within 15min. A larger or shorter message expiry may be set with `--message-expiry` flag to the command.
Note that the credential number must be unique for each respective `id-object.json`. Duplicate credential numbers for the same `id-object.json` will be rejected when submitting to chain.

To create the account on the chain make sure you have access to a node, then do
```console
concordium-client transaction deploy-credential credential.json
```
where `credential.json` is the file obtained in the previous step.

## Recovery of identity
If the identity object used to create credentials is lost, it can be recovered from the identity provider by generating a recovery request using the 24 words used when the identity was originally created. To generate such a request, run

```console
user_cli recover-identity --cryptographic-parameters cryptographic-parameters.json \
                          --ip-info ip-info.json \
                          --request-out recovery-request.json # recovery request to send to the identity provider
```

It outputs the following files
- `recovery-request.json` contains the recovery request that should be sent to the identity provider.

The request should be sent to the identity provider through a trusted channel, together with any other required identity data. Assuming everything is in order when validating the request, the identity provider should eventually return the identity object that you lost. You can then recreate your account keys (`account-keys.json`) by running `user_cli create-credential-v1` (see above).


# Import created accounts into concordium-client

The account keys are primarily meant for clients to integrate into their key management solution and their software, e.g., an exchange integrating their trading platform with the Concordium chain.

However if the `account-keys.json` file **is not encrypted** it can be imported into concordium-client with the command
```console
 concordium-client config account import account-keys.json --format=genesis --name my-account
 ```
 where the `--name` option is optional, and if given, will name the account according to the given value, "my-account" in the example above.
 
If the `account-keys.json` file is encrypted then it must first be decrypted. This can be done with the `utils` tool which is documented in the [developer documentation](https://developer.concordium.software/en/mainnet/net/references/developer-tools.html).

The initial account keys **cannot** be directly imported into concordium-client.


## Format of the key files

Both initial account keys and subsequent account keys are stored in JSON files. The unencrypted data is a JSON record with a number of fields. For sending transactions the fields that are relevant are

- `accountKeys` contains the account keys. It has the following format

```json
"accountKeys": {
    "keys": {
      "0": {
        "keys": {
          "0": {
            "signKey": "1e16c2e2302023fc5235c60734981a2427004f95b6ace50a1d8a205ee9e5f9e7",
            "verifyKey": "7e9983b292cf5e5822b48dbed1c2d498aca97c097f7116511f7dcf6187d218c4"
          }
        },
        "threshold": 1
      }
    },
    "threshold": 1
  }
```
which contains the account keys. In this example the account has a single credential with index 0, and that credential has a single key with index `0`. The private key is `1e16c2e2302023fc5235c60734981a2427004f95b6ace50a1d8a205ee9e5f9e7` and its public key is `7e9983b292cf5e5822b48dbed1c2d498aca97c097f7116511f7dcf6187d218c4`.


- `address` is the address of the account, e.g., 
```json
"address": "2xe6cXEzBJZ8KXSYwb5uXJdHPZfAstbSZjfdAqsoF7VEq6q7AP"
```

- keys for encrypted transfers. These are only needed for sending and receiving encrypted transfers.

```json
  "encryptionPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c58a2f44906bda77f42bc3503b53b604a851737829899ffd4895abc0184e2da448e673f5e87367991d4a453a7f562df974",
  "encryptionSecretKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c557da780304fba3b831439243201396e8c83daa83da1acc385a7a28519011e6da"
```
