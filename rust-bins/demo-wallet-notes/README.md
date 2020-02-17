This crate contains the `simple_client` and `simple_server` binaries which expose various ways of creating and validating data structures related to the identity layer of Concordium.

The binaries can be build via `cargo build --release` which will create the binaries in `../target/release/`. They are called `client` and `server`. The binaries can also be run directly via `cargo run --release --bin server` (or `--bin client`).

# Server

The server is a minimalistic HTTP server that understands 4 requests. It needs access to two files when it starts (see `--help` command for how to override the defaults).
- a file with some "global" parameters. These are some common commitment keys, generators, etc. This file is needed during credential generation and credential checking on-chain. If the parameters do not match credential checking will fail.
- a file with a list of identity providers with all of their **public** and **private** data. Private keys are needed because the server acts as the identity provider. The public data from identity providers must also match of that on the chain (supplied in the genesis data) in order for the credentials to validate.

Example files can be found in [global parameters](example_server_interactions/global.json) and [identity providers](example_server_interactions/identity-providers-public-private.json).

To generate fresh instances of parameters you need to use the `client` binary, see its documentation.

We now describe the interactions the server supports. We assume the server is listening on `localhost:8000` (default address).

## GET public data on identity providers

```console
$> curl -X GET http://localhost:8000/ips 
```

This will return a JSON array listing all of the public data on identity providers (everything apart from their private keys). 

## GET global parameters

```console
$> curl -X GET http://localhost:8000/globalparams
```

Will return the global parameters the server is started with, as a JSON object.

## Create an identity object

```console
$> curl -d "@example_id_object_request.json" -H "Content-Type: application/json" -X POST http://localhost:8000/identity_object
```

Given an attribute list and a choice of an identity provider this request returns a new identity object (see [example](example_server_interactions/example_id_object_request.json))
A request is a JSON object which looks as 
```json
{
    "ipIdentity": 0,
    "name": "Aleš",
    "attributes": {
        "chosenAttributes": {
            "CountryOfNationality": "17",
            "CountryOfResidence": "16",
            "CreationTime": "11"
        },
        "expiryDate": 1612796169
    },
    "anonymityRevokers": [0,1,2],
    "threshold": 2
}
```

The response is a JSON object ([example](example_server_interactions/example_id_object_response.json))with both public information and account-holder private information that would normally only appear on the user's device. This object needs to be stored because we generate multiple credentials from it.

## Create a credential from an identity object and a choice of policy

```console
$> curl -d "@example_credential_request.json" -H "Content-Type: application/json" -X POST http://localhost:8000/generate_credential
```

The input file ([example](example_server_interactions/example_credential_request.json)) takes the returned object from the previous interaction and requires three additional fields (some of which are optional)
- `revealedItems` which is a JSON array of which attributes the user wishes to reveal. If this field is not present we assume no attributes are revealed (note that attribute list variant and expiry date are implicitly always revealed)
- `accountNumber` this is a mandatory field and **must** be unique per identity-object, meaning that for each credential generated from this identity object a fresh number must be used. Should be a number between 0 and 255 (inclusive).
- `accountData` is an optional field which contains the public and private key of the account this credential will be deployed on. If not present a fresh pair is generated and returned.

A returned value from this interaction is a JSON object with two fields, `credential` and `accountData` ([example](example_server_interactions/example_credential_response.json)).
The credential is what can be deployed on the chain, and the `accountData` should be stored because it is needed to sign transactions from the account containing this credential.

If the request already contains the account data then the same is returned, see [example request](example_server_interactions/example_credential_request_existing.json) and [example response](example_server_interactions/example_credential_response_existing.json).
