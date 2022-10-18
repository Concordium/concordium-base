This page describes how to use the `identity_provider_cli` tool that can be used by the identity provider to manually sign identity objects and create initial accounts.

The tool is partially interactive.

# Prerequisites

- The `identity_provider_cli` tool.
- A file with cryptographic parameters for the chain. We'll refer to this file as `cryptographic-parameters.json` below.
- A file with the list of anonymity revokers supported by the identity provider. We refer to this file as `ars.json` below.
- When validating identity object requests, a file with identity provider private keys. We refer to this file as `ip-data.json` below.
- When validating identity object requests, a file with request sent by the user. We refer to this file as `request.json` below.
- When validating identity recovery requests, a file with recovery request sent by the user. We refer to this file as `recovery-request.json` below.

There are two flows for validating identity object requests, the version 0 flow and the version 1 flow. In the version 0 flow, the creation of an identity involves the creation of an initial account. In the version 1 flow, there is no initial account creation.
# Tool invocation


## Output files after validation of identity object requests in the version 0 flow

Upon success the tool will generate three files.

- The identity object which must be sent back to the user. We refer to this as `id-object.json` below.
- The initial account creation transaction. We refer to this as `initial-account.json` below. This must be submitted to the chain, for example via the wallet proxy.
- The anonymity revocation record. We refer to this as `ar-record.json` below. This must be stored by the identity provider.

## Output files after validation of identity object requests in the version 1 flow

Upon success the tool will generate three files.

- The identity object which must be sent back to the user. We refer to this as `id-object.json` below.
- The anonymity revocation record. We refer to this as `ar-record.json` below. This must be stored by the identity provider.

## Validating identity object requests in the version 0 flow
```console
identity_provider_cli sign-identity-request --cryptographic-parameters cryptographic-parameters.json \
                      --ars ars.json \
                      --ip-data ip-data.json \
                      --request request.json \
                      --id-out id-object.json  \
                      --initial-account-out initial-account.json\
                      --ar-record-out ar-record.json
```

The tool will first verify the cryptographic validity of the request. The identity provider must then accept the user's choice of anonymity revokers and anonymity revocation  threshold. After accepting, the tool will ask for the following data
- expiry year and month of the identity object.
- an LEI of the entity for which this identity object is being created. This is optional, and if left empty will not be used.

Upon success the tool will display output similar to the following.
```
Successfully checked pre-identity data.
Wrote signed identity object to file id-object.json. Return it to the user.
Wrote initial account transaction to file initial-account.json. Submit it before 2021-11-21 21:56:59 +01:00.
Wrote anonymity revocation record to file ar-record.json. Store it.
```

The initial account transaction must be submitted to the chain before the identity object is returned to the user.
To submit it to the wallet proxy curl may be used via the following invocation on the **testnet**. On **mainnet** replace
`https://wallet-proxy.testnet.concordium.com/v0/submitCredential` with `https://wallet-proxy.mainnet.concordium.software/v0/submitCredential`.

```console
curl -X PUT https://wallet-proxy.testnet.concordium.com/v0/submitCredential -d @initial-account.json -H 'Content-Type: application/json'
```
If successful this will print the submission id of the account creation transaction.
This can be queried either via curl as
```console
curl https://wallet-proxy.testnet.concordium.com/v0/submissionStatus/$submissionId
```
or on the network dashboard
`https://dashboard.testnet.concordium.com/lookup/$submissionId`


## Validating identity object requests in the version 1 flow
```console
identity_provider_cli sign-identity-request-v1 --cryptographic-parameters cryptographic-parameters.json \
                      --ars ars.json \
                      --ip-data ip-data.json \
                      --request request.json \
                      --id-out id-object.json  \
                      --ar-record-out ar-record.json
```

The tool will first verify the cryptographic validity of the request. The identity provider must then accept the user's choice of anonymity revokers and anonymity revocation  threshold. After accepting, the tool will ask for the following data
- expiry year and month of the identity object.
- an LEI of the entity for which this identity object is being created. This is optional, and if left empty will not be used.

Upon success the tool will display output similar to the following.
```
Successfully checked pre-identity data.
Wrote signed identity object to file id-object.json. Return it to the user.
Wrote anonymity revocation record to file ar-record.json. Store it.
```

## Validating a recovery request
Upon receiving recovery request from the user, run
```console
identity_provider_cli validate-recovery-request --cryptographic-parameters cryptographic-parameters.json \
                      --ip-info ip-info.json \
                      --request recovery-request.json
```

Upon success the tool will display the ID recovery validation result. The identity provider should return the identity object, if the following is satisfied:
-  the validation result it is `true`, and
-  the timestamp in the request does not deviate more than 15 minutes from the time the request was received,
-  the request is not a duplicate, i.e. the identity provider has not seen the very same request before. 
