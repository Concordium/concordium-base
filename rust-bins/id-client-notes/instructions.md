# Prerequisites

In order to use the client tool for issuing identities you need
- a file `global.json` with cryptographic parameters for the network you wish to deploy accounts onto
- public keys of one identity provider. Below we refer to this file as `identity_provider-0.pub.json`.
- private keys of one identity provider. Below we refer to this file as `identity_provider-0.json`.
- a list of possible identity providers. Below we refer to this file as `identity_providers.json`.
- pblic keys of anonymity revokers, in the format they are in genesis. Below we refer to this file as `anonymity_revokers.json`

The tool is interactive, so it is not possible to fully script it at the moment.

# Creating the request

The first step is to create the request for the identity object. This can be achieved by running
```console
client create-chi --out user-chi.json
```
This will create a file `user-chi.json` that contains a private key for the identity object (so-called `idCredSec`). This file is needed in subsequent steps.

Following this, a request for the identity object can be made by executing the following command.

```console
client start-ip --ars anonymity_revokers.json\
                --ips identity_providers.json\
                --global global.json\
                --chi user-chi.json\
                --private user-aci.json\
                --public id-object-request.json
```
This will query the user for the identity provider that you wish to make the request to, as well as which anonymity revokers to choose. At least one needs to be chosen. The final query will be for the anonymity revocation threshold, which does not matter, but one needs to be chosen.

The output of this are two files
- `user-aci.json` which contains private information that the user alone keeps
- `id-objec-request.json` which is used in a subsequent step.

# Acting as the identity provider

The next step is to act as the identity provider and create the identity object from the identity object request. **It is important to use the same identity provider as was chosen in the previous step.**

```console
client ip-sign-pio --ars anonymity_revokers.json\
                   --ip-data identity_provider-0.json\
                   --global global.json\
                   --pio id-object-request.json\
                   --out identity-object.json\
                   --initial-cdi-out initial-cdi.json 
```
This will prompt for the expiry date that you wish to set. This is not very important, just set it for some time in the future. It is in the format of YYYYMM, so a good value would be `202212`.

It will further prompt for attributes that should be in the identity object. It is fine to select none there.

The main output is the file `identity-object.json`, which is needed to create accounts.

# Generate credentials from an identity object.

Up to 237 accounts can be created from the given identity object. To create an account, first a credential must be created as follows.

```console
client create-credential --global global.json\
                         --ars anonymity_revokers.json\
                         --ip-info identity_provider-0.pub.json\
                         --private user-aci.json\
                         --id-object identity-object.json\
                         --out credential.json\
                         --keys-out account-keys.json 
```

This will output two files, `credential.json` and `account-keys.json`. 
Before doing so, it will prompt the user for the "index". This is a number that is used to tie the credential to the identity object. When creating multiple credentials from a given identity object, **different indices must be used**.

The file `credential.json` contains the credential that must be sent to the chain to create the account.
The file `account-keys.json` contains the private account keys that can be imported into the concordium-client.

# Create an account on the chain

To deploy the credential on the chain you need the `concordium-client`. Deployment is simple, simply do
```console
concordium-client transaction deploy-credential credential.json
```
where `credential.json` is the file from the previous step.

# Import the account into concordium-client

To import the account to use with concordium-client, you need to add the commitments to the credential's contents.
They are contained within the proofs blob, so you can deserialize that to get them.
But concordium-client doesn't save these values anyway, so you can just insert random values:

```JSON
"contents": {
    "commitments": {
        "cmmAttributes": {},
        "cmmCredCounter": "a4f6a0d5712aa784d5dbc8d7c410711d9422ce397653a377bc85a6dac04707860ace8f51d9b48060184942367bc5e517",
        "cmmIdCredSecSharingCoeff": [
            "b588968126fe9cba61e7036a540f9a6f85995a3b220a6c1170b474296496f3d0d933885421b97f574e7dc0b5f01430a9"
        ],
        "cmmMaxAccounts": "b77ded7505f79e3af65ab4770b3ad5eadb569ac9849b3d0e5202c1248e26426a1e188794debad3faf633bb3e905ed750",
        "cmmPrf": "aebb98086e061229ecad0e31620d294329917484c5b353dcb95f72a3047efca8ba29fb8bbaabf0ecb8837d2feb266aea"
    },
    ...
},
```

Then run:

```console
concordium-client config account import --format=genesis account-keys.json
```
where `account-keys.json` is the file with account keys generated in the step `create-credential` above, with the commitments added.
