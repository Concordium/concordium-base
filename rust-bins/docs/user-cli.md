This page describes how to use the `user_cli` tool to request an identity object from an identity provider and create accounts from the identity returned by the identity provider.

# Prerequisites

- The `user_cli` tool.
- A file with cryptographic parameters for the chain. We'll refer to this file as `cryptographic-parameters.json` below.
- A file with the list of anonymity revokers supported by the identity provider. We refer to this file as `ars.json` below.
- A file with identity provider public keys. We refer to this file as `ip-info.json` below.
- For creating accounts from the identity the `concordium-client` tool and access to an up-to-date node.

The tool supports two modes. The `generate-request` mode which generates the request for the identity object that is to be sent to the identity provider, and the `create-credential` mode.
In this latter mode the tool requires the identity object returned by the identity provider and generates a credential that can be sent to the chain to create an account.

# Generate a request for the identity object

To generate a request to the identity provider together with some auxiliary data use the following command, modifying the paths as appropriate.
```console
user_cli generate-request --cryptographic-parameters cryptographic-parameters.json \
                          --ars ars.json \
                          --ip-info ip-info.json
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

# Create accounts from an identity object

After obtaining the identity object from the identity provider you can create additional accounts on the chain. Accounts are created by deploying credentials. Note that the initial account already exists on the chain, since the initial account credential was deployed by the identity provider before this point.
The `user_cli` tool can only be used to create credentials. To deploy them to the chain, thus creating accounts, you need to use `concordium-client` and access to a node.

To create a credential use the following command.
```console
user_cli create-credential --id-use-data id-use-data.json \
                           --id-object id-object.json \
                           --keys-out account-keys.json
                           --credential-out credential.json
```
You will have to select whether to reveal the LEI, which was optional when creating the identity object. Use the space key to select and deselect list entries. 

It outputs the following files
- `account-keys.json` which contains account keys of the account that will be created by the credential. DO NOT LOSE THIS FILE. It cannot be recovered.
- `credential.json` which contains the payload of the account creation transaction. **This must be sent to the chain, otherwise the account will not be created.**
By default this must be sent to the chain within 15min. A larger or shorter message expiry may be set with `--message-expiry` flag to the command.
Do note that an expiry longer than 2 hours is not acceptable. Note also that the credential number must be unique for each respective `id-object.json`. Duplicate credential numbers for the same `id-object.json` will be rejected when submitting to chain.

To create the account on the chain make sure you have access to a node, then do
```console
concordium-client transaction deploy-credential credential.json
```
where `credential.json` is the file obtained in the previous step.
