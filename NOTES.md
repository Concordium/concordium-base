# ID layer API

The identity layer component is essentiall to all user-facing and
user-interacting parts of the project. The API consists of functionality to
support the following operations.

1.  Request an identity object from the identity provider.
2.  Identity provider verifies the request and issues an identity object.
3.  User verifies the received identity object and generates a number of
    credentials from it. Credentials can be generated so that they create a new
    account, or deployed onto an existing account.
4.  The bakers verify the credentials that are sent and recorded on the chain.
5.  Given a credential as visible on the chain the anonymity revokers can
    decrypt IdCredPub which identifies the user to the relevant identity
    provider.
6.  The identity provider stores encryption of the PRF key under IdCredPub which
    the anonymity revokers can decrypt, and therefore find all accounts created
    from the given identity object. There should be a tool that generates all possible accounts from 
    a given PRF key and credential/identity object request.
7.  The baker expose an API where all credentials on a given account can be
    looked up. The most interesting part of this is the encryption of IdCredPub
    for anonymity revokers, and any publicly revealed attributes. Currently all
    of the information is exposed as received in the credential minus the proofs.

## Implementations

The core functionality for all of these is implemented inside [./rust-src/id](./rust-src/id)
crate.

The relevant data structures are all defined in [./rust-src/id/src/types.rs](./rust-src/id/src/types.rs)
module. In addition to this rust library for use in the scheduler and
external baker API there is an equivalent Haskell module
[./haskell-src/Concordium/ID/Types.hs](./haskell-src/Concordium/ID/Types.hs) that duplicates some of the data
structures. It is important that these two are constantly in sync, otherwise
credentials created by e.g., the wallet, will not be accepted by the chain.
The rest of the node software only uses the Haskell API.

There is a tool [./rust-bins/src/bin/generate_testdata.rs](./rust-bins/src/bin/generate_testdata.rs) that can be used to
generate some example testdata that is used by the Haskell testsuite to make
sure that the data structures are in sync. The script is not part of the CI,
but it could easily be with a little bit of effort.

The data objects which are directly used by the APIs above are 
- [./rust-src/id/src/types.rs#L1080](CredentialDeploymentInfo) which is the credential that is sent to the chain. The corresponding counterpart in Haskell is [./haskell-src/Concordium/ID/Types.hs#L558](CredentialDeploymentInformation) which is the data type that is used in the scheduler and stored with accounts. Credential checking is currently somewhat bad in the sense that what we do when we receive a credential is deserialize it, then we inspect some of the values in Haskell, e.g., RegId, and then we serialize it again and send the whole object over FFI to a rust verify function ([./rust-src/id/src/ffi.rs#L166](verify_cdi_ffi)).
This should be optimized at some point to remove duplicate work, since just deserializing is fairly expensive for credentials. Some of the values need to be checked to be valid group elements, which is expensive in the BLS-12 curve we are using.
- [./rust-src/id/src/types.rs#L607](IpInfo) is the public information about the identity provider and its allowed anonymity revokers. This information is on the chain, currently only in genesis and there is no way to update it. 
  - The bakers need to have this information in order to validate credentials.
  - The user wallet needs to have access to this information in order to both create the request for the identity object as well as to generate the credential to be put on the chain.
- [./rust-src/id/src/types.rs#L488](PreIdentityObject) is the data that is sent from the user to the identity provider. Note that it was decided that the identity provider will select the attributes themselves so user attributes are not part of the request.
- [./rust-src/id/src/types.rs#L542](IdentityObject) is the data that is received back from the identity provider. It contains the original request, with added attributes the identity provider selects, as well as a signature that is used to create credentials.
- [./rust-src/id/src/types.rs#L1396](IdObjectUseData) is the private data that the user generates before requesting the identity object. They need to store it in order to be able to use the received identity object to create credentials.

# Current internal testing tools

In addition to the core functionality we have a number of internal testing
tools and support binaries.

-   [./rust-bins/src/bin/client.rs](./rust-bins/src/bin/client.rs) is a tool for showcasing all the different flows
    of the identity issuance process, from generating private data, getting the
    identity object, creating the credential, and revoking anonymity of a
    credential. Note that this is not meant for anything other than internal
    testing.
-   [./rust-bins/src/bin/server.rs](./rust-bins/src/bin/server.rs) is a simple server used by the wallet middleware
    to issue credentials and create accounts. It is currently used because the
    wallet is a browser wallet and at this point it does not use our libraries
    directly. This means it cannot generate accounts or credentials itself. We
    have recently managed to compile the core libraries for WASM which means the
    web wallet could be reworked to generate credentials itself without this
    particular server, although whether that is worthwhile to do in light of the
    native wallet is unclear. The functionality of this is described in
    [./rust-bins/demo-wallet-notes/](./rust-bins/demo-wallet-notes/) although some of the examples there are out of
    date and need to be regenerated.
-   [./rust-bins/src/bin/wallet_server.rs](./rust-bins/src/bin/wallet_server.rs) is the mock server provided to Mjolner so
    that they can progress with identity issuance process. It acts as an
    identity provider roughly in the way Notabene sketched out it would operate.
    This should be phased out once Notabene gets up and running with their own
    mock API and later proper ID server.
-   [./rust-bins/src/bin/genesis_tool.rs](./rust-bins/src/bin/genesis_tool.rs) is a tool that is used to generate initial
    bakers and accounts to be included in the genesis block. This is again an
    internal tool and the accounts it generates are dummy ones. For the real
    genesis to be included in the MVP genesis block this will need to be done
    more manually. See the documentation in the tool for details on how it works.

# Libraries provided to Mjolner

-   The functionality the native wallet uses is in the [./rust-src/wallet/](./rust-src/wallet/) crate.
    Its API is described in [./rust-bins/wallet-notes/README.md](./rust-bins/wallet-notes/README.md) which also includes
    example input output for different calls. Since Mjolner is building a wallet
    they only need the functionality that concerns the user; generating identity
    object requests, processing identity objects, creating new credentials and
    sending them as a transaction to the chain, creating transfer transactions
    and sending them to the chain.

# Libraries and needs for Notabene

-   We currently do not provide any functionality to Notabene. We have recently
    managed to compile our core libraries for WASM which is what Notabene
    intends to use to integrate into their flow. This should be extended with a
    simple API that takes the identity object request see
    [./rust-bins/wallet-notes/id-request.json](./rust-bins/wallet-notes/id-request.json) for an example, parses it and
    produces whatever Notabene needs from it. This needs to be discussed with
    Andres directly I think.
    
    Notabene will then add a number of attributes to that and we need an
    additional API endpoint to sign the resulting data object to obtain an
    identity object which Notabene will return to the user. An example of such a
    thing is [./rust-bins/wallet-notes/example-id-object-response.json](./rust-bins/wallet-notes/example-id-object-response.json)

# Missing pieces/open questions

-   Credential deployment is currently for free and a possible DOS vector. This
    was a decision from Torben that we have to deploy credentials for free and
    the reason something is needed here is that either somebody has to create an
    account for you, and deploy the credential, or it has to be done for free.
    
    It takes in the range of a few miliseconds to verify a credential, about
    30-40ms for the simple ones, which will increase fairly significantly with
    the addition of the Sonic. Since nobody pays for them it is an easy way to
    overwhelm the bakers. Currently there is no mitigation for this. One easy
    thing would be for the baker to only consider a limited number of
    credentials for inclusion in the block when it is its turn, say at most 200.
    This would transform it from a security issue to a liveness issue, i.e., you
    might have to wait a long time before your credential gets in because
    somebody else is spamming invalid ones.
-   Credentials and identity object lack certain proofs. In particular the
    proofs that 
    
    -   sharing of the PRF key is done correctly in the identity object
    -   sharing of IdCredPub is done correctly in the credential.
    
    This requires both a range proof and a proof that a linear combination of
    values sums up to the right thing. The plan for both of these is to use
    SONIC with committed inputs.
    
    In addition to this, we currently do not enforce maximum account number (how
    many credentials can be created from a given identity object) when creating
    credentials and that is because we need a range proof as well. This also
    needs to be added when we have SONIC.
-   Credential lists need to be reworked as they were agreed, including naming
    of keys, values, etc. The attribute list should fit the following example
    
        "attributeList": {
            "chosenAttributes": {
              "firstName": "John",
              "lastName": "Doe",
              "sex": "1",
              "dob": "19800229",
              "countryOfResidence": "DE",
              "nationality": "DK",
              "idDocType": "1",
              "idDocNo": "1234567890",
              "idDocIssuer": "DK",
              "idDocIssuedAt": "20200401",
              "idDocExpiresAt": "20291231",
              "nationalIdNo": "DK123456789",
              "taxIdNo": "DE987654321"
            },
            "validTo": "203004",
            "maxAccounts": 255,
            "createdAt": "202004"
          },
-   Attribute encoding for strings needs to be reworked. It should be explicit about length. For discrete values where we don't expect any proofs, e.g., names of users, passport number, ... the encoding that was agreed upon is to use the first 6 bits of the 254 allowed in the field to encode the length, and the remaining 248 to encode the value, zero padded on the left. This allows unambiguously encoding strings even when they contain NUL characters in any position.

# Proxy for Mjolner

In addition to the libraries we currently provide a
[https://gitlab.com/Concordium/tools/wallet-proxy](proxy server) for Mjolner
that is their main contact with the baker. It provides a layer of abstraction
and some additional functionality that is not directly exposed by the baker.

This currently provides the following endpoints 
- GET /accNonce to get the next account nonce for an account, as a best guess
- GET /submissionStatus to query submission status of a given submission (i.e.,
  committed, absent, finalized, received)
- PUT /submitCredential where the wallet submits the credential to the baker.
- PUT /submitTransfer where the wallet submits the simple transfer. This currently
  has a very simplified interface to make it easy. Once the baker API is
  reworked to a protobuf version and also the transaction API is changed so it
  is not just a binary blob this should probably be changed as well.

What is currently missing from this is the transaction API for getting a list of
transactions on a given account. In the `wallet-proxy` repository there is already a
library `Lib.hs` which essentially provides what is needed; it provides a
streaming query or a paging API to get the transactions from a backend
Postgresql database. This should return all transactions that affect the balance
on a given account. The missing piece is to expose this paging in the proxy.

# Docker image for Mjolner

There is a docker images which packages all the necessary things for Mjolner.
The documentation for this is in
[https://gitlab.com/Concordium/p2p-client#wallet-local-development-mode](the P2P
repository) where the details of how to access each server is described.

This docker-compose setup will start up a local baker network and set up a PostgreSQL database that can be consumed by the `wallet-proxy`.

# TODO: Notes from a meeting with Mjolner

Attributes:

- There is a fixed list of attributes, and the wallet knows how to interpret each attribute based on the name
- Includes Generic and “Natural Person” in https://docs.google.com/spreadsheets/d/1HCj25BFwBsvi2-jvEQkOabq4p61MRni7L_HXO5TPowk/edit#gid=0  
- All values from “Natural Person” are sent as string (no integers)
- “id” in “generic” attributet is not sent
- The generic attributes will not be part of “chosenAttributes”, but will be next to them and will always be present:
  - maxAccount is an integer
  - createdAt and validTo is strings in format “YYYYMM”
  - id will never be sent (is implicit in the list format)

Transfer API

All field names should be camelCase.

- TransferSuccess ->          transferSuccess
- InvalidTargetAccount -> invalidTargetAccount
- NonExistentAmount ->  nonExistentAmount
- MalformedTransaction ->             malformedTransaction
- InsufficientEnergy ->      insufficientEnergy
- Ales will describe which fields are mandatory / optional in the submissionStatus response

Most of these JSON parsers and printers are automatically generated either in globalstate-types or globalstate and you can modify field names; search for `deriveJSON` in those packages.

Transaction List API

- We send the id of the last received transaction to Concordium Server. It returns the next page with a default page size of 20
- Ales decides whether he adds a Boolean stating whether there is more data, or we query and get and empty list when we reached the last page.

# TODO: Libraries for Mjolner

We had promised to add an additional call that validates whether the strings is a valid Concordium address. This is a function `String -> Bool` that only validates that the string is Base58Check V1 address, i.e., it corresponds to 32 bytes when decoded. It does not check that it actually exists on the chain.

This should be added to [./rust-src/wallet/src/lib.rs](./rust-src/wallet/src/lib.rs) in the same style
as the other functions, and then further exposed in the variants for Android and iOS. Martin or Ian can help with that.

Martin is the best person to contact when new version of these need to be built for Android and iOS and sent to Mjolner.

# TODO: Other stuff for Mjolner

- They want to be able to compute the transaction fee. This depends on the GTU to ENERGY conversion rate which is at the moment 1 NRG = 100 µGTU, but the intent is that it is going to be adjustable.
There needs to be some way for the wallet to obtain this and estimate the fee so that it can display it to the user.

- In the identity provider that is supplied as part of the mock server the `IpMetadata` should include the proper Notabene logo image and proper name (as opposed to the current automatically generated "Identity provider 0"). Moreover issuanceStart should be the correct Notabene URL https://app.notabene.id/idiss/authorize

- We need to expose an additional endpoint in the `wallet-proxy` for Mjolner to get the account balance.
It is unclear what the best thing to do there is, whether to take the best block, last finalized, and what to do with pending transactions that the user has sent.

- The `Get /submissionStatus` returned value needs to be reworked somewhat. Right now it will return a number of outcomes, indexed per block. Mjolner does not like the fact that outcomes can be different in different blocks (theoretically at least, probably difficult to observe in practice) so they would like a top-level field "outcome" that indicates whether 
  - the outcome is ambiguous
  - if it is not ambiguous then they would like an easier to digest format than what we have now, but it was not decided what exactly that would be. They have all the information there now.

# TODO: Libraries for Notabene

We have managed to compile the libraries for WASM but we probably need to provide a simple API for Notabene to use from Javascript. The precise API will need to be discussed with them, but once it is settled and exposed Ian is the best person to consult to get it distributed.