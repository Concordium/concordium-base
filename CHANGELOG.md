# Changelog for the core rust-src and haskell-src libraries

The [idiss](./idiss) and [mobile_wallet](./mobile_wallet/) libraries have their
own changelogs.

## rust-src libraries (most recent on top)
   - Move AttributeKind from the id::ffi module to id::constants.
   - the Display implementation of AttrubuteTag has been fixed. It was off by one.
   - the `create_credential` also outputs the randomness from the commitments used 
     in the proofs for credential deployment. The client tool will also output the randomness 
     using it to create credentials. 
   - the account holder signature is now on the hash of the entire credential, not
     just on the challenge. See `credential_hash_to_sign` for what exactly is being
     hashed and signed.
   
## haskell-src library changes
   - Add support for transfers with memos. This introduces protocol version 2.
   - Two new update types for adding identity providers and anonymity revokers.
   - New transaction/payload type `RegisterData`. And a corresponding event `DataRegistered`.
   - Transaction signatures have a double indexing now with (credentialIndex,
     keyIndex) structure.
   - New transaction type updateAccountCredentials
   - replaced key handling transaction types (add, update, remove) with a single
     transaction to update keys of a specific credential.

## Changes in other tools
   - the `genesis` tool can generate genesis for the P2 chain if supplied with
     genesis parameters in version 4.
   - the `client` tool renames `accountData` to `accountKeys` in its
     `create_credential` function.
