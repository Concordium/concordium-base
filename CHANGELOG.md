# Changelog for the core rust-src and haskell-src libraries

The [idiss](./idiss) and [mobile_wallet](./mobile_wallet/) libraries have their
own changelogs.

## rust-src libraries (most recent on top)
   - `AccountAddress::new` is renamed to `account_address_from_registration_id`.
   - Implement `crypto_common::Serial` and `crypto_common::Deserial` for `ReceiveName` and `ContractName`.
   - Remove `Amount` from `crypto_common` and use the `Amount` defined in `concordium-contracts-common`:
     - `Amount` now has a field `micro_ccd` instead of `microgtu`.
     - The default arithmetic (operator syntax, such as `+`, `-`, `*`) with `Amount` is now unchecked.
   - There are no longer implementations of `From<u64> for Amount` and `From<Amount> for u64` as the behavior of these are not obvious.
     Instead, the functions `Amount::from_micro_ccd` or `Amount::from_ccd` and the getter `micro_ccd` should be used instead.
   - Remove `AccountAddress` from `id` and use the `AccountAddress` defined in `concordium-contracts-common`.
   - Introduce core functionality for proving and verifying properties about an identity behind an account, such as
     revealing an attribute, proving ownership of an account, and proving that an attribute is in a range.
   - Move AttributeKind from the id::ffi module to id::constants.
   - the Display implementation of AttrubuteTag has been fixed. It was off by one.
   - the `create_credential` also outputs the randomness from the commitments used 
     in the proofs for credential deployment. The client tool will also output the randomness 
     using it to create credentials. 
   - the account holder signature is now on the hash of the entire credential, not
     just on the challenge. See `credential_hash_to_sign` for what exactly is being
     hashed and signed.
   
## haskell-src library changes
   - Add support for account aliases. This introduces protocol version 3.
   - Add support for transfers with memos. This introduces protocol version 2.
   - Two new update types for adding identity providers and anonymity revokers.
   - New transaction/payload type `RegisterData`. And a corresponding event `DataRegistered`.
   - Transaction signatures have a double indexing now with (credentialIndex,
     keyIndex) structure.
   - New transaction type updateAccountCredentials
   - replaced key handling transaction types (add, update, remove) with a single
     transaction to update keys of a specific credential.

## Changes in other tools
   - the `genesis` tool now supports generating genesis for the P3 chain if
     if asked with `--gdver=5`.
   - the `genesis` tool can generate genesis for the P2 chain if asked with `--gdver=4`
   - the `client` tool renames `accountData` to `accountKeys` in its
     `create_credential` function.
