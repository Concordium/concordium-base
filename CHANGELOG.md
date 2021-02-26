# Changes since OT4

## Mobile wallet

- in the response from `create_credential` the field `accountData` is renamed to
  `accountKeys` and its structure is changed. It is now a dictionary of
  dictionaries to reflect the two-level indexing of keys.
- the "signatures" response from the transaction making functions is changed to
  reflect the two level indexing of signatures.


## Other

- the account holder signature is now on the hash of the entire credential, not
  just on the challenge. See `credential_hash_to_sign` for what exactly is being
  hashed and signed.

- the `client` tool renames `accountData` to `accountKeys` in its
  `create_credential` function.

- Transaction signatures have a double indexing now with (credentialIndex,
  keyIndex) structure.

- New transaction type updateAccountCredentials

- replaced key handling transaction types (add, update, remove) with a single
  transaction to update keys of a specific credential.
