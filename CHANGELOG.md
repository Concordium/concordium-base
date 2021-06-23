# Changes since OT4

## Idiss

- `create_identity_object` has an additional argument which is the expiry time
  of the initial credential deployment message. This is an integer denoting
  seconds since the unix epoch. This should be set to now + 5min or similar. The
  expiry determines the last time the transaction can be included in a block.
  After this time has passed, if the transaction is not committed, it will never
  be.
- The `request` field of the response from `create_identity_object` has a
  changed format, with the addition of the `messageExpiry` field.

## Mobile wallet

- in the response from `create_credential` the field `accountData` is renamed to
  `accountKeys` and its structure is changed. It is now a dictionary of
  dictionaries to reflect the two-level indexing of keys.
- the "signatures" response from the transaction making functions is changed to
  reflect the two level indexing of signatures.
- the `create_credential` function requires an additional field `expiry`, which
  should have the same format and has the same meaning as the `expiry` field
  when creating transactions, i.e., it is a u64 and denotes the number of
  seconds since the unix epoch.
- the `credential` field object in the response from `create_credential` is modified.
  There is a new field `credentialPublicKeys` and the old field `account` is removed.
- there is a new field inside the `credential` object in the response from `create_credential`.
  The field is `messageExpiry`, it is mandatory and has type `u64`.
- the input object of `create_id_request_and_private_data` has an additional optional field `arThreshold`.
  When used it must be at least 1 and no more than the number of anonymity revokers.
  When not used, the functionality is unaffected by this change.

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

- New transaction/payload type `RegisterData`. And a corresponding event `DataRegistered`.

- Two new update types for adding identity providers and anonymity revokers.
