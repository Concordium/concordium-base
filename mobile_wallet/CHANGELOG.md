# Changelog

## 0.9.0
   - The functions `create_transfer` and `create_encrypted_transfer` have been extended to support
     the new transfer types, i.e. transfer with memo and encrypted transfer with memo, respectively.
     If the JSON field `memo` is given in the input, `create_transfer` will use the payload for
     transfer with memo, and `create_encrypted_transfer` will use the payload for encrypted transfer
    with memo. If the `memo` is not given in the input, the functions will use the payloads for transfer
    and encrypted transfer, respectively. 

## 0.8.0
   - in the response `create_credential` the field `commitmentsRandomness` is added and
     contains the randomness from commitments used in proofs.
   - the input object of `create_id_request_and_private_data` has an additional optional field `arThreshold`.
     When used it must be at least 1 and no more than the number of anonymity revokers.
     When not used, the functionality is unaffected by this change.

## 0.7.0
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
