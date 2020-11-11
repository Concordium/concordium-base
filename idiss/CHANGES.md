# Changes for Notabene

The `token` in the return value should not be URLencoded, it should just be plain JSON.

# Additional keys

The identity provider now needs to have an additional key for signing the initial account creation transaction.
This is a normal Ed25519 signature key.

# Initial account creation flow

The initial request to the identity provider now additionally contains enough information for creation of the initial account.
The `idiss` library is extended with an additional call `create_initial_credential` that makes the data of the request for the initial account.
Specifically it returns a JSON object with fields
```json
{
    "request": {...},
    "accountAddress": "..."
}
```
where `accountAddress` is the address of the account that will be created (if everything goes as it should).

The identity provider is now responsible for submitting this data and creating the initial account.
The identity should not be returned to the user before the initial account was created.

The return value of `create_initial_account` should be submitted to the wallet-proxy. The endpoint to use is PUT /v0/submitCredential.
The result of the submission is either
- status code 2\*\* in which case the body contains a JSON object `{ "submissionId": "..." }`. The submissionId can be used to query the status of the submission.
- status code 4\*\* in which case the submission is invalid, this is most likely if the submission is a duplicate. The identity should be rejected in such a case.
- status code 5\*\* in case of an internal server error. In this case the submission should be retried after some time.

The submission status can be queried at the wallet-proxy endpoint `GET /v0/submissionStatus/{submissionId}`.
The return value is either
- status code 4\*\* in which case the given transaction submissionId is malformed, e.g., not a valid hash.
- status code 5\*\* in which case an internal server error occurred, the query should be retried after some time.
- status code 2\*\* in which case the return value is a JSON object with fields
  * status (mandatory) with a value of one of "finalized", "committed", "absent", "pending". Finalized and absent are final states. Finalized means the account creation is finalized, absent means that the transaction was invalid and was rejected. Pending is before the transaction is in any blocks, and committed means that it is in one or more blocks, but not yet finalized.
  * blockHashes (optional) is a JSON object that is only present if the transaction is committed or finalized. This provides no additional information that is relevant for the identity provider at the moment.

The identity provider is responsible for ensuring that the initial account creation transaction is successfully finalized and it should not return the identity object before this is completed.
The list of reasons for why the initial account creation could fail is as follows
- reuse of keys by the account holder
- incorrect configuration of the identity provider, i.e., use of wrong keys.

In addition to this, the wallet-proxy might have connectivity issues, or connectivity issues when communicating with the node. In such cases it will return an error code in the 5\*\* range.

# Return object

The returned identity object should be expanded. In the past it was a JSON object with a single field `identityObject`. It should now be
a JSON object with two fields
```json
{
    "identityObject": {..},
    "accountAddress": "...",
    "credential": {..}
}
```
where accountAddress is the address of the initial account that will be created
(returned by `create_initial_account` call), the credential is the initial
credential that created the account.
