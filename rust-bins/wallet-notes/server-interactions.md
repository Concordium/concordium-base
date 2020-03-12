# Account creation

In order to create an account the wallet will have to submit the credential.
The example is n [credential-response.json](credential-response.json), and
specifically the part of the object under "credential" is what should be sent.

The wallet should make a PUT request to the middleware with the object
```json
{
  "credential": {...}
}
```

The response body will contain a JSON payload with either the body
```json
{
  "status": "success",
  "transactionHash":
  "978d98d3748f79299fc3e147c3526e7cbc6e8b0812d5ac95d05bd810cff6b141" // 64 base-16 characters
}
```
or 

```json
{
  "status": "error",
  "error": "String describing the error"
}
```

In the first case the submission was successful and the returned hash can be
used to query the status of the submission. In the latter case something went
wrong. This latter case should not happen unless there are connectivity issues
between the middleware and the node, or if there are format issues with the
request. This latter should not happen if versions are consistent throughout the
stack.

# Query status

Status can be queried by making a GET request to, e.g., 
`transactionStatus/978d98d3748f79299fc3e147c3526e7cbc6e8b0812d5ac95d05bd810cff6b141`.

The response to this will be either `Null` if the server does not know about
this particular object, or a JSON object with the following structure

```json
{
    "status": "received"/"committed"/"finalized",
    "$blockhash_1": "$transactionsummary_1"
    "$blockhash_2": "$transactionsummary_2"
    ...
}
```

where "$blockhash" is the hash of the block this transaction appears in. If the
status is `received` then there should be no blocks, if the status is
`committed` there will be at least one block, and possibly many. If the status
is `finalized` there should be exactly one block.

Transaction summary is the summary of the transaction, and is always an object
with of the following shape.

```json
{
   "sender": //String, address of the sender of the transaction, can be Null
   "hash": //String, hash of the transction,
   "cost": //Number, amount of GTU charged to execute this transaction
   "energycost": //Number, the amount of energy used by execution of this transaction
   "type": //String, type of the transaction, Null for credential deployment,
   "result": //Object, result of transaction execution, see below,
   "index": //Number, index of the transaction in the block (i.e., 0, 1, ...)
}
```

The result of transaction execution is an object of the form
```json
{
   "outcome": "success"/"reject",
   "details": //format dependent on outcome and transaction type, details to come
}
```
