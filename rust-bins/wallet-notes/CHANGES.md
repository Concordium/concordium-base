# Changes after OT4



# Changes after OT3

## Initial request and initial account creation

The `create_id_request_and_private_data` return object now has an additional
field `initialAccountData` that has the form analogous to what the return value
from `create_credential` is. An example is

```json
  "initialAccountData": {
    "accountAddress": "4ZETgG7tTVj3zT9AuwykK4SDRnLAQdwjRvEZwMPrA21tG2kBTa",
    "accountData": {
      "keys": {
        "0": {
          "signKey": "c905f640c6e873d1600f8bcd30c241386bdb8060499ad2fad016931a196e411a",
          "verifyKey": "17e852665894a1a7ec4d4250c7fb68819a12505c8ebed53ee59869eb119330b6"
        }
      },
      "threshold": 1
    },
    "encryptionPublicKey": "993fdc40bb8af4cb75caf8a53928d247be6285784b29578a06df312c28854c1bfac2fd0183967338b578772398d4120196b4864a9fec966f68e6c2c7ab474c8355c7ffdc6fa4afd70a91dc0cd83bb33df7c8e7e54fed77298c5bd803ab6a0e9f",
    "encryptionSecretKey": "993fdc40bb8af4cb75caf8a53928d247be6285784b29578a06df312c28854c1bfac2fd0183967338b578772398d412016497cd56dad49fa369404216f0108cfa366b74abbd1a3692f9ed140e46cd3ec9"
  }
```

## Identity providers have an additional public key.

This should not affect the wallet, assuming the data is never inspect and is
just passed to the library directly.

## Global parameters are changed.

Again, if the wallet never inspects them this should not affect it. The
generators field was removed because it is subsumed by others.

## A new library call to generate all accounts.

A new library call was added `generate_accounts` to generate all the accounts
from an identity object, see [./README.md](./README.md) for documentation of the
input and output formats.
