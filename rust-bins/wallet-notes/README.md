# Libraries

The wallet libraries expose a functionality that will be needed by the wallet.
They expose an interface which takes JSON input and JSON output and it is up to
the user of the libraries to supply correct data and ensure any invariants and
preconditions that are specified.

The library currently exposes the following methods with the following
c-compatible signatures.
- ```char* create_id_request_and_private_data(const char*, uint8_t*)```
- ```char* create_credential(const char*, uint8_t*)```
- ```void free_response_string(char*)```

After calling the `create_id_request_and_private_data` function it is the
__caller's__ responsibility to free the returned string via the
`free_response_string` function.

The  `create_id_request_and_private_data` will either
- successfully generate the required information (see below for the format) and
  set the second parameter to `1`. In this case the returned string is a JSON value.
- or fail and set the second parameter to `0`. In this case the returned string
  is a description of the error.
  
In all cases the precondition is that the input string is a NUL-terminated
UTF8-string, and the returned string is likewise a NUL-terminated UTF8-encoded string.

## create_id_request_and_private_data

This function takes as input a NUL-terminated UTF8-encoded string. The string
must be a valid JSON object with fields

- "ipInfo" ... is a JSON object that describes the identity provider. This 
  data is the one obtained from the server by making a GET request to /ip_info,
  e.g.,
  
  ```curl -XGET localhost:8000/ip_info```
  
  See below for the description of the server.

The output of this function is a JSON object with two keys
- "idObjectRequest" - this is the identity object request that should be sent to
  the identity provider
- "privateIdObjectData" - this is the __private__ information that the user must
  keep in order to be able to use the returned identity object.
  
An example returned value is in the file [example-id-object-data.json](example-id-object-data.json).

### Performance

At the moment the `create_id_request_and_private_data` call takes about 30ms on
a AMD Ryzen 7 3700X. Memory consumption is on the order of a few kB.

## create_credential

This function takes as input a NUL-terminated UTF8-encoded string. The string
must be a valid JSON object with fields
- "identityObject" ... this must contain the value returned by the identity provider.
- "privateIdObjectData" ... this is the value that was returned by the
  `create_id_request_and_private_data` function and stored locally
- "global" ... this are the global parameters with a number of cryptographic
  keys. They can be retrieved from the server, see below.
- "ipInfo" ... same as in the `create_id_request_and_private_data` call
- "revealedAttributes" ... attributes which the user wishes to reveal. This is
  an array of attribute names. The user should select these from among the
  attributes in the identityObject field. The key "revealedAttributes" is
  optional. If not present we take it as the empty set.
- "accountNumber" ... this must be a number between 0 and 255 (inclusive).
  Multiple credentials can be generated from the same identity object, and this
  number is essentially a nonce. It __must__ be different for different
  credentials from the same id object, otherwise the credential will not be
  accepted by the chain.
- "accountData" ... this is an optional field describing the account to which
  the generated credential should be attached. If not present we assume that a
  fresh account is to be created, which means the library will generate an
  account key for this account.

The returned value is a JSON object with the following fields.
- "credential" - this is the credential that is to be deployed on the chain. All
  data here is public.
- "accountData" - contains the public and __private__ keys of the account the
  credential belongs to. This is very sensitive and must be kept protected.
- "accountAddress" - the address of the account this credential belongs to. This
  will either be a new account or existing account, depending on the input "accountData".

An example input to this request is in the file [credential-input.json](credential-input.json).

## Example
The [Example C program](example.c) that uses the library is available. This
program reads a JSON file and passes it to the library, retrieving and printing
the result. On a linux system the program can be compiled and run like so.
  - First compile the libraries in [../rust-src](../rust-src) by running 
    ```cargo build --release```. 
  - Next from this directory run
    ```gcc example.c -lwallet -L ../../rust-src/target/release/ -o example```
    or 
    ```clang example.c -lwallet -L ../../rust-src/target/release/ -o example```
    depending on what C compiler is preffered.

The binary can then be run as something like the following
- ```LD_LIBRARY_PATH=../../rust-src/target/release ./example input.json``` 
  which will try to call `create_id_request_and_private_data` with the contents
  of [input.json](input.json)
- ```LD_LIBRARY_PATH=../../rust-src/target/release ./example credential-input.json``` 
  which will try to call `create_credential` with the contents
  of [credential-input.json](credential-input.json)

# Simple server acting as the identity provider

To enable testing of the wallet with respect to the identity provider while the
details are being resolved with our partners.

The server is a minimal server which (by default) listens on `localhost:8000`
and accepts `GET` requests. At the moment two requests are supported.

- get the public information about the identity provider needed to construct the
  request. The request can be made as
  ```curl -XGET localhost:8000/ip_info```
  or equivalent. This returns a single JSON object in the format which can be
  passed as part of the request to the library.
  
- get the global parameters that will be needed for the deployment of
  credential. This is a number of public keys, etc.
  ```curl -XGET localhost:8000/global```
  This returns a single JSON in the format which can be passed as part of a
  request to create a credential.

- Get the identity object based on the request returned from a library call.
  The request must be encoded in a URL parameter with key `id_request`. The
  value must be in the format returned by the library.
  
  The small python script [example-request.py](example-request.py) illustrates
  how a request should be done. This script reads the file
  [id-request.json](id_request.json) which should contain the content returned
  from the call to the library minus the `privateIdObjectData`.

  At the moment the server will immeditely reply with the signed identity object
  which the wallet must store. How this will proceed in the future will be
  worked out over the next few weeks with our partner. Regardless of how the
  identity verification is going to proceed, what is returned is going to stay
  similar to what it now, with perhaps the format being change a little.

  The returned object is the Identity Object which the wallet must store
  securely, and back up.

# Example JSON input/output files mapping.

- [input.json](input.json) the input to the library call to create id request.
- [example-id-object-data.json](example-id-object-data.json) response from the
  library call to create id request.
- [id-request.json](id-request.json) data to be sent to the identity provider to
  request the identity object
- [example-id-object-response.json](example-id-object-response.json) response
  from the identity provider, the identity object.
- [credential-input.json](credential-input.json) input to the creation of the
  credential library call.
- [credential-response.json](credential.json) the response from credential creation call.


# How to run the server
  From the current directory, the easiest way to run the server is to have
  `cargo` installed and run

  ```cargo run --release --bin wallet_server -- --ip-data database/identity_provider-0.json --global database/global.json```
