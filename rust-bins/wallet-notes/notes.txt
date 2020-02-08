# Libraries

The wallet libraries expose a functionality that will be needed by the wallet.
They expose an interface which takes JSON input and JSON output and it is up to
the user of the libraries to supply correct data and ensure any invariants and
preconditions that are specified.

The library currently exposes the following methods with the following
c-compatible signatures.
- ```char* create_id_request_and_private_data(const char*, uint8_t*)```
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
```LD_LIBRARY_PATH=../../rust-src/target/release ./example```

This will print, if successful, a JSON object with two fields `idObjectRequest`
and `privateIdObjectData`. These are the values returned by the function
`create_id_request_and_private_data`. The value in `idObjectRequest` is what
should be sent to the identity provider, and the `privateIdObjectData` is the
data that must be kept secure by the user. It will be needed in next steps to
create credentials. This object contains a number of secret keys which should be
secured by the wallet.

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
