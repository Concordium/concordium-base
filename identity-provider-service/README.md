# Identity provider service

This module contains a proof of concept identity provider service which helps to show the flow that is required by
an identity provider. It uses the provided libraries from the crypto repository to verify the incoming request,
and after an identity verifier has verified the caller's identity, to create the identity object that the wallet can
then retrieve and use. 

# How to build and run

To build the executables move to the identity-provider-service directory and run:

```cargo build --release```

## Identity provider service

Navigate next to the generated binary and run (remember to update paths to your files):

```./identity-provider-service --identity-provider identity_provider.json --anonymity-revokers anonymity_revokers.json --global-context global.json```

Here identity_provider_file.json points to the file path for a file containing a JSON representation of the IpData type, and 
anonymity_revokers_file.json refers to a file containing the JSON representation of the ArsInfos type.

### Configuration file examples

An example of each file type can be found in the `data` directory of the module.

## Identity verifier service

Navigate next to the generated binary and run:

```./identity_verifier```

## Testing with the wallet on Staging

It is possible to test identity creation using the proof of concept identity provider service locally. Build and run the
two services as described above. Install and run an Android emulator using Android 8 (it is not possible
to use Android 9 or above, as they prohibit HTTP communication by default, which this proof of concept relies on). 
When creating a new identity select `Internal test` as this will forward the wallet to `10.0.2.2` which is how
the Android emulator calls the host machine.

# Service flow description

The flow that is implemented by this proof of concept follows the flow that is expected by the current Concordium ID app 
for Android. The flow is as follows:

1. Receive a request from a wallet on `http://[hostname]:8100/api/identity?response_type=code&redirect_uri=concordiumwallet://identity-issuer/callback&state={idObjectRequest}`.
1. Deserialize `idObjectRequest` and validate its contents by using the supplied library function 
`id::identity_provider::validate_request`.
1. Perform identity verification with the identity verifier, i.e. the identity of the given caller has to be verified.
In the proof of concept the identity verifier is another service, which always verifies an identity and returns a 
static attribute list for any identity.
1. Create a signature for the received request and attribute list by using the supplied library function
`id::identity_provider::sign_identity_object`.
1. Save the corresponding revocation record that can be used by the anonymity revokers to identify the user.
1. Generate the identity object which consists of the received request, the attribute list and the signature and 
save it so that it can be retrieved later.
1. Return to the caller with an HTTP 302 Found redirect `location` header to where the identity object will be available
when processing has completed. In the case of the proof of concept it will be available instantaneously. The format of 
the `location` header is: `redirect_uri#code_uri=url_where_identity_object_can_be_retrieved`, where `redirect_uri` is
the query parameter received in step 1. The proof of concept supplies the identity object at `http://[hostname]:8100/api/identity/{id_cred_pub}`.
1. The wallet starts polling asynchronously for the identity object at the provided `code_uri`. When retrieving
 the identity object it is wrapped inside the following JSON object that the wallet expects:
```
{ 
    "status": "(done|pending|error)",
    "detail": "Optional free text",
    "token": { "identityObject": url_encoding_of_json_serialized_versioned_identity_object }
}
```
The `pending` status can be returned if the process of verifying and creating the identity is still processing. Done is used when
the identity object is available.

The flow above has also been pictured in the diagram below:

![alt text](doc/identity-provider-sequence-diagram.png "Sequence diagram")

# Exposed services

|Method|URL|Description|
|---|---|---|
|GET|`http://[hostname]:8100/api/identity?response_type=code&redirect_uri={redirect_uri}&state={idObjectRequest}`|The endpoint the wallet calls to initiate the identity creation flow.|
|GET|`http://[hostname]:8100/api/identity/{base_16_encoded_id_cred_pub}`|The endpoint that exposes access to created identity objects. The caller will be redirected to this URL after creation of an identity object, so that they can retrieve it.|
|POST|`http://[hostname]:8101/api/verify/`|An endpoint that simulates an identity verifier. The endpoint always returns OK 200 and provides a static attribute list independent of the caller.|

Here `[idObjectRequest]` should contain a URL encoded version of a JSON serialized versioned PreIdentityObject 
encapsulated with a idObjectRequest tag, i.e.: 
```
{
    "idObjectRequest" : 
    {
        "value": 
        {
            PreIdentityObject JSON...
        },
        "v": 0
    } 
}
```
encoded into a URL.