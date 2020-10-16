# Identity provider service

This module contains a proof-of-concept identity provider service which shows how the provided libraries can be used 
to verify an incoming request, and after the identity of the caller has been verified by an identity verifier, create 
a signed identity that the calling wallet can retrieve.

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

Move to the identity-provider-service directory and run:

```./identity_verifier```

# Service flow description

The flow that is implemented by this proof of concept follows the flow that is expected by the current Concordium ID apps 
for Android and iOS. The flow is as follows:

1. Receive a request from a wallet on `http://[hostname]:8100/api/identity?state={idObjectRequest}`.
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
1. Return to the caller with an HTTP 302 FOUND redirect URL to the location where the created identity object 
is available as JSON. In the case of this proof of concept the redirect URL is 
`/api/identity/{base_16_encoded_id_cred_pub}`.

After a successful flow the service provides access to the created identity object on 
`http://[hostname]:8100/api/identity/`

TODO: Add a diagram that goes hand in hand with the sequence above.

# Exposed services

|Method|URL|Description|
|---|---|---|
|GET|`http://[hostname]:8100/api/identity?state={idObjectRequest}`|The endpoint the wallet calls to initiate the identity creation flow.|
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