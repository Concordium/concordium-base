# identity-provider-service

This module contains a proof-of-concept identity provider service.

# How to build and run

Move to the identity-provider-service directory and run:

```cargo build --release```

Navigate next to the generated binary and run (remember to update paths to your files):

```./identity-provider-service --identity-provider identity_provider.json --anonymity-revokers anonymity_revokers.json --global-context global.json```

Here identity_provider_file.json points to the file path for a file containing a JSON representation of the IpData type, and 
anonymity_revokers_file.json refers to a file containing the JSON representation of the ArsInfos type.

# Configuration file examples

An example of each file type can be found in the `data` directory of the module.

# Exposed services

|Method|URL|
|---|---|
|GET|http://hostname:8100/api/identity?state=[idObjectRequest]|

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