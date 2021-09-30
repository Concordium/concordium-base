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

```console
./identity-provider-service --anonymity-revokers data/anonymity_revokers.json --identity-provider data/identity_provider.json --wallet-proxy-base url-for-wallet-proxy --retrieve-base identity-provider-service-base-url --global-context data/global.json
```

Here identity_provider_file.json points to the file path containing the JSON representation of the identity provider public and private keys.
The `anonymity_revokers_file.json` refers to a file containing the JSON
representation of the anonymity revoker's public keys. This list determines the
supported anonymity revokers.

### Configuration file examples

An example of each file type can be found in the [./data](./data) subdirectory.

## Identity verifier service

The identity verifier is a supporting service that verifies the real-life
identity of the user. In this POC we assume that the service has a REST API that
the provider uses. The identity provider redirects the caller, after it has
validated the cryptographic proofs, to the identity verifier, which would
then verify the real-life identity, by e.g., asking the user to take photos, and
provide documents. In the proof of concept the user can simply input all their
personal attributes manually, and the identity verifier will accept them without
challenging the information.

The identity verifier can be run by using:

```console
cargo run --release --bin identity-verifier -- --id-provider-url url-for-identity-provider-service --identity-provider-public data/identity_provider.pub.json
```

or directly running the binary `identity_verifier` in `./target/release/`.

## Testing with the wallet on Staging

It is possible to test identity creation using the proof of concept identity provider service locally. Build and run the
two services as described above. Install and run an Android emulator using Android 8 (it is not possible
to use Android 9 or above, as they prohibit HTTP communication by default, which this proof of concept relies on).
When creating a new identity select `Internal test` as this will forward the wallet to `10.0.2.2` which is how
the Android emulator calls the host machine.

## Exposed services

|Method|URL|Description|
|---|---|---|
|GET (+POST)|`http://[hostname]:[provider_port]/api/identity`|The endpoint the wallet calls to initiate the identity creation flow. It performs validation of the incoming request and if valid forwards the user to the identity verifier service.|
|GET|`http://[hostname]:[provider_port]/api/identity/create/{id_cred_pub}`|Endpoint that the identity verifier forwards the user to after having validated their attributes. If the user has created a valid set of attributes, then this endpoint will ensure that an identity is created.|
|GET|`http://[hostname]:[provider_port]/api/identity/{base_16_encoded_id_cred_pub}`|The endpoint that exposes access to created identity objects. The caller will be redirected to this URL after creation of an identity object, so that they can retrieve it.|
|GET|`http://[hostname]:[verifier_port]/api/verify/`|An endpoint that simulates an identity verifier. The endpoint presents an HTML form where the user can submit their attributes which will always be accepted. In a real world application the attributes would have to be verified.|
|POST|`http://[hostname]:[verifier_port]/api/submit/`|Accepts submissions from the HTML for served by the verifier. The attributes are saved to a file database. No verification of the attributes are performed for the POC.|
|GET|`http://[hostname]:[verifier_port]/api/verify/attributes/{id_cred_pub}`|Provides read access to saved attributes. The identity provider accesses this endpoint to get attributes, and assumes that if an attribute list exists, then the user has been verified successfully.|

The POST method is only there for historical reasons. The GET method is the one in use.

The `state` field of the initial `GET` request should be urlencoded string
containing valid JSON of the form
```json
{
    "idObjectRequest": {
        "v": 0,
        "value": {
            PreIdentityObject JSON
        }
    }
}
```
and `redirect_uri` should be a string.


The initial POST request should have content-type `application/json` and the body should be a JSON object in the format
```json
{
    "idObjectRequest": {
        "v": 0,
        "value": {
            PreIdentityObject JSON
        }
    },
    "redirectURI": "url where the response is redirected"
}
```


# Service flow description

The flow that is implemented by this proof of concept follows the flow that is expected by the current Concordium ID app
for Android. The flow is as follows:

1. Receive a request from a wallet on `http://[hostname]:8100/api/identity
1. Deserialize `IdentityObjectRequest` and validate its contents by using the supplied library function
`id::identity_provider::validate_request`. The validated request is saved in the database.
1. Forward the wallet to the identity verification attribute HTML form. When forwarding a signature on the `id_cred_pub`
   is also provided to the identity verifier, so that the identity verifier can verify if the incoming submission
   should be handled or not.
1. The user fills out the attribute form and submits it to the identity verifier, which then verifies the signature
   from the identity provider service using its public-key, and then saves the attributes to a file database. If the
   signature is invalid the submission is rejected. At this step the identity verifier should validate the attributes of
   the user, but for the POC the attributes are simply accepted at face value. Afterwards the user is forwarded back
   to the identity provider service that will perform the next step.
1. Read the validated request from the database that matches the current flow. The attribute list for the given user
is retrieved from the identity verifier. The request and attribute list are signed by using the supplied library function
`id::identity_provider::sign_identity_object`.
1. Save the corresponding revocation record that can be used by the anonymity revokers to identify the user.
1. Generate the identity object which consists of the received request, the attribute list and the signature and
save it so that it can be retrieved later.
1. Create the initial account transaction using the supplied library function and submit it to a Concordium-run service `wallet-proxy`.
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
    "token": { "identityObject": {...},
               "accountAddress": "address of the initial account"
    }
}
```
- If status is `done` then the `token` field is present in the described format.
- If status is `pending` then the `token` field is either not present or `null`
- If status is `error` then the `token` field is either not present or `null`, and the `detail` field is present, describing the error.

The flow above has also been pictured in the diagram below:

![alt text](doc/identity-provider-sequence-diagram.png "Sequence diagram")

# Steps to manually test an identity provider service

The following steps can be taken to manually test an implementation of an identity provider. Note that the example
provided here is tied into the test data provided in the `data` directory, i.e. if you change the identity-provider,
then the following example won't be successful.

The test data files can be regenerated with the
[./generate-testdata.sh](./generate-testdata.sh) script, however this should
only be done if some formats have changed.

1. Act as a client that wants a new identity and send the request in [data/valid_request.json](./data/valid_request.json)
1. If the identity provider returned successfully, then verify that the HTTP code is 302 Found, and that the `location`
header is `concordiumwallet://identity-issuer/callback#code_uri=url_where_identity_object_is_available`. The first part
is  determined by the value of `redirect_uri`, but the value for `code_uri` is controlled by the identity provider
implementation, and should direct to the service that serves the identity object when it has been created.
1. Verify that the anonymity revocation record and the identity object have been stored if the identity verification
process has completed.
1. Test that the identity object can be retrieved by sending the following request:
    ```
    GET url_where_identity_object_is_available
    ```
1. An example of a successful response is HTTP 200 with the following bodies depending on the scenario:
```json
{
  "token": {
    "accountAddress": "38nWQqVECPAe34JKknEC4xAXgnzPxYawMZ3eBrFVZx9Tqos1L3",
    "identityObject": {
      "v": 0,
      "value": {
        "attributeList": {
          "chosenAttributes": {
            "countryOfResidence": "DE",
            "dob": "19700101",
            "firstName": "John",
            "idDocExpiresAt": "20291231",
            "idDocIssuedAt": "20200401",
            "idDocIssuer": "DK",
            "idDocNo": "1234567890",
            "idDocType": "1",
            "lastName": "Doe",
            "nationality": "DK",
            "sex": "1"
          },
          "createdAt": "202011",
          "maxAccounts": 200,
          "validTo": "202111"
        },
        "preIdentityObject": {
          "choiceArData": {
            "arIdentities": [
              1,
              2,
              3,
              4
            ],
            "threshold": 2
          },
          "idCredSecCommitment": "ad56aefd6d7cf58ef7359f0dfbe52f25182a484acdf9902b179772e63ce154a15a5a07b3863b5b3b1a47922448601ee9",
          "ipArData": {
            "1": {
              "encPrfKeyShare": "8b4eba22d5ed22ef04d6563bcb77f3d1b8afc1fb960d28b03f2192c1cb53afe3ba70ec461c5782624a40ec72823a0a99aca4fe770da76f692e40b337f271a714d56b476dcd01b67549dd2c27843b9d78d7d4a0cfb9810bcd0ef01cc51b3b8c26b83b59e271ac4ec2c9313e12a81cb726e3e5f27be7c3d96646e9440cb53d39feff50d39f66ca37c94e0df90f2e3ad180a2bfb7f3a9c6a5519cc3245a3aceed111687b795e312c187c043655de7783f378cf5f345a530dc93dc2c67b91ec96c168d0f3f4c5f2b5040a17bae90a5eb4ec273832d30212de09ad60406506590acaf632a5fd22e3decfc5d63437b9211c9a3b9cc37fec1ae17ca93129168b6e676c18e14bcfceb83d907115fa6cf25c37d65466ed0d855dce9ed4c24d767f5bc681cb7c13979de473aa09eeb365277ee82c7e9195dd74ecaa590464a14dd952a512fc8ad4aa631f41f961048a809c9756080a2cf2ae0c961bd1686a334f4672f7becf0f989eff5e47e74298c845587e7d34488420db02ec1f5f21110e7d214e33f41a37ba7706d78c202fff6a4c4c7e06a7be4c71e79c87967cf6eeb04aaea102ee78619ccdc923b4640339804693e60468e8e377008d59840e4e682b97db0356e09312f8ca37ae8b5a7fca3294125dfe81739525fcb691cae39c99408d14ca5c320b17028496701374a4e2bcd6eca5b9520e01b1821f9febf6bd89ba5ca4da0ac7679ef6e6b77c79d00224c1cdec1cbbe62905a1eff772b8f6988af62a24891a608be4ffded3dab65bc81cdde1b308f7010c05546f898dcf3ac7390cc5056406dbea57aa67bf6c6606cc50b3f10c7097c63f5d7d1428357868c232aee3bab4f703d1f7fe93eb1f8f4173592ec41ee897d8288f0584cc2343677cf86b6d9edd25ca93f3f083c6913be5398fe8df0b7ea0c65e92ea88c2290de6744a66c592203f5a182ac6dc7a494ed5c403b26a34e2cfffd8c2313dc31de43eaf9c0c7870ecc2e51fa51d69d563d53b70bf81a3bd2a2b39885fc49a2aeeda035ad674b7e8df678ac32b8e6e132f8754ab11db1c0c81ee58472cf7371ec9616a747f20693c16ffedc",
              "proofComEncEq": "7247523e29c937ae61cbdf11fb14d64e94d365d39c891c5a4cefb822a9f5e22772066da0251b2fe319f41782213873dbfbd3eabb8d33f1ef245b28d4b0cd0f1b223403a2f9ee2780fdc13dda0c78e5f1233d0dbc890f515d4112d103679d8a80"
            },
            "2": {
              "encPrfKeyShare": "a3a94ab8d57a17bffc1c6135780935ff59de663f12ae5b0dce77fce03949b81e7041b55822d90fefea59831c23b22d6e8946cac723081adc5dac893b80917195ac37d31472fda3a490bee0e5f207241da102b7451819fbb1c0f0d5c95e03c6b394d96cc6db80bfe81e6ed4770a4202d37fd52d4b66ada41bf35d20e661728e20447bf2141d6aaff87e66f41ede294a8688d30a0fb19587f175a7fd64da3faf9d91927730abfea498a695eae136141067ea4bdf20f4968d105edcba3d4a206783821fb904383d572cecf41343781139c3db0d3326fc18929cadd925156a9dd2d84fa6d029ab66042b2557b06351165340b13a4dd5c5bf0215582317c6d09e5d5a6586ea02d1c3f5d00272f76ac93ceced93e46ee02c5090d5f85ff66b92bc309391299efdf2ba12909ca5ce75d6e7190e0576783769bca47fb633a40a95b5910a98ce0e0d7385fa1252da92a68381e7f9812c1574c5b24e95bbcaa957ae47405e611bcfaf553fb92e215ce08e185722ea16b2db46c8e5484d1bea886a5b462768ab09ae55ffe9769d1712a9608a517ec7bc3ffecb2afc481c1f1b883177eb818a47326404a240ca2d5e5157e4390c003b8cf42e2d790b029ceca9d61f82e536a2bdf85676fd378bf62d568d1fa2ce34b2968872b86d4af5cdfefe5bc53f0f80d9a3edf2bebe519abd9bb7032af4a6e96974dd6aa51af9e13244d035cb898487c8ab319002c80094e8ac504ba9448d5c5ca6b4c3f8b4ada25b8d967397706353b1de3679d94d4b8ba3260936a2e05212a451dd2f72a2dc55ee1c9df13fe8412266a32e880feba2304c246b5825cfac8b4065b903fd381c4f0b07360af7d87ceb9fe1f9c5bcb271b51670a0352b2ac97c718632703689248540fdedf1ff2122687e4a362a4e2825bf2a3acc9ac75cfc9d412419f0b3c1bead8706835204e9d9b72ab59d52ca7c099674c7e960f872fc3741c4ab4ac068f1dc798d02ec798b7b8825dbb943b54e4f82ceed7fb369d470cd7a8403d7761254779421c9eb4c0bf92f3aa2e0220d4461b5e192b898a7e7f7feab7480896225786141bfd93a020abc1ae6",
              "proofComEncEq": "441747545cca82001883aa5c4f1fdfa46f68491e292984317819d1bda216f0ad06d76533e8dbe6b21c6f2beacb24e37b6afc7624d37f1e3a1a96392ecfcfd5390d9f40b9d2a651b832371d17f7cca65e37e399f8512f5a1cab3062b70e84c0a4"
            },
            "3": {
              "encPrfKeyShare": "b3eb77fabbabade6f29b1f0ef416e12086c6e617abfc3f40be1f8cfa0d8331196c654065966c3273510209bebd1584218927c1c10b536d6c8eaca7fab3e7ab2f24b57518a34a3b06e55c187699336a78d385a8ec1212efe7ed8e3c6b367a65c08104ad35abc26d07fd8d945c9a2d74d55c5df5090a4c7158557d1df14a353f26d1000f11dd831dc98a2d8ef147c28a448ab9c63affe3d42119a47adf57b8d55d436c364170bebbd474d889ac5ad9e773e8e54788d18ea764ddcd9feadbe7d77097a1daff1b6d93e9b147281312c4118be25d72c796e2fc1c19038cb068072f07b323ee7612362ff1c58cb4ab9812d02ab9930536a4712eba3665e54c70405547da6578ccaf88b420862279113dce885a72971a0e1fcb5894c300971019a02ea789fd4d6bbf6e028ac08a73ab18c0f4c45c56f466647dc3ef5520b7719eed9b3e39bd1886ac7a6e7c081dc20243c78e6fb1c8d25ae3ce829412e243626ca2716e8fee4315388e20f86b47483d684001333c4caf54baf1e354a93b1022f5912fc38a2db901904b9fd231d350ab1b85a739442873d9a56ab881265cff5d31719c5ec06ac4d3ae977e5cd36792b53967da6da1656d6cc7e291417934e0bb45e60ea128f365f12d8ec76895b90c39f21e5deed9ec35cc11e0211be8826b530fb95fd4881ec74a259b3857602f8eb8a6def62070da89b7b7824b8dfcc1b6066d582ecd1cea887142102f151fc893727bfe41f8af55dcc2c9d56d6633ac054810dec5e96ac5ce4257e0a20562276a9817ee5af4cd16c83ed0ce7980fb83572e72bb643a999db7b813f8c2390d243e0c13fcafc56cd105de149a11720bc3c5d02bc2aab98890dbd8500d2bc7c1b78015579ea78ba7173cebe56e85d9d1f38a6945a4abc9414927e00a9fc40abff89e9bdb76b4569cec17ea26d285e032bdaf3a50968683ae22b3efe1ad7492ab4d8b1bd8a0ab15bc02cde90852986daa456f6444ea90c60226b10f3b3a51972b46c1a12183af8c9333f3923578833b19a59f1c26bc3915b6c40fbb400807af776d8bf288687bf86d05a4a394b6449a08bba5874744c522",
              "proofComEncEq": "22b77c9d65768a36a8c632309667e0a1e92775485145c3ac3ba075afaac313a0531603608e3966684edc4c3a4f8f1d4b3336acc911184292dcb77d944bef03d70e000b85ba2bd004de6a6fb9bda465877fdf9d47fcb4aca0b026dc6d30350200"
            },
            "4": {
              "encPrfKeyShare": "86ebb61979a51d9706cf0be7a2a1be1c453d550781c231712d27bab93834b1e603c1ebcebd8178aeb3d5586b9bc3a06ba044469ad3520f2f9b5e860997eb04cc301dc27213951ea30d8659be8495d8c19d33fd3438f232ba7e94cdb2f0e027d8966f6bb356bd2a95d92d90e8518ce61fe446b7b72fbe91a0eae667c26afcddef070f4c33d222b4af5d9c3ef0ba228eea82e57d545d14b37c7291e8188ce8a7c7391d41616451ef1c8f88383e6eeaa68e5102f44b6abb199d57aa0e41791450fe9040951bbebfa66c4786856b6d29a3a3fa66ef32feeca1e2458df3ceb0297e0240adfc49f67b977bbb70b1ffffe0859fb6a3c90682a98cb4bcb42f86f8b6488874151e1cb50ef53acd73368206f483fc1943209aa870db2ebd57787c9ff3ee4094d7030440ce661263251a63ed33ec8b881e776475c48edb0ca61d71d6554abc8e99241450cb09643c5bc49da6cd374d925c0c35cc18825ad34237b88fe8e5bc8fb8966e6eaf5f501d5b29ba341a796a3ae9b22f0f9e8f7e191977cd2b6c9eafac7a98f3d3c9be6eef99d2a88e11b114fc5824d715ccf1222db6ae517f0a66b7dec48cdbb95539442f260a5d861880cda3dfb8da0cb5ba85ebb715dd92b7ab95d60d79f185b9b9842477fefd70240cc1478f7c5ebfef26ec48cda2c95d14f3c082130852779d9040050b9f34cd4e6d8327ef69de81788c28fbbe835113879fe835a91e5bf7416a833d020c63587b6b6f89de3c16e5f1999e7166fbac90c5e23ab493d6b5c907a3efad3ed607c150bb632021b1b48f10d58392d6c2be8381140596b7bc2932de168af10e08e1d1a688dfcd9a8c40f2936d2724b74682a190fc98d1645e0f08948feb647a718784229bcdb709ca9444db1e2aa406200100ed07fa533f4d021ec58dad0cc94a62fc5bff64ab2679c41c02049165a8fbd276223594976e22743897ce31909cc22139ae697373881dc8278e5383fb9dd2b0b5fa4d1b79161abc18237750d54b10256438372083fa1f539b1a5f08a59841fdf14fbc654df2190f0ff472fb8e5d7503dc9ccbcc87af605bfcd02449f2d4de3c1de759d9",
              "proofComEncEq": "408dca530a07add604d31e4b82aadc08577092898a0d1f135390363a9df8b2c73a4da45c6a4f1ddb25189455a741bd4637377053b98ee2dc465167f91f06dc4125122619c6349983bd0d7007f7016a0e157feb68bf607368e94a594d748dc6a6"
            }
          },
          "prfKeyCommitmentWithIP": "970cf34d0e884a6b5ea286a6f41a54b04dbba46c2f74d42d95199400d5a0d0f350c98a443a2a87ec5466bd933a01072b",
          "prfKeySharingCoeffCommitments": [
            "8a369f6311dae3d899ebad5c3842ec16db4e7dbc260d0a26ca6f191fbff4cfdf8c0be1f3733981f24a53283339841589",
            "b82c7a5a0b22b4c7fa04f953487369fdecfe88296d16c8f879dce691b896f76a7b4a72a5a2c047405c31d0dda1b51b9c"
          ],
          "proofsOfKnowledge": "1a27fcd28eb932903d0807c645236b13c7662cd51de7dc86541b38fb5b0755396d650d1536c89063dfcb31f7dbecaae279454ca64cb1ce6c173ed6c8924099f248e81ad991af6cd447e2673647bc2cf6e034d3bf8cc4d2143fdc41f050142fca0bf076d47ced9a550a7372e45ac52a541e44bebe78fe0031fffb75c96928bdc1190970542a4ca5f908f8c6917bb576190c66bb1a8eaec6718de6819bf07ffe2a43b32d54791c0de11a69ccf9da0f683084f7bf0cf6afb3dfee775781a03193280f4cb71854d58bd37145377a0510b2742d3956d61b465b1c58062ec47b6c75b3405c992e44b9549a96f689b9da36bb83f4c2fd59531e90aa66d34cbc1687840b400ac4ca8e8c9898f01831370a8a0f11d868fc84678c8988bfd0e2a77b39b9b6030061948d67b9f304fc98757cfbda919b22e4b1aa6e437566883c03e8825e416eed6fc406d91721f5807923daf186fd1864c82aec91c9eaad58454e399be0f47e0c0102e43c27c30817bf116ea6b24f4fb80f12aff8f58450b9c5a46d809d700550f570342ac5c839e00710dde4dc1f28fcb92f364feeecc5340cb569cb04a3958a0802c1875ec49133cec6ec607f58edeefea9d99f9b56f2ab9fcee1893b7fef9a1eab5df20bd084f241976185c755468f1602afed59017a4d6a64e56f343c979ee70b00000000000000048ec38fe57ba79e3a4ba787ae1d0ef208c33200f4a08c0c4f29eb7924ad7771b161da839aa1d752e1036eae9a47b3d6a28cfb4b75a8b9e5f7d11e8fc14d754f9723654b3365ab0984f78138556a4860380fcdfb102834f9e74e900b1184a7a0e18fd7c194404f0adc0d98e514be37f7d045ea90f19f2a5c65ec9f0aa1429e7cce4d23e04db2debfdca52afc4546267102873c4cde65c0dee744ed078c0b22b1e855e1b654f75ca2ef41ac0bb05404a9b86e5b444d6762382f817c5293faba2d9628910ddcc1601df3aa49403faba9f88bc0b1db7d86de647d714a06ad1f5498723c77638ef18cf595b5584b4d1e8eb920f140dfdb59a8ea4e1db87c28ee4d431c1387b50021a242b2b7e5a20b720982615ba3be05f17291aebc7a8e83d0e6f26000000008b19e779a51d8b691898a63599160205b834e9737fd5cddc6f5d6513dd2d7f9f200cd6803eb43b53c44582dfa29747d74b19ef1f0ab0d490bde98e7949d9a057e91e26a590b1f7ab008beab927d958a6267f76adfce00ff465b12ef832ac3e78fb71ce025a01e9d394eedc209ebabab9b6e3b657c6ed7f811b63135566fbbd381950e41bbb15d496e4b2d29e4eb062744b14831453b505a942bf5714e5a927785dd919a421c4ab2ff1f3c111c1b1c28fc07c39d45197d2dddaf8dd4bb00f7e01897c4d9e6c4f0b8a1bc373228672851d58398d75e7396ea7e56b6f750501c8f02b586170ec1dbab5b6ed1ebd0e68dd4adaa43d5bc02f75e325ba03048e9ade6819c1a7cd3b9d02fbb34b405998e8a53adc1fb64ecf21577ec84457bd3528605d885d31fa6b031e70c1ffc9c9b47deaffb506f88648e304ffb47eaaf15d5c8c8f38dba62009ff7e97beced948959f03141993a361ef0dbe872d172d15a041b78b3dba8ecce3171221c78a48056fd7608a2a00ecb9108088a87c93fa964303a994e8c1420a3daad6ed41142d6976954351324ca9efc5dee7def42d76d2253fb1cf96a44b4eeae48eb27e7d15d135f51ffbfa58a6c9263b41028a4c93ea0d5e2ff2ec803d793d0edfba8d254b886b463bef6d3e3b3827cf459363c55835b6bc0bec3b01ca89a3eb697a53dcfad4e16e850fabbc43d82ba7b6ff72a91d081102c73a3600261527be4fcfc40e1b8af7b167d80873f4361664c25d281b984e540c68ac11409ccf3bf6b2dba6b519cea9860b4287044b9fe6d8cb133b5c0f6c0b6d8d7faae656f26085374b562b99a2c84392bad6d532070494411f5e2ef17ffbd060c0b712e9c5e2682746556f7451e10e29d05a61f79df0469f46961607147cfc0ea2fd7aa65e7b705693a7c78606ef94cf33ed7ba5c5c75ba3f0b7840ea325cd43ad2a23dfb2fc8e4c6e774810484da288c69feed9de97782d7e7fb91f5223acffab359e1caf683aabab22f580544ffa1c6f6b6ea26f386b1d55a7f3eac3a8587315508e02dd013b6c49128ebb86c91c82936a60b523cad6fcd4e7bcdd2c1caf24f5d4c7c908153d3f33b9e13db137c06d0d5c2dcf3b7f035608db71b1dd2e0c156a118d476751e351aa16f17ba2068bc2d2183b36de617fc006f4b213a9eb6c3c2e68a48e7390523a6cf26c05a58479e93b648909558e5b23e06b793e646d5577b5f0f93407035b63f6515b9b3d309d2e761a9b4187736c8996c66dd99c3374223778a9680715f0c1c5d0d14cb42802ba01cdbc86a101d9aa78f7c84f050d771868cb7b050adcffb50e78c5a0c8f9738ccdd82c0df3081e6878edb5966690090f5495b334899a505d21f84f5b110722b1979863f7f94e35b5d013a89c11bd8b222cca75336b78731d6608ae7e705cd99dc4a8b9f36839a005fc839786e31bf5f61625d89beeb84d69db4437b443447a1b35400bc3cfc044cbea7f8d1b11876d324616e781f5e20ee14fce1ca360ece1b880e9094bc33b90a1073e00f1d262e7451cf65deab49f1c4ad59bf6ed2e70f3c8900025bfd608cec18acd129c9f1300563d500000008b5b65d1b9b35077371e686f51bef8f08e23a9292381278e801e8a76974459e7be7596f95c70272d7e9b3c21cb6624c90b2a0994fe799e5ceb4f6042ab5bfeb4ea2f963eb971d4b46c8289235107d008761311201b1184047b93748f3b3cf108190507fabc0c26c6a4442dd648ad68b881b81bce3b0ec07026cb91578b5565af055c84b9cf8b81035437449fa58401b78992f2ed66d16abf72bd2923be2967415c8e1f1d98a06e211f33e6541713ce719374dbb0c89c13129811399a5549257c08cc6bc919cf97425a871db261d56372fe6c021e00cd9885f9593b41aa4770782695e4dc85ad910c727884a59e60eb50d943a765d218aec937bd154d59ea0af72350dd059187cb0c54d41d86603708efc3e116eec507b20240f3c134f76a4419d8f9575ffd9f3dbbab719c31676c99c5c648941ecd145f445b6dc9d77efd5e43a4c582726f1e4919ded664b9f150ded578ac71581293afe31c2904c91c480e049a82d8413274082908323b638103fa030f9f14a86833b0a2d308e321c097f65b2a30f5d6d92b237a98af6e0a157965cb3cd3aa89e9c1432bb40e4fdd3174d7f6a4703b363105e32c1b9bc4e411ffeedbcb1ec22c192db51d0ee278e619b0ca4f19ef835dcb9daa7d33f918e56604bea41f92601696d19b4ccfbe038358c969816b0926dc349178cfd8f196c4678ebb7f0b121e503f7cc7d74ebf3ff25ec3e6f8609cbd2dbb888e537dbcd785a82f866e6ade6f1839fcd6f574b96693b9c45a524cf6a826180922d7c0419a9de0e418ff5194479bdcaa49f1953bb5beb2bb5b79bb7edaad56b3a3416a3f8a29159b6932b3acb3f9f6ca8720e3c2f12c9e6228030152ee98b5950c25670660c4d5f1cd6c8a6726294cd95dd3fb3fc10c2d38f5d417f8a786ead37157511d014cedfefa21d3eab8f8db3d56280cb6192146223bbfd97e829857f64047237a0358f989e6d8fa1419139596db7dc24a3cbe3c00860ddcaa5f614a72e7113cc35f75dbda63762a3b9b77de5fe2cb1d7ec5fe166a716ab99be599f1d42041ac42923f4c7520196f477eefedc01f689414d241f212d011c075c7c8c2cfa25fda96342aaaee53eacc781d3442582ec0f7ef8db40eaa34de64044a36a91a8f571fab7866f3c2225dc4299153387acdf22564bcbdc0920a179928ceb47be9ce26e252fa14061336edb63a1b71500eadcd1149cf206c8f52a56be13e79fc17897ebd0ff7f36a1088cfb94753636c5e38202b01d2c20bb8ffa62eff02310e99a36d6feb46c60f5f017746bf3304b00f78849671e573731555ef29943d54df760a157bc4eefa53010b1709e52b526575993d3fd2f2c34da455818c25261e3761bbf7a9e49e7cf295fd5a08717539f4d4c71b68bdc109bea6aa49641724358d75bf8bb748ae9dfbc51ab0aa62b15a7df371e7de0e5dc4c8f4c79fd0515810bfc00a0c1551fc932de558a321b145ff75cb6d06862bad57994d83c690a0e4befe0fa3d217521a78f9b6b723f3362980d93847b027d352ff86b85f29161d99d5b6d3cbf711b3032f2197718ff4d31731c0b155fedb26cc92bd907ddef000000088ca642d82497289e2fb62ddfe93db2e7a3e5db534fea0cc1b52eb21166d3179e6a75b470001d3570265b92d0f2bb25088bd2e08de60d803b608054553ad3cd62a452515860e31a5a29730c734abaef2c80841b1a576485ad1b027b40c6ddfe7ea47e2282ce3d543500d468eb3805372c83ddbd81a1dfdc985cda10f3582da31192f54bbeeb7bc49bded5de831e0c5c6bb3b8eea3f69d3d3aa0d632afcc066ff78c0b9a4728aa4588b64d43cdb41459a58198186f4983da37928997989fb5220f8657d93b28f48a4f9fa3fcde7439cf8cd1b687bb42b83f4e3448f33fec7ad56645617f341a0b03441ab8a5d9203740bcb93175dd4073794c94f15d4447b5d4915c0cfa6b8c7b303d43266cd66dd79041193a078dcc7020dd28ca68cc53209b3f97562a9700ad6259e23edb7482aa209e6a7136045a169579fdce65e2e5e9c52c1f2989c711ce34f8d375d9ac6976f213a9bd4fc7140c43a1c71dd2503b3aa5ba566a1576df440993aef8ac80caf02c34d55f82036f71bc34c35062ced5c4d0128c446b2d1985f7fa96b9aa2fd5499a369b8eb1c761f889f6655744b18fb14e71feec5ec22123943c1c398ab7f2722e35aa11810a8c09e7f3d20b914a0ef7c30dcd36fd379c284a7d6fbe40956a26167043d5609b2d8761aa5cfe0c29cdeb0b37ad0c393f930052208ea41021792b3527687c82fe7b0de2f5194658d266a12ceca5a9ffc9ba739ab2d50f1ec3822d2b5c91e06388b6735f3504fb358450c000183503491d2ec7c726c416afd9672e8849b261c57e80ef15b5f185767782e560ab80b4f06a0acf3dfd98b3225f2242cf5229f984fd2dd6b169f627fcf3486b634c585c82d9b74edba9e6216bee6f903c4c84c2ac49ae07bacadf043f6bf2e337e70dc412b2b2821609ac547f94ea698d488fd8ea4b61c1d3b6f764d1782cfa6581936a13fcf7867aac99ae6a0b880816f1088ae847d6696a2b775fad9613a91e111f4a2974c0ead6584c182ab9eb057812811d8e04319b4a899f22be73f925bc2d9360d6fa064a57e636181b7bed92a6d6fdec63f1785209f355dd7e4fe986b1767197c7a2a47a2265d4564946e225fcb5325ace7d0226dcc4e928cefdd61b1aea4a546ea69e830cbd5df7c5e297461996889efdca35447491afe3e7b926dce126ad1a5db82e5833a2f93d235495b6ca9e7ce20b05d2e0a975520df960d312f8cacf8e854f5b97dcc3584cf038b79c3e53afc871d0d13cc2ca0ce2b3f3b7effac5b42ade561ee0391107bbeb2ab5305c659a14023a0eb4e07566fc858a9b5d719a86602ca129a3c0f97457679a6adc6a3a8991eb1e6aea126653592da1a7aa81294b12b71df3d8e5eb800a126fc92e4555981c49de1923d864d57469696fad73652b1007541ff4a55453518f0118f0fcf7976c20df2d96ef2892b3638b5a30f349581794dc46da427c6da1d21dfda1d2fe8f6c3f197086d01715749b5c0309bc0c2f96dad1e5961e27ec22545c6794f81379b38c998b4a644844cc4cee00b7531242313e71c219ea8c48910ca736b7990a3cb29e8a6b493d90a1c23e4be0455217000000088ee32b80860b9b1905ba2e4c10c8c6ac3fdd440423dd5d045e9c9de07352d03812b87415703e125dd70958464b00988788f1e408ae94cc512b0cc612cd83570476fce18db52a5e3f937e14c62d9f0dfc3e03e5e927ccd6b73de86290d44374fca84ca7dbbd524d6c5b6aa3d675a4d067e1a993a99ecb204715989ea5d4069b4ec9fef13529e4278fe158378339aec4fa8febffc1b87cae5bf6f1bea7546303b191fb8a14267dd9f0e3b2fe2672f94b17fef18a4316074fcb81a459d0ca97ef28a22adac4ed1604e6a413b4503c70ba4111735797f16694396c4762a8dcb1bc0a8026e81cc24c5da13e3dc7b365e0055e99841773189f7e5c9ae85863fbf31cda7a841bed0ffcec8507dd6726e00d7ecbff63fd418e1a31a778e8164f8d4cff1987f588bcbcb4e6be79ccec4c2bd0ca5f4ff691d24837adef9e7958c015140acd65100e85ce38439b42f6fae09fa35ce28f3e8e60a65375bba2e9fa94c6dbb7d7fcab18c0901f4c8863c360fcdf265ecdb2c800de8760a975a0d2c28a2cac18b0a70b0a4041cad09c423d28493d63da360fa84b12daa097ee286c3b2efc47431b5ea1b8b1b3cad174d92c1492c7aab9e7afad1e4681064b54fcdc3b8f9f5206fe986d0ba5c7e7495c77205c7a49d1b951a922440878aacce7eed2ca651a5c6c60a81167df6421064e6f9e04f8fedbd771b49a2a93b6e09ff00e8a888fca6d0dcb0a0bf80177c680a675e775b8638dac17aac370164febcc5efa2adc669664d1f21b918974e41474486070578e8cedca0a180b8dc4e6a73f30b0459d7c3983e05ba7232c878c473cac508fed476b8ccbc9d1ed0d00ae316f4633289a016b16176cd8701416eb44456bce39ba53a1d7d70da9b094742b65e8fbbe256f930323c6078d84a59f50cf49d11ed94e1f15fa234e3009b4383c165b322ac4842c47c9f1cb90170b2aaf157ef06a1df723a5422b280127cfffd83befb26f043377c0fac98cd0673663b247a7fb8fb053a18e905c4bb77d0c5a00d20c4a8f163e996bde25672d3029000838072925641556d6c1631c8c2f91608d9deb7de468952bf320c36e0c15ffc1d6968e935e21b697214dab67254642b5c3ab532295f264ea18aa4fa556b92669bc32555c4695d36207d7d6d1d385cb08eaea3524afbbbd60372d4328",
          "pubInfoForIp": "8d926ce6c3edee7fd4123634fda856849e811d9453cdde4532a1ffb259901640cffba52cb8129b908f35ce300e35e7e0831e9f1d151379af8d4c951764dfbe89f0537024dac87f046241ca199e61273199212fe6957b7a004e112ee63e1893290300eb00dc61943a40e666e1c515f2f0ae4d35a1429924a274e01931f638fb2f9df20084e9f28def7548f85f8862fa2b084dee105ae15c654c1bb435b5d8c865247703000c154c5b699071fc451e57f1dd6dbee7accadc6207080a67c842db0fe06b236002"
        },
        "signature": "ae74a329e549c69dace39d1d34140a7c5bb1706c25ced865858d72791ad13f8d6e947f0bfc0b9ae61e888f46e36f0c1fa732cc8d6a8ac23b908db62342022d33f4b5313b3cbf3df6939c8c621b225fbdb9ec2bb5b561b793da45845ab058b4ae"
      }
    }
  },
  "detail": "",
  "status": "done"
}
```

If no error has been encountered, but the identity object is not ready yet due to the identity verification
process, then an expected response would look like:
```
{
    "status": "pending",
    "detail": ""
}
```

To signal that an error occurred, i.e. if queried for an identity object that does not exist, and is not currently
being processed, then an error can be returned:
```
{
    "status": "error",
    "detail": "Identity object does not exist"
}
```
