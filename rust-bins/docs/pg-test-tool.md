# Privacy Guardian Testing Tool

The privacy guardian testing tool is used to test the functionality of privacy guardian decryption keys without doing an actual identity disclosure. The tool can be found in [../src/bin/pg_test_tool.rs](../src/bin/pg_test_tool.rs).

The `pg_test_tool` tool can

- generate a test record via subcommand `gen-enc`
- test the key using a test record `test-dec`

To see all the options use the `--help` option at different levels.

A test record is specific to a given privacy guardian and contains an encrypted message.

## Subcommand

The tool provides the following subcommands.

### gen-enc

Generate a test record for a specific privacy guardian. The following options are supported

- `-g, --global <global>` a filename, containing cryptographic parameters of the chain the privacy guardian is part of.
- `-p, --pg-pub <pg-pub>` a filename, containing the privacy guardian public key (encryption key).
- `-o, --out <out>` a filename, where the test record will be to output to.

By default, the tool will encrypt three BIP-39 words. The following options enable custom messages.

- `--use-custom-message` if set, encrypts the message provided by `--message`.
- ` --message <custom-message>` a pure ASCII string, excluding the null character (), which is at most `31` characters long.

### test-dec

Test the functionality of a privacy guardian decryption key by decrypting the message inside a test record. 

- `-g, --global <global>` a filename, containing cryptographic parameters of the chain the privacy guardian is part of.
- `-s, --pg-priv <pg-priv>` a filenname, containing the privacy guardian private and public keys.
- `-t, --test-rec <test-record>` a filename, containing the test record.

## Example

This section shows how to generate a test record and how to test the functionality of a privacy guardian key.

### Global Cryptographic Parameters

Both testing and test record generation require the cryptographic parameters of the chain the privacy guardian is part of. We assume that they are stored in a file `global.json`.

This file can be generated using (concordium-client)[https://github.com/Concordium/concordium-client] along the lines of

```console
concordium-client raw GetCryptographicParameters > global.json
```

For this example, we use the Concordium Mainnet parameters.

### Generating Test Record

Here, we generate a test record for the privacy guardian with index `123`. For this we need the public key `pg-info-123.pub.json` which has the following format.

```json
{
  "v": 0,
  "value": {
    "arIdentity": 123,
    "arDescription": {
      "name": "TestPG",
      "url": "example.com",
      "description": "example privacy guardian"
    },
    "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5acea92da06db110940eccd067ea8fa8058f3404b0437b07048f58c1dfdb48a74349a9aeeedd92ded065779aeec6dda92"
  }
}
```

Run

```console
pg_test_tool gen-enc -g global.json -p pg-info-123.pub.json -o pg-test-123.json
The encrypted message will be: dolphin swamp run
Record the message for test result verification.
Wrote test information to pg-test-123.json.
```

The test message is `dolphin swamp run` and the content of the test record `pg-test-123.json` will be

```json
{
  "v": 0,
  "value": {
    "pgIdentity": 123,
    "msgHash": "304f7b6a861ef6129735c64f9000803ad786854fcb7a1122bba3b2dfade35399",
    "msgEnc": [
      "b28f89d82626cf566e67bbe9ae1706da0341a203d6fa6c8795f972538419be173ec62e83011e8de51a04463a095977d6a11bc93648c42a41e9ca7c8f4d61a9e0eaddac6a213c0c5fb59e22f11c2871be0e5351f13c7eeb0e259f7be9ecde91aa",
      "b03d9a2dbb6a280dcb20adc33f0ed1362008c7635ffe106abc7b3da474fb2e37589a229bc9cdc2e269501b43fb09118eadc65188f3227e92f74befdeb55f02acf05cc4ccfe3582a576445b332c11ddeeabee569a26336b10ac3afb20b33d8f53",
      "a203ff3e7d5cf69b754d7ce2e724b62d1f48fbcc916120515fdfa14798d01a358f93cd36bb4e0aeb34aa8f05a3b137f3aaa94b19826bd86a31c58c1ca24ae0ca77bfcf1b138c388e9a51c73a542860320abee398c81ead16ac7a9268960e3945",
      "a4431c445a798e6fe8fa41e229825a75914b0ef102212bc924a4f1c58e2c4b42c61bb3274365251b755c4d43788ada898fabe4a2abe06cb3c7f6a99d840a694241caaa2a1bda8f295b1f047f6aa97a81f26039d67e4acadd3b92ae44eafa9a43",
      "a6e20f72724cdec72a70a811bb974b6f54a3814eb863435716295e0aa683b169a66a249e437a0f30ec10160f4087c7a1a09e68f0d529c2f0b89b022686231bb1e649b53702c4ac3e59e7e9b481a056bbdbd7149827ef729d06581ad241e1f6a6",
      "a39978d5ab251dda77a91a66e6756b4fab778897a7014ebe71ef4204974574fb7d44a0fc040d52b664dee88cbeadeb47a2f76996424b518b3fa31c746d1c5c987da3841fd6903d15b18def0ebd5dfe2d82a94007558b36669a4cece0c4d97e68",
      "b05d81e264304f9e6c1e762e19a4f83afa052fbbc77a98c2a421a1c37cdc9dab8ab23b2baf9d8a9ab16adcbd3a1f88f68bd322f030cd765090d7ff08a5ace5c282b7d497191e48ff229766c600c5999c04eb20d091d478fdcd6bb00a72ae3aec",
      "aefaed58590f5213170f9e55299567a6f1d61a3e45db97d9505b670fd8003727d973b5a23683ec24d8318c2289b9197781213c3883c7ab2aa1c664b7ad8ddb426eb847d6074324dd5680d72117630018bc5f16b4bd8ca692f99c63934b9e4590"
    ]
  }
}
```

### Testing

The test record `pg-test-123.json` from above is now used by privacy guardian `123` to test the functionality of their decryption key `pg-data-123.json`. Stored in encrypted form the file has the following format

```json
{
  "metadata": {
    "encryptionMethod": "AES-256",
    "keyDerivationMethod": "PBKDF2WithHmacSHA256",
    "iterations": 100000,
    "salt": "kjvWdPyHgJwrDdhXF7qZ8w==",
    "initializationVector": "ceIRwzn+ejnqUfxxA0oHhg=="
  },
  "cipherText": "nbSXO0ZxKWvRyBxGNbY8HCRXK7Zx2RejHssXGCa84fQvkkhcwHRoIghAESTve2AqjV6g/rRb74MeSd5eg7tzHoQTMYMA+cP1fydpEICjJ9vYCUGRkoNbhLLuPUR34+qyeNKzyJPGQndQTzvfQtZxWJwuEAlds3YclPhNHbcjJ2Zd3lOtiRAPc0wmvD/MetNKPWKvPLly2/kji261onqWyuaG5s9tSR3htapgl1a9gw5OxtLFDM0Jt1NLhnz3KzpwgNVwqv10+mgCMXoy5mhP9dIRdCFz/04Tq4VYwYEJ/A/e1gg9Y/A3D1074hlJ/gcLvOnJOQRa6YAXvsKZIDKQ3XagMgngcs/naxdMVrRDbyjmZor2AX9jgSAMoTWxkRPr7Rzl15r/pBa36aaotZkPuPdwJtW+1D2MXIl4lnK76IoX26qTh45bZan7te7UC4lEN2cxweYfwmoPui0Y5PJZaWJTlGonIg/Tu59Rx3FeWPulCzkImhKlQ1xIxfNb2so4jy6L3N7ty3ILLAoiiVewgXIPcg7mhDjEOeR8Qylb/EwljFIzcdlPJHJYe/3BCwJLydjPdAqhx/KKAoXlvKqX8ouCcB6a8CZsBepD3t5jMJ6lf9e+n2bQtXOOx6eY9x8plRrMyAtjZAYuEDa/pbB28fdHsxHCjmF+8mD3g2YcIAY="
}
```

Run

``` console
./pg_test_tool test-dec -g global.json -s pg-data-123.json -t pg-test-123.json 
Enter password to decrypt PG credentials: 
Test successful!
Please report back the following message: dolphin swamp run
```