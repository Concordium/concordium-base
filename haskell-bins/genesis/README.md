# Genesis block tool

The genesis tool is used to create initial genesis blocks to start nodes with,
as well as to print contents of genesis blocks in a human readable way.

## Generating new genesis

The general invocation of the tool to create a genesis block is the following

```console
$ genesis make-genesis\
          --identity-providers=identity-providers.json
          --anonymity-revokers=anonymity_revokers.json
          --crypto-params=global.json
          --accounts=initial-accounts.json
          --update-authorizations=authorizations.json
          --gdver=3
          genesis.json
          genesis.dat
```
where all files except `genesis.dat` are input files, and `genesis.dat` is the
output file which can be used to start a node.
The tool outputs an additional file `genesis_hash`, in the same directory as the
`genesis.dat` file. This contains the hash of the produced genesis block. This
is useful for running a bootstrap node.

The `genesis.json` file contains chain parameters, an example file is
```json
{
    "v": 2,
    "value": {
        "genesisTime": 1623218400000,
        "slotDuration": 250,
        "leadershipElectionNonce": "60ab0feb036f5e3646f957085238f02fea83df5993db8e784e11500969af9420",
        "epochLength": 14400,
        "maxBlockEnergy": 3000000,
        "finalizationParameters": {
            "minimumSkip": 0,
            "committeeMaxSize": 1000,
            "waitingTime": 100,
            "skipShrinkFactor": 0.5,
            "skipGrowFactor": 2,
            "delayShrinkFactor": 0.5,
            "delayGrowFactor": 2,
            "allowZeroDelay": true
        },
        "chainParameters": {
            "electionDifficulty": 0.025,
            "euroPerEnergy": 0.00002,
            "microGTUPerEuro": 500000,
            "bakerCooldownEpochs": 166,
            "accountCreationLimit": 10,
            "foundationAccount": "4LH62AZmugKXFA2xXZhpoNbt2fFhAn8182kdHgxCu8cyiZGo2c",
            "minimumThresholdForBaking": "2500000000",
            "rewardParameters": {
                "mintDistribution": {
                    "mintPerSlot": 0.0000000007555665,
                    "bakingReward": 0.85,
                    "finalizationReward": 0.05
                },
                "transactionFeeDistribution": {
                    "baker": 0.45,
                    "gasAccount": 0.45
                },
                "gASRewards": {
                    "baker": 0.25,
                    "finalizationProof": 0.005,
                    "accountCreation": 0.02,
                    "chainUpdate": 0.005
                }
            }
        }
    }
}
```
This file must be created manually and tailored to specific needs of the network.

The remaining files may be created with other tools.

The `identity-providers.json`, `anonymity_revokers.json` and `global.json` may
be generated using the [id-client](../../rust-bins/src/bin/client.rs) tool.
Alternatively, identity providers and anonymity revokers may be created using
the [keygen tool](../../rust-bins/src/bin/keygen.rs) and then combined manually.

After these files are available `initial-accounts.json` may be generated using
another [genesis-tool](../../rust-bins/src/bin/genesis_tool.rs).

The update authorizations contain public keys for performing chain updates. For
testing purposes they may be generated using the
[generate-update-keys](../generate-update-keys/Main.hs) tool.

### Supported protocol versions

- If `--gdver=3` then the tool will output initial genesis for protocol version 1.
  (This is the default if no version is specified.)
- If `--gdver=4` then the tool will output initial genesis for protocol version 2.
- If `--gdver=5` then the tool will output initial genesis for protocol version 3.
- If `--gdver=6` then the tool will output initial genesis for protocol version 4.

## Printing contents of genesis blocks

```console
genesis print-genesis genesis.dat
```

will display, in human readable form, the contents of `genesis.dat`.
