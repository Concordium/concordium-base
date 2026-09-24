# Token Update CDDL

`cis-7.cddl` describes the operations, events, and reject reasons related to the "Token Update" transaction. The `fixtures` folder
includes fixtures to validate the CDDL against.

## Validation

The cargo `cddl` tool is used for validation:

```bash
cargo install cddl
```

From the `cddl` directory, compile the schema and validate every fixture:

```bash
cddl compile-cddl --cddl cis-7.cddl

for fixture in fixtures/*.cbor; do
    echo "Validating $fixture"
    cddl validate --cddl cis-7.cddl --cbor "$fixture"
done
```
