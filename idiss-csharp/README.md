# Description

Here, a C# library `IdissLib` for identity issuance is provided. The library uses two C functions `validate_request_cs` and `create_identity_object_cs` 
that are exported by the Rust library `idiss` in `concordium-base`. 

The `IdissLib` library provides two wrappers around the imported C functions :
```csharp
public static string validate_request(VersionedGlobalContext global, VersionedIpInfo ip_info, VersionedArInfos ars_infos, IdObjectRequest request)
```
that given a global context, identity provider info, anonymity revoker info and a request either
- returns the address of the initial account, if the request is valid, or
- throws an exception, if the request is invalid or the input is malformed.

```csharp
public static IdentityCreation create_identity_object(VersionedIpInfo ip_info, AttributeList alist, IdObjectRequest request, UInt64 expiry, IpPrivateKeys ip_keys){
```
that given identity provider info, attribute list, request, expiry and the private keys of the identity provider either
- returns a `IdentityCreation` object containing 
    * the identity object that is returned to the user
    * the anonymity revocation record
    * the initial account creation object that is sent to the chain
    * the address of the inital account 
- throws an exception, if any of the inputs are malformed.

# Example

In `IdissExample`, there is an example that uses the testdata from the `data` folder and prints the output of the two functions above. 
If the identity creation is successful, it prints the JSON serialization of the returned `IdentityCreation` object.

To build, step inside the `IdissExample` directory and do
```
dotnet build
```

In order to run the example on Windows, do
1. Build the Rust library `idiss` from `concordium-base` with the command
  ```bash
  cargo build --release --features=csharp
  ```
  This produces a `idiss.dll` that will appear in the `target/release` directory. 
2. Move/copy the `idiss.dll` to `IdissExample/bin/Debug/net5.0`
3. Step inside the `IdissExample` directory and do
   ```bash
   dotnet run
   ```

# Testing

In `IdissLibTest`, there is a test that tests the functions `validate_request` and `create_identity_object`. 
To build the test, step inside the `IdissLib` directory and do
```
dotnet build
```

In order to run the test on Windows, do
1. The same `idiss.dll` that is needed for the running the example above
   is needed for running the test. If not already build, build the Rust library `idiss` from `concordium-base` with the command
  ```bash
  cargo build --release --features=csharp
  ```
  This produces a `idiss.dll` that will appear in the `target/release` directory. 
2. Move/copy the `idiss.dll` to `IdissLibTest/bin/Debug/net5.0`
3. Step inside the `IdissLibTest` directory and do
   ```bash
   dotnet test
   ```