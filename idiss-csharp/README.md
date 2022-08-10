# Description

Here, a C# library `IdissLib` for identity issuance is provided. The library uses five C functions `validate_request_cs`, `create_identity_object_cs`,
`validate_request_v1_cs`, `create_identity_object_v1_cs` and `validate_recovery_request_cs`
that are exported by the Rust library `idiss` in `concordium-base`. 

The `IdissLib` library provides two wrappers around the imported C functions :
```csharp
public static AccountAddress ValidateRequest(Versioned<GlobalContext> global, Versioned<IpInfo> ipInfo, Versioned<Dictionary<string, ArInfo>> arsInfos, IdObjectRequest request)
```
that given a global context, identity provider info, anonymity revoker info and a request either
- returns the address of the initial account, if the request is valid, or
- throws an exception, if the request is invalid or the input is malformed.

```csharp
public static IdentityCreation CreateIdentityObject(Versioned<IpInfo> ipInfo, AttributeList alist, IdObjectRequest request, UInt64 expiry, IpPrivateKeys ipKeys)
```
that given identity provider info, attribute list, request, expiry and the private keys of the identity provider either
- returns a `IdentityCreation` object containing 
    * the identity object that is returned to the user
    * the anonymity revocation record
    * the initial account creation object that is sent to the chain
    * the address of the inital account 
- throws an exception, if any of the inputs are malformed.

```csharp
public static void ValidateRequestV1(Versioned<GlobalContext> global, Versioned<IpInfo> ipInfo, Versioned<Dictionary<string, ArInfo>> arsInfos, IdObjectRequestV1 request)
```
that given a global context, identity provider info, anonymity revoker info and a request either
- does nothing, if the request is valid, or
- throws an exception, if the request is invalid or the input is malformed.

```csharp
public static IdentityCreationV1 CreateIdentityObjectV1(Versioned<IpInfo> ipInfo, AttributeList alist, IdObjectRequestV1 request, IpPrivateKeys ipKeys)
```
that given identity provider info, attribute list, request, and the private keys of the identity provider either
- returns an `IdentityCreationV1` object containing
    * the identity object that is returned to the user
    * the anonymity revocation record
- throws an exception, if any of the inputs are malformed.

```csharp
public static void ValidateRecoveryRequest(Versioned<GlobalContext> global, Versioned<IpInfo> ipInfo, IdRecoveryWrapper request, DateTimeOffset now)
```
that given a global context, identity provider info, an identity recovery request and the current time of the identity provider either
- does nothing, if the request is valid, or
- throws an exception, if the request is invalid or the input is malformed.

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
If building and running in Release mode (using the flag `--configuration Release`), the `ìdiss.dll` instead have to be placed at
`IdissExample/bin/Release/net5.0`.

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
If building and testing in Release mode (using the flag `--configuration Release`), the `ìdiss.dll` instead have to be placed at
`IdissLibTest/bin/Release/net5.0`.