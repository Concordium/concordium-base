// #![no_std]
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod derive;
mod smart_contract;

/// A helper to report meaningful compilation errors
/// - If applied to an Ok value they simply return the underlying value.
/// - If applied to `Err(e)` then `e` is turned into a compiler error.
fn unwrap_or_report(v: syn::Result<TokenStream>) -> TokenStream {
    match v {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive the Deserial trait. See the documentation of
/// [`derive(Serial)`](./derive.Serial.html) for details and limitations.
///
/// In addition to the attributes supported by
/// [`derive(Serial)`](./derive.Serial.html), this derivation macro supports the
/// `ensure_ordered` attribute. If applied to a field the of type `BTreeMap` or
/// `BTreeSet` deserialization will additionally ensure that the keys are in
/// strictly increasing order. By default deserialization only ensures
/// uniqueness.
///
/// # Example
/// ``` ignore
/// #[derive(Deserial)]
/// struct Foo {
///     #[concordium(size_length = 1, ensure_ordered)]
///     bar: BTreeSet<u8>,
/// }
/// ```
#[proc_macro_derive(Deserial, attributes(concordium))]
pub fn deserial_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input);
    unwrap_or_report(derive::impl_deserial(&ast))
}

/// Derive the Serial trait for the type.
///
/// If the type is a struct all fields must implement the Serial trait. If the
/// type is an enum then all fields of each of the enums must implement the
/// Serial trait.
///
///
/// Collections (Vec, BTreeMap, BTreeSet) and strings (String, str) are by
/// default serialized by prepending the number of elements as 4 bytes
/// little-endian. If this is too much or too little, fields of the above types
/// can be annotated with `size_length`.
///
/// The value of this field is the number of bytes that will be used for
/// encoding the number of elements. Supported values are 1, 2, 4, 8.
///
/// For BTreeMap and BTreeSet the serialize method will serialize values in
/// increasing order of keys.
///
/// Fields of structs are serialized in the order they appear in the code.
///
/// Enums can have no more than 65536 variants. They are serialized by using a
/// tag to indicate the variant, enumerating them in the order they are written
/// in source code. If the number of variants is less than or equal 256 then a
/// single byte is used to encode it. Otherwise two bytes are used for the tag,
/// encoded in little endian.
///
/// # Example
/// ```ignore
/// #[derive(Serial)]
/// struct Foo {
///     #[concordium(size_length = 1)]
///     bar: BTreeSet<u8>,
/// }
/// ```
#[proc_macro_derive(Serial, attributes(concordium))]
pub fn serial_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input);
    unwrap_or_report(derive::impl_serial(&ast))
}

/// A helper macro to derive both the Serial and Deserial traits.
/// `[derive(Serialize)]` is equivalent to `[derive(Serial, Deserial)]`, see
/// documentation of the latter two for details and options:
/// [`derive(Serial)`](./derive.Serial.html),
/// [`derive(Deserial)`](./derive.Deserial.html).
#[proc_macro_derive(Serialize, attributes(concordium))]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    unwrap_or_report(serialize_derive_worker(input))
}

fn serialize_derive_worker(input: TokenStream) -> syn::Result<TokenStream> {
    let ast = syn::parse(input)?;
    let mut tokens = derive::impl_deserial(&ast)?;
    tokens.extend(derive::impl_serial(&ast)?);
    Ok(tokens)
}

/// Derive the DeserialWithState trait. See the documentation of
/// [`derive(Deserial)`](./derive.Deserial.html) for details and limitations.
///
/// This trait should be derived for `struct`s or `enum`s that have fields with
/// [`StateBox`](../concordium_std/struct.StateBox.html),
/// [`StateSet`](../concordium_std/struct.StateSet.html), or
/// [`StateMap`](../concordium_std/struct.StateMap.html). Please note that it is
/// necessary to specify the generic parameter name for the
/// [`HasStateApi`](../concordium_std/trait.HasStateApi.html) generic parameter.
/// To do so, use the `#[concordium(state_parameter =
/// "NameOfGenericParameter")]` attribute on the type you are deriving
/// `DeserialWithState` for.
///
/// # Example
/// ``` ignore
/// #[derive(DeserialWithState)]
/// #[concordium(state_parameter = "S")]
/// struct Foo<S, T> {
///     a: StateMap<u8, u8, S>,
///     #[concordium(size_length = 1)]
///     b: String,
///     c: Vec<T>,
/// }
/// ```
#[proc_macro_derive(DeserialWithState, attributes(concordium))]
pub fn deserial_with_state_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input);
    unwrap_or_report(derive::impl_deserial_with_state(&ast))
}

/// Derive the `SchemaType` trait for a type.
/// If the feature `build-schema` is not enabled this is a no-op, i.e., it does
/// not produce any code.
#[proc_macro_derive(SchemaType, attributes(concordium))]
pub fn schema_type_derive(input: TokenStream) -> TokenStream {
    unwrap_or_report(derive::schema_type_derive_worker(input))
}

/// Derive the conversion of enums that represent error types into the Reject
/// struct which can be used as the error type of init and receive functions.
/// Creating custom enums for error types can provide meaningful error messages
/// to the user of the smart contract.
///
/// When a contract function rejects, the enum is serialized and returned along
/// with the error code. The serialization means that the enum *must* implement
/// [`Serial`](../concordium_contracts_common/trait.Serial.html) if [`Reject`]
/// is to be derived.
///
/// The conversion will map the first variant to error code -1, second to -2,
/// etc.
///
/// ### Example
/// ```ignore
/// #[derive(Reject, Serial)]
/// enum MyError {
///     IllegalState, // receives error code -1
///     WrongSender, // receives error code -2
///     TimeExpired(time: Timestamp), // receives error code -3
///     ...
/// }
/// ```
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive")]
/// fn receive<A: HasActions>(ctx: &impl HasReceiveContext, state: &mut MyState)
/// -> Result<A, MyError> {...}
/// ```
#[proc_macro_derive(Reject, attributes(from))]
pub fn reject_derive(input: TokenStream) -> TokenStream {
    unwrap_or_report(derive::reject_derive_worker(input))
}

/// Derive the Deletable trait.
/// See the documentation of
/// [`derive(Deletable)`](./derive.Deletable.html) for details and limitations.
///
/// The trait should be derived for types which have not implemented the
/// `Serialize` trait. That is, Deletable should be derived for types with a
/// non-trivial state.
/// Non-trivial state here means when you have a type `MyState` which has one or
/// more fields comprised of
/// [`StateBox`](../concordium_std/struct.StateBox.html),
/// [`StateSet`](../concordium_std/struct.StateSet.html), or
/// [`StateMap`](../concordium_std/struct.StateMap.html).
///
/// Please note that it is
/// necessary to specify the generic parameter name for the
/// [`HasStateApi`](../concordium_std/trait.HasStateApi.html) generic parameter.
/// To do so, use the `#[concordium(state_parameter =
/// "NameOfGenericParameter")]` attribute on the type you are deriving
/// `Deletable` for.
///
/// # Example
/// ``` ignore
/// #[derive(Serial, DeserialWithState, Deletable)]
/// #[concordium(state_parameter = "S")]
/// struct MyState<S> {
///    my_state_map: StateMap<SomeType, SomeOtherType, S>,
/// }
/// ```
#[proc_macro_derive(Deletable, attributes(concordium))]
pub fn deletable_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input);
    unwrap_or_report(derive::impl_deletable(&ast))
}

/// Derive the StateClone trait.
/// See the documentation of
/// [`derive(StateClone)`](./derive.StateClone.html) for details and
/// limitations.
///
/// The trait is used in the
/// [`TestHost`](../concordium_std/test_infrastructure/struct.TestHost.html)
/// when rolling back the state. If that functionality is needed, then this
/// trait must be derived for types which have not implement the `Clone` trait.
/// That is, `StateClone` should be derived for types with a non-trivial state.
/// Non-trivial state here means when you have a type `MyState` which has one or
/// more fields comprised of
/// [`StateBox`](../concordium_std/struct.StateBox.html),
/// [`StateSet`](../concordium_std/struct.StateSet.html), or
/// [`StateMap`](../concordium_std/struct.StateMap.html).
///
/// Please note that it is
/// necessary to specify the generic parameter name for the
/// [`HasStateApi`](../concordium_std/trait.HasStateApi.html) generic parameter.
/// To do so, use the `#[concordium(state_parameter =
/// "NameOfGenericParameter")]` attribute on the type you are deriving
/// `StateClone` for.
///
/// # Example
/// ``` ignore
/// #[derive(Serial, DeserialWithState, StateClone)]
/// #[concordium(state_parameter = "S")]
/// struct MyState<S> {
///    my_state_map: StateMap<SomeType, SomeOtherType, S>,
/// }
/// ```
#[proc_macro_derive(StateClone, attributes(concordium))]
pub fn state_clone_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input);
    unwrap_or_report(derive::impl_state_clone(&ast))
}

/// Derive the appropriate export for an annotated init function.
///
/// This macro requires the following items to be present
/// - `contract="<name>"` where *\<name\>* is the name of the smart contract and
///   the generated function is exported as this name prefixed with *init_*. The
///   name should be unique in the module, as a contract can only have one
///   init-function.
///
/// The annotated function must be of a specific type, which depends on the
/// enabled attributes. *Without* any of the optional attributes the function
/// must have a signature of
///
/// ```ignore
/// #[init(contract = "my_contract")]
/// fn some_init<S: HasStateApi>(ctx: &impl HasInitContext, state_builder: &mut StateBuilder<S>,) -> InitResult<MyState> {...}
/// ```
///
/// Where `HasInitContext`, `InitResult`, and `StateBuilder` are exposed from
/// `concordium-std` and `MyState` is a user-defined type.
///
/// # Optional attributes
///
/// ## `payable`: Make function accept an amount of CCD
/// Without setting the `payable` attribute, the generated function will reject
/// any non-zero amount of CCD supplied with the transaction. This means we are
/// required to explicitly mark our functions as `payable`, if they are to
/// accept CCD.
///
/// Setting the `payable` attribute changes the required signature to include an
/// extra argument of type `Amount`, allowing the function to access the amount
/// of CCD supplied with the transaction.
///
/// ### Example
/// ```ignore
/// #[init(contract = "my_contract", payable)]
/// fn some_init<S: HasStateApi>(ctx: &impl HasInitContext, state_builder: StateBuilder<S>, amount: Amount) -> InitResult<MyState> {...}
/// ```
///
/// ## `enable_logger`: Function can access event logging
/// Setting the `enable_logger` attribute changes the required signature to
/// include an extra argument `&mut impl HasLogger`, allowing the function to
/// log events.
///
///
/// ### Example
/// ```ignore
/// #[init(contract = "my_contract", enable_logger)]
/// fn some_init<S: HasStateApi>(ctx: &impl HasInitContext, state_builder: StateBuilder<S>, logger: &mut impl HasLogger) -> InitResult<MyState> {...}
/// ```
///
/// ## `low_level`: Manually deal with the low-level state.
/// Setting the `low_level` attribute disables the generated code for
/// serializing the contract state.
///
/// If `low_level` is set, the `&mut StateBuilder<S>` in the signature is
/// replaced by `&impl mut HasStateApi` found in `concordium-std`, which gives
/// access to manipulating the low-level contract state directly. This means
/// there is no need to return the contract state and the return type becomes
/// `InitResult<()>`.
///
/// ### Example
/// ```ignore
/// #[init(contract = "my_contract", low_level)]
/// fn some_init(ctx: &impl HasInitContext, state: &mut impl HasStateApi) -> InitResult<()> {...}
/// ```
///
/// ## `parameter="<Param>"`: Generate schema for parameter
/// To make schema generation include the parameter for this function, add
/// the attribute `parameter` and set it equal to a string literal containing
/// the name of the type used for the parameter. The parameter type must
/// implement the SchemaType trait, which for most cases can be derived
/// automatically.
///
/// ### Example
/// ```ignore
/// #[derive(SchemaType)]
/// struct MyParam { ... }
///
/// #[init(contract = "my_contract", parameter = "MyParam")]
/// ```
///
/// ## `error="<Error>"`: Generate schema for error
/// To make schema generation include the error for this function, add
/// the attribute `error` and set it equal to a string literal containing
/// the name of the type used for the error. The error type must
/// implement the SchemaType trait, which for most cases can be derived
/// automatically.
///
/// ### Example
/// ```ignore
/// #[derive(SchemaType)]
/// enum MyError { ... }
///
/// #[init(contract = "my_contract", parameter = "MyError")]
/// fn some_init(ctx: &impl HasInitContext, state: &mut impl HasStateApi) -> Result<(), MyError> {...}
/// ```
///
/// ## `crypto_primitives`: Function can access cryptographic primitives
/// Setting the `crypto_primitives` attribute changes the required signature to
/// include an extra argument `&impl HasCryptoPrimitives`, which provides
/// cryptographic primitives such as verifying signatures and hashing data.
///
/// ### Example
/// ```ignore
/// #[init(contract = "my_contract", crypto_primitives)]
/// fn some_init<S: HasStateApi>(
///     ctx: &impl HasInitContext,
///     state_build: StateBuilder<S>,
///     crypto_primitives: &impl HasCryptoPrimitives,
/// ) -> InitResult<MyState> {...}
/// ```
#[proc_macro_attribute]
pub fn init(attr: TokenStream, item: TokenStream) -> TokenStream {
    unwrap_or_report(smart_contract::init_worker(attr, item))
}

/// Derive the appropriate export for an annotated receive function.
///
/// This macro requires the following items to be present
/// - `contract = "<contract-name>"` where *\<contract-name\>* is the name of
///   the smart contract.
/// - `name = "<receive-name>"` where *\<receive-name\>* is the name of the
///   receive function, **or** the `fallback` option. The generated function is
///   exported as `<contract-name>.<receive-name>`, or if `fallback` is given,
///   as `<contract-name>.`.Contract name and receive name is required to be
///   unique in the module. In particular, a contract may have only a single
///   fallback method.
///
/// The annotated function must be of a specific type, which depends on the
/// enabled attributes. *Without* any of the optional attributes the function
/// must have a signature of
///
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive")]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &HasHost<MyState, StateApiType = S>
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// Where the `HasStateApi`, `HasReceiveContext`, `HasHost`, and `ReceiveResult`
/// are from `concordium-std` and `MyState` and `MyReturnValue` are user-defined
/// types.
///
/// # Optional attributes
///
/// ## `payable`: Make function accept an amount of CCD
/// Without setting the `payable` attribute, the function will reject any
/// non-zero amount of CCD, supplied with the transaction. This means we are
/// required to explicitly mark our functions as `payable`, if they are to
/// accept CCD.
///
/// Setting the `payable` attribute changes the required signature to include an
/// extra argument of type `Amount`, allowing the function to access the amount
/// of CCD supplied with the transaction.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive", payable)]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &HasHost<MyState, StateApiType = S>,
///     amount: Amount
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// ## `mutable`: Function can mutate the state
/// Setting the `mutable` attribute changes the required signature so the host
/// becomes a mutable reference.
///
/// **When a receive method is mutable, the state, e.g. `MyState`, is serialized
/// and stored after each invocation. This means that even if the state does
/// not change semantically, it will be considered as modified by callers.**
/// Thus the `mutable` option should only be used when absolutely necessary.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive", mutable)]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &mut HasHost<MyState, StateApiType = S>
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// ## `enable_logger`: Function can access event logging
/// Setting the `enable_logger` attribute changes the required signature to
/// include an extra argument `&mut impl HasLogger`, allowing the function to
/// log events.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive", enable_logger)]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &HasHost<MyState, StateApiType = S>,
///     logger: &mut impl HasLogger
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// ## `low_level`: Manually deal with the low-level state including writing
/// bytes Setting the `low_level` attribute disables the generated code for
/// serializing the contract state. However, the return value is still
/// serialized automatically.
///
/// If `low_level` is set, the `&mut StateBuilder<S>` in the signature is
/// replaced by `&impl mut HasStateApi` found in `concordium-std`, which gives
/// access to manipulating the low-level contract state directly.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive", low_level)]
/// fn contract_receive(
///     ctx: &impl HasReceiveContext,
///     state: &mut impl HasStateApi
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// ## `parameter="<Param>"`: Generate schema for parameter
/// To make schema generation include the parameter for this function, add
/// the attribute `parameter` and set it equal to a string literal containing
/// the type used for the parameter. The parameter type must
/// implement the SchemaType trait, which for most cases can be derived
/// automatically.
///
/// ### Example
/// ```ignore
/// #[derive(SchemaType)]
/// struct MyParam { ... }
///
/// #[receive(contract = "my_contract", name = "some_receive", parameter = "MyParam")]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &HasHost<MyState, StateApiType = S>,
/// ) -> ReceiveResult<A> {...}
/// ```
///
/// ## `return_value="<ReturnValue>"`: Generate schema for the return value.
/// To make schema generation include the return value for this function, add
/// the attribute `return_value` and set it equal to a string literal containing
/// the type used for the parameter. The parameter type must
/// implement the SchemaType trait, which for most cases can be derived
/// automatically.
///
/// ### Example
///
/// ```ignore
/// #[derive(SchemaType)]
/// struct MyReturnValue { ... }
///
/// #[receive(contract = "my_contract", name = "some_receive", return_value = "MyReturnValue")]
/// fn contract_receive<S: HasStateApi>(
///    ctx: &impl HasReceiveContext,
///    host: &HasHost<MyState, StateApiType = S>,
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
///
/// ## `error="<Error>"`: Generate schema for error
/// To make schema generation include the error for this function, add
/// the attribute `error` and set it equal to a string literal containing
/// the type used for the error. The error type must
/// implement the SchemaType trait, which for most cases can be derived
/// automatically.
///
/// ### Example
/// ```ignore
/// #[derive(SchemaType)]
/// enum MyError { ... }
///
/// #[receive(contract = "my_contract", name = "some_receive", error = "MyError")]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &HasHost<MyState, StateApiType = S>,
/// ) -> Result<A, MyError> {...}
/// ```
///
/// ## `fallback`: Create a fallback entrypoint.
/// A contract can have a *single* fallback entrypoint defined.
/// If defined, invocations on missing entrypoint will be redirected to the
/// fallback entrypoint. For fallback entrypoints, the `name` attribute is not
/// allowed. This is because fallback entrypoints always have the empty string
/// as their name.
///
/// To get the name of the entrypoint used for invocation, use
/// `ctx.named_entrypoint()`. The method is available in all receive methods,
/// but is only useful on fallback entrypoints.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", fallback)]
/// fn contract_receive<S: HasStateApi>(
///    ctx: &impl HasReceiveContext,
///    host: &HasHost<MyState, StateApiType = S>,
/// ) -> ReceiveResult<MyReturnValue> {
///     let named_entrypoint = ctx.named_entrypoint();
///     // ...
/// }
/// ```
/// ## `crypto_primitives`: Function can access cryptographic primitives
/// Setting the `crypto_primitives` attribute changes the required signature to
/// include an extra argument `&impl HasCryptoPrimitives`, which provides
/// cryptographic primitives such as verifying signatures and hashing data.
///
/// ### Example
/// ```ignore
/// #[receive(contract = "my_contract", name = "some_receive", crypto_primitives)]
/// fn some_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &impl HasHost<MyState, StateApiType = S>,
///     crypto_primitives: &impl HasCryptoPrimitives,
/// ) -> ReceiveResult<MyReturnValue> {...}
/// ```
#[proc_macro_attribute]
pub fn receive(attr: TokenStream, item: TokenStream) -> TokenStream {
    unwrap_or_report(smart_contract::receive_worker(attr, item))
}

#[proc_macro_attribute]
/// Derive the appropriate export for an annotated test function, when feature
/// "wasm-test" is enabled, otherwise behaves like `#[test]`.
pub fn concordium_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    unwrap_or_report(smart_contract::concordium_test_worker(attr, item))
}

/// Sets the cfg for testing targeting either Wasm and native.
#[cfg(feature = "wasm-test")]
#[proc_macro_attribute]
pub fn concordium_cfg_test(_attr: TokenStream, item: TokenStream) -> TokenStream { item }

/// Sets the cfg for testing targeting either Wasm and native.
#[cfg(not(feature = "wasm-test"))]
#[proc_macro_attribute]
pub fn concordium_cfg_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = proc_macro2::TokenStream::from(item);
    let out = quote! {
        #[cfg(test)]
        #item
    };
    out.into()
}

/// If `wasm-test` feature of `concordium-std` is enabled ignore the item,
/// this usually happens when executing tests with `cargo-concordium` utility.
/// Otherwise this is equivalent to `#[cfg(not(test))]`. Use as a dual to
/// `#[concordium_cfg_test]`.
#[cfg(feature = "wasm-test")]
#[proc_macro_attribute]
pub fn concordium_cfg_not_test(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// If `wasm-test` feature of `concordium-std` is enabled ignore the item,
/// this usually happens when executing tests with `cargo-concordium` utility.
/// Otherwise this is equivalent to `#[cfg(not(test))]`. Use as a dual to
/// `#[concordium_cfg_test]`.
#[cfg(not(feature = "wasm-test"))]
#[proc_macro_attribute]
pub fn concordium_cfg_not_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = proc_macro2::TokenStream::from(item);
    let out = quote! {
        #[cfg(not(test))]
        #item
    };
    out.into()
}

// Supported attributes for `concordium-quickcheck`

#[cfg(feature = "concordium-quickcheck")]
#[proc_macro_attribute]
/// Derive the appropriate export for an annotated QuickCheck function by
/// exposing it as `#[concordium_test]`. The macro is similar to `#[quickcheck]`
/// but uses a customized test runner
/// instead of the standard  `QuickCheck`'s `quickcheck`
///
/// The macro optionally takes a `num_tests` attribute that specifies how many
/// tests to run: `#[concordium_quickcheck(tests = 1000)]`. If no `tests` is
/// provided, 100 is used.
///
/// Note that the maximum number of tests is limited to 1_000_000.
//  QUICKCHECK_MAX_PASSED_TESTS defines the limit.
pub fn concordium_quickcheck(attr: TokenStream, input: TokenStream) -> TokenStream {
    use syn::{
        parse::{Parse, Parser},
        spanned::Spanned,
    };

    let input = proc_macro2::TokenStream::from(input);
    let span = input.span();
    syn::Item::parse
        .parse2(input)
        .and_then(|item| match item {
            syn::Item::Fn(mut item_fn) => {
                smart_contract::quickcheck::wrap_quickcheck_test(attr, &mut item_fn)
            }
            _ => Err(syn::Error::new(
                span,
                "#[concordium_quickcheck] can only be applied to functions.",
            )),
        })
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
