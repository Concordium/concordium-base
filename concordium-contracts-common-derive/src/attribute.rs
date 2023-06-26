//! This module contains the main logic for the attribute macros.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use syn::{parse::Parser, punctuated::*, spanned::Spanned, Ident, Meta, Token};

fn attach_error<A>(mut v: syn::Result<A>, msg: &str) -> syn::Result<A> {
    if let Err(e) = v.as_mut() {
        let span = e.span();
        e.combine(syn::Error::new(span, msg));
    }
    v
}

/// Attributes that can be attached either to the init or receive method of a
/// smart contract.
struct OptionalArguments {
    /// If set, the contract can receive CCD.
    pub(crate) payable:           bool,
    /// If enabled, the function has access to logging facilities.
    pub(crate) enable_logger:     bool,
    /// The function is a low-level one, with direct access to contract memory.
    pub(crate) low_level:         bool,
    /// Which type, if any, is the parameter type of the function.
    /// This is used when generating schemas.
    pub(crate) parameter:         Option<syn::LitStr>,
    /// Which type, if any, is the return value of the function.
    /// This is used when generating schemas.
    pub(crate) return_value:      Option<syn::LitStr>,
    /// Which type, if any, is the error type of the function.
    /// This is used when generating schemas.
    pub(crate) error:             Option<syn::LitStr>,
    /// If enabled, the function has access to cryptographic primitives.
    pub(crate) crypto_primitives: bool,
}

/// Attributes that can be attached to the initialization method.
struct InitAttributes {
    /// Which type, if any, is the event type of the function.
    /// This is used when generating schemas.
    pub(crate) event:    Option<syn::LitStr>,
    /// Name of the contract.
    pub(crate) contract: syn::LitStr,
    pub(crate) optional: OptionalArguments,
}

/// Attributes that can be attached to the receive method.
struct ReceiveAttributes {
    /// Name of the contract the method applies to.
    pub(crate) contract: syn::LitStr,
    /// Name of the method.
    pub(crate) name:     syn::LitStr,
    pub(crate) optional: OptionalArguments,
    /// If enabled, the function has access to a mutable state, which will also
    /// be stored after the function returns.
    pub(crate) mutable:  bool,
}

#[derive(Default)]
struct ParsedAttributes {
    /// We use BTreeSet to have consistent order of iteration when reporting
    /// errors.
    pub(crate) flags:  BTreeSet<syn::Ident>,
    /// We use BTreeMap to have consistent order of iteration when reporting
    /// errors.
    pub(crate) values: BTreeMap<syn::Ident, syn::LitStr>,
}

impl ParsedAttributes {
    /// Remove an attribute and return its value (i.e., right hand side of
    /// `ident = value`), if present. The key must be a valid Rust identifier,
    /// otherwise this function will panic.
    pub(crate) fn extract_value(&mut self, key: &str) -> Option<syn::LitStr> {
        self.extract_ident_and_value(key).map(|x| x.1)
    }

    /// Remove an attribute identifier and the value and return it, if present.
    /// The key must be a valid Rust identifier, otherwise this function
    /// will panic.
    pub(crate) fn extract_ident_and_value(
        &mut self,
        key: &str,
    ) -> Option<(syn::Ident, syn::LitStr)> {
        // This is not clean, constructing a new identifier with a call_site span.
        // But the only alternative I see is iterating over the map and locating the key
        // since Ident implements equality comparison with &str.
        let key = syn::Ident::new(key, Span::call_site());
        self.values.remove_entry(&key)
    }

    /// Remove an attribute and return whether it was present.
    pub(crate) fn extract_flag(&mut self, key: &str) -> Option<Ident> {
        // This is not clean, constructing a new identifier with a call_site span.
        // But the only alternative I see is iterating over the map and locating the key
        // since Ident implements equality comparison with &str.
        let key = syn::Ident::new(key, Span::call_site());
        self.flags.take(&key)
    }

    /// If there are any remaining attributes signal an error. Otherwise return
    /// Ok(())
    pub(crate) fn report_all_attributes(self) -> syn::Result<()> {
        let mut iter = self.flags.into_iter().chain(self.values.into_keys());
        if let Some(ident) = iter.next() {
            let mut err =
                syn::Error::new(ident.span(), format!("Unrecognized attribute {}.", ident));
            for next_ident in iter {
                err.combine(syn::Error::new(
                    ident.span(),
                    format!("Unrecognized attribute {}.", next_ident),
                ));
            }
            Err(err)
        } else {
            Ok(())
        }
    }
}

/// Parse attributes ensuring there are no duplicate items.
fn parse_attributes<'a>(iter: impl IntoIterator<Item = &'a Meta>) -> syn::Result<ParsedAttributes> {
    let mut ret = ParsedAttributes::default();
    let mut errors = Vec::new();
    let mut duplicate_values = BTreeMap::new();
    let mut duplicate_flags = BTreeMap::new();
    for attr in iter.into_iter() {
        match attr {
            Meta::NameValue(mnv) => {
                if let Some(ident) = mnv.path.get_ident() {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(ls),
                        ..
                    }) = &mnv.value
                    {
                        if let Some((existing_ident, _)) = ret.values.get_key_value(ident) {
                            let v = duplicate_values.entry(ident).or_insert_with(|| {
                                syn::Error::new(
                                    existing_ident.span(),
                                    format!("Duplicate attribute '{}'.", existing_ident),
                                )
                            });
                            v.combine(syn::Error::new(
                                ident.span(),
                                format!("'{}' also appears here.", ident),
                            ));
                        } else {
                            ret.values.insert(ident.clone(), ls.clone());
                        }
                    } else {
                        errors.push(syn::Error::new(
                            mnv.path.span(),
                            format!(
                                "Values of attribute must be string literals, e.g., '{} = \
                                 \"value\"'",
                                ident
                            ),
                        ));
                    }
                } else {
                    errors.push(syn::Error::new(
                        mnv.path.span(),
                        "Unrecognized attribute. Only attribute names consisting of a single \
                         identifier are recognized.",
                    ))
                }
            }
            Meta::Path(p) => {
                if let Some(ident) = p.get_ident() {
                    if let Some(existing_ident) = ret.flags.get(ident) {
                        let v = duplicate_flags.entry(ident).or_insert_with(|| {
                            syn::Error::new(
                                existing_ident.span(),
                                format!("Duplicate attribute '{}'.", existing_ident),
                            )
                        });
                        v.combine(syn::Error::new(
                            ident.span(),
                            format!("'{}' also appears here.", ident),
                        ));
                    } else {
                        ret.flags.insert(ident.clone());
                    }
                } else {
                    errors.push(syn::Error::new(
                        p.span(),
                        "Unrecognized attribute. Only attribute names consisting of a single \
                         identifier are recognized.",
                    ))
                }
            }
            Meta::List(p) => {
                errors.push(syn::Error::new(p.span(), "Unrecognized attribute."));
            }
        }
    }
    let mut iter = errors
        .into_iter()
        .chain(duplicate_values.into_values())
        .chain(duplicate_flags.into_values());
    // If there are any errors we combine them.
    if let Some(err) = iter.next() {
        let mut err = err;
        for next_err in iter {
            err.combine(next_err);
        }
        Err(err)
    } else {
        Ok(ret)
    }
}

// Supported attributes for the init methods.

const INIT_ATTRIBUTE_PARAMETER: &str = "parameter";
const INIT_ATTRIBUTE_CONTRACT: &str = "contract";
const INIT_ATTRIBUTE_PAYABLE: &str = "payable";
const INIT_ATTRIBUTE_ENABLE_LOGGER: &str = "enable_logger";
const INIT_ATTRIBUTE_LOW_LEVEL: &str = "low_level";
const INIT_ATTRIBUTE_RETURN_VALUE: &str = "return_value";
const INIT_ATTRIBUTE_ERROR: &str = "error";
const INIT_ATTRIBUTE_EVENT: &str = "event";
const INIT_ATTRIBUTE_CRYPTO_PRIMITIVES: &str = "crypto_primitives";

fn parse_init_attributes<'a, I: IntoIterator<Item = &'a Meta>>(
    attrs: I,
) -> syn::Result<InitAttributes> {
    let mut attributes = parse_attributes(attrs)?;
    let contract: syn::LitStr =
        attributes.extract_value(INIT_ATTRIBUTE_CONTRACT).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "A name for the contract must be provided, using the 'contract' attribute.\n\nFor \
                 example, #[init(contract = \"my-contract\")]",
            )
        })?;
    let parameter: Option<syn::LitStr> = attributes.extract_value(INIT_ATTRIBUTE_PARAMETER);
    let payable = attributes.extract_flag(INIT_ATTRIBUTE_PAYABLE).is_some();
    let enable_logger = attributes.extract_flag(INIT_ATTRIBUTE_ENABLE_LOGGER).is_some();
    let low_level = attributes.extract_flag(INIT_ATTRIBUTE_LOW_LEVEL).is_some();
    let return_value = attributes.extract_ident_and_value(INIT_ATTRIBUTE_RETURN_VALUE);
    if let Some((ident, _)) = return_value {
        return Err(syn::Error::new(
            ident.span(),
            "The 'return_value' attribute is currently not supported for init methods.",
        ));
    }
    let error = attributes.extract_value(INIT_ATTRIBUTE_ERROR);
    let event = attributes.extract_value(INIT_ATTRIBUTE_EVENT);
    let crypto_primitives = attributes.extract_flag(INIT_ATTRIBUTE_CRYPTO_PRIMITIVES).is_some();

    // Make sure that there are no unrecognized attributes. These would typically be
    // there due to an error. An improvement would be to find the nearest valid one
    // for each of them and report that in the error.
    attributes.report_all_attributes()?;
    Ok(InitAttributes {
        contract,
        event,
        optional: OptionalArguments {
            payable,
            enable_logger,
            low_level,
            parameter,
            return_value: None, // Return values are currently not supported on init methods.
            error,
            crypto_primitives,
        },
    })
}

// Supported attributes for the receive methods.

const RECEIVE_ATTRIBUTE_PARAMETER: &str = "parameter";
const RECEIVE_ATTRIBUTE_RETURN_VALUE: &str = "return_value";
const RECEIVE_ATTRIBUTE_ERROR: &str = "error";
const RECEIVE_ATTRIBUTE_CONTRACT: &str = "contract";
const RECEIVE_ATTRIBUTE_NAME: &str = "name";
const RECEIVE_ATTRIBUTE_FALLBACK: &str = "fallback";
const RECEIVE_ATTRIBUTE_PAYABLE: &str = "payable";
const RECEIVE_ATTRIBUTE_ENABLE_LOGGER: &str = "enable_logger";
const RECEIVE_ATTRIBUTE_LOW_LEVEL: &str = "low_level";
const RECEIVE_ATTRIBUTE_MUTABLE: &str = "mutable";
const RECEIVE_ATTRIBUTE_CRYPTO_PRIMITIVES: &str = "crypto_primitives";

fn parse_receive_attributes<'a, I: IntoIterator<Item = &'a Meta>>(
    attrs: I,
) -> syn::Result<ReceiveAttributes> {
    let mut attributes = parse_attributes(attrs)?;

    let contract = attributes.extract_value(RECEIVE_ATTRIBUTE_CONTRACT);
    let name = attributes.extract_ident_and_value(RECEIVE_ATTRIBUTE_NAME);
    let fallback = attributes.extract_flag(RECEIVE_ATTRIBUTE_FALLBACK);
    let parameter: Option<syn::LitStr> = attributes.extract_value(RECEIVE_ATTRIBUTE_PARAMETER);
    let return_value: Option<syn::LitStr> =
        attributes.extract_value(RECEIVE_ATTRIBUTE_RETURN_VALUE);
    let error: Option<syn::LitStr> = attributes.extract_value(RECEIVE_ATTRIBUTE_ERROR);
    let payable = attributes.extract_flag(RECEIVE_ATTRIBUTE_PAYABLE).is_some();
    let enable_logger = attributes.extract_flag(RECEIVE_ATTRIBUTE_ENABLE_LOGGER).is_some();
    let low_level = attributes.extract_flag(RECEIVE_ATTRIBUTE_LOW_LEVEL);
    let mutable = attributes.extract_flag(RECEIVE_ATTRIBUTE_MUTABLE);
    let crypto_primitives = attributes.extract_flag(RECEIVE_ATTRIBUTE_CRYPTO_PRIMITIVES).is_some();

    if let (Some(mutable), Some(low_level)) = (&mutable, &low_level) {
        let mut error = syn::Error::new(
            mutable.span(),
            "The attributes 'mutable' and 'low_level' are incompatible and should not be used on \
             the same method. `mutable` appears here.",
        );
        error.combine(syn::Error::new(
            low_level.span(),
            "The attributes 'mutable' and 'low_level' are incompatible and should not be used on \
             the same method. `low_level` appears here.",
        ));
        return Err(error);
    }

    if let (Some((name, _)), Some(fallback)) = (&name, &fallback) {
        let mut error = syn::Error::new(
            name.span(),
            "The attributes 'name' and 'fallback' are incompatible and should not be used on the \
             same method. `name` appears here.",
        );
        error.combine(syn::Error::new(
            fallback.span(),
            "The attributes 'name' and 'fallback' are incompatible and should not be used on the \
             same method. `fallback` appears here.",
        ));
        return Err(error);
    }
    // Make sure that there are no unrecognized attributes. These would typically be
    // there due to an error. An improvement would be to find the nearest valid one
    // for each of them and report that in the error.
    attributes.report_all_attributes()?;
    match (contract, name) {
        (Some(contract), Some((_, name))) => Ok(ReceiveAttributes {
            contract,
            name,
            optional: OptionalArguments {
                payable,
                enable_logger,
                low_level: low_level.is_some(),
                parameter,
                return_value,
                error,
                crypto_primitives,
            },
            mutable: mutable.is_some(), /* This is also optional, but does not belong in
                                         * OptionalArguments, as
                                         * it doesn't apply to init methods. */
        }),
        (Some(contract), None) => {
            if let Some(ident) = fallback {
                Ok(ReceiveAttributes {
                    contract,
                    name: syn::LitStr::new("", ident.span()),
                    optional: OptionalArguments {
                        payable,
                        enable_logger,
                        low_level: low_level.is_some(),
                        parameter,
                        return_value,
                        error,
                        crypto_primitives,
                    },
                    mutable: mutable.is_some(), /* TODO: This is also optional, but does not
                                                 * belong in
                                                 * OptionalArguments, as
                                                 * it doesn't apply to init methods. */
                })
            } else {
                Err(syn::Error::new(
                    Span::call_site(),
                    "A name for the method must be provided using the 'name' attribute, or the \
                     'fallback' option must be used.\n\nFor example, #[receive(name = \
                     \"receive\")]",
                ))
            }
        }
        (None, Some(_)) => Err(syn::Error::new(
            Span::call_site(),
            "A name for the method must be provided, using the 'contract' attribute.\n\nFor \
             example, #[receive(contract = \"my-contract\")]",
        )),
        (None, None) => Err(syn::Error::new(
            Span::call_site(),
            "A contract name and a name for the method must be provided, using the 'contract' and \
             'name' attributes.\n\nFor example, #[receive(contract = \"my-contract\", name = \
             \"receive\")]",
        )),
    }
}

/// Check whether the given string is a valid contract initialization
/// function name. This is the case if and only if
/// - the string is no more than 100 bytes
/// - the string starts with `init_`
/// - the string __does not__ contain a `.`
/// - all characters are ascii alphanumeric or punctuation characters.
fn is_valid_contract_name(name: &str) -> Result<(), &str> {
    if !name.starts_with("init_") {
        return Err("Contract names have the format 'init_<contract_name>'");
    }
    if name.len() > 100 {
        return Err("Contract names have a max length of 100");
    }
    if name.contains('.') {
        return Err("Contract names cannot contain a '.'");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
        return Err("Contract names can only contain ascii alphanumeric or punctuation characters");
    }
    Ok(())
}

/// Check whether the given string is a valid contract receive function
/// name. This is the case if and only if
/// - the string is no more than 100 bytes
/// - the string __contains__ a `.`
/// - all characters are ascii alphanumeric or punctuation characters.
fn is_valid_receive_name(name: &str) -> Result<(), &str> {
    if !name.contains('.') {
        return Err("Receive names have the format '<contract_name>.<func_name>'.");
    }
    if name.len() > 100 {
        return Err("Receive names have a max length of 100");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
        return Err("Receive names can only contain ascii alphanumeric or punctuation characters");
    }
    Ok(())
}

pub fn init_worker(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let ast: syn::ItemFn =
        attach_error(syn::parse(item), "#[init] can only be applied to functions.")?;

    let attrs = Punctuated::<Meta, Token![,]>::parse_terminated.parse(attr)?;

    let init_attributes = parse_init_attributes(&attrs)?;

    let contract_name = init_attributes.contract;

    let fn_name = &ast.sig.ident;
    let rust_export_fn_name = format_ident!("export_{}", fn_name);
    let wasm_export_fn_name = format!("init_{}", contract_name.value());

    if let Err(e) = is_valid_contract_name(&wasm_export_fn_name) {
        return Err(syn::Error::new(contract_name.span(), e));
    }

    let amount_ident = format_ident!("amount");

    // Accumulate a list of required arguments, if the function contains a
    // different number of arguments, than elements in this vector, then the
    // strings are displayed as the expected arguments.
    let mut required_args = vec!["ctx: &impl HasInitContext"];

    let (setup_fn_optional_args, fn_optional_args) = contract_function_optional_args_tokens(
        &init_attributes.optional,
        &amount_ident,
        &mut required_args,
    );

    let mut out = if init_attributes.optional.low_level {
        required_args.push("state: &mut impl HasStateApi");
        quote! {
            #[export_name = #wasm_export_fn_name]
            pub extern "C" fn #rust_export_fn_name(#amount_ident: concordium_std::Amount) -> i32 {
                use concordium_std::{trap, ExternContext, ExternInitContext, ExternStateApi, HasStateApi};
                #setup_fn_optional_args
                let ctx = ExternContext::<ExternInitContext>::open(());
                let mut state = ExternStateApi::open();
                match #fn_name(&ctx, &mut state, #(#fn_optional_args, )*) {
                    Ok(()) => 0,
                    Err(reject) => {
                        let code = Reject::from(reject).error_code.get();
                        if code < 0 {
                            code
                        } else {
                            trap() // precondition violation
                        }
                    }
                }
            }
        }
    } else {
        required_args.push("state_builder: &mut StateBuilder");
        quote! {
            #[export_name = #wasm_export_fn_name]
            pub extern "C" fn #rust_export_fn_name(amount: concordium_std::Amount) -> i32 {
                use concordium_std::{trap, ExternContext, ExternInitContext, StateBuilder, ExternReturnValue};
                #setup_fn_optional_args
                let ctx = ExternContext::<ExternInitContext>::open(());
                let mut state_api = ExternStateApi::open();
                let mut state_builder = StateBuilder::open(state_api.clone());
                match #fn_name(&ctx, &mut state_builder, #(#fn_optional_args, )*) {
                    Ok(state) => {
                        // Store the state.
                        let mut root_entry = state_api.create_entry(&[]).unwrap_abort();
                        state.serial(&mut root_entry).unwrap_abort();
                        // Return success
                        0
                    },
                    Err(reject) => {
                        let code = Reject::from(reject).error_code.get();
                        if code < 0 {
                            code
                        } else {
                            trap() // precondition violation
                        }
                    }
                }
            }
        }
    };

    let arg_count = ast.sig.inputs.len();
    if arg_count != required_args.len() {
        return Err(syn::Error::new(
            ast.sig.inputs.span(),
            format!(
                "Incorrect number of function arguments, the expected arguments are ({}) ",
                required_args.join(", ")
            ),
        ));
    }

    // Embed a schema for the parameter and return value if the corresponding
    // attribute is set.
    let parameter_option = init_attributes.optional.parameter;
    let return_value_option = None; // Return values are currently not supported on init.
    let error_option = init_attributes.optional.error;
    let event_option = init_attributes.event;
    let wasm_name_cloned = wasm_export_fn_name.clone();
    let rust_name_cloned = rust_export_fn_name.clone();

    out.extend(contract_function_schema_tokens(
        parameter_option,
        return_value_option,
        error_option,
        rust_export_fn_name,
        wasm_export_fn_name,
    )?);

    // Adding the event schema
    out.extend(contract_function_event_schema(event_option, rust_name_cloned, wasm_name_cloned)?);

    ast.to_tokens(&mut out);

    Ok(out.into())
}

pub fn receive_worker(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let ast: syn::ItemFn =
        attach_error(syn::parse(item), "#[receive] can only be applied to functions.")?;

    let attrs = Punctuated::<Meta, Token![,]>::parse_terminated.parse(attr)?;

    let receive_attributes = parse_receive_attributes(&attrs)?;

    let contract_name = receive_attributes.contract;

    let method_name = receive_attributes.name;

    let fn_name = &ast.sig.ident;
    let rust_export_fn_name = format_ident!("export_{}", fn_name);
    let wasm_export_fn_name = format!("{}.{}", contract_name.value(), method_name.value());

    // Validate the contract name independently to ensure that it doesn't contain a
    // '.' as this causes a subtle error when receive names are being split.
    let contract_name_validation =
        is_valid_contract_name(&format!("init_{}", contract_name.value()))
            .map_err(|e| syn::Error::new(contract_name.span(), e));

    let receive_name_validation = is_valid_receive_name(&wasm_export_fn_name)
        .map_err(|e| syn::Error::new(method_name.span(), e));

    match (contract_name_validation, receive_name_validation) {
        (Err(mut e0), Err(e1)) => {
            e0.combine(e1);
            return Err(e0);
        }
        (Err(e), _) => return Err(e),
        (_, Err(e)) => return Err(e),
        _ => (),
    };

    let amount_ident = format_ident!("amount");

    // Accumulate a list of required arguments, if the function contains a
    // different number of arguments, than elements in this vector, then the
    // strings are displayed as the expected arguments.
    let mut required_args = vec!["ctx: &impl HasReceiveContext"];
    if receive_attributes.mutable {
        required_args.push("host: &mut impl HasHost");
    } else {
        required_args.push("host: &impl HasHost");
    }

    let (setup_fn_optional_args, fn_optional_args) = contract_function_optional_args_tokens(
        &receive_attributes.optional,
        &amount_ident,
        &mut required_args,
    );

    let mut out = if receive_attributes.optional.low_level {
        quote! {
            #[export_name = #wasm_export_fn_name]
            pub extern "C" fn #rust_export_fn_name(#amount_ident: concordium_std::Amount) -> i32 {
                use concordium_std::{SeekFrom, Logger, ExternReceiveContext, ExternContext, ExternLowLevelHost};
                #setup_fn_optional_args
                let ctx = ExternContext::<ExternReceiveContext>::open(());
                let mut host = ExternLowLevelHost::default();
                match #fn_name(&ctx, &mut host, #(#fn_optional_args, )*) {
                    Ok(rv) => {
                        if rv.serial(&mut ExternReturnValue::open()).is_err() {
                            trap() // Could not serialize the return value.
                        }
                        0
                    }
                    Err(reject) => {
                        let reject = Reject::from(reject);
                        let code = reject.error_code.get();
                        if code < 0 {
                            if let Some(rv) = reject.return_value {
                                if ExternReturnValue::open().write_all(&rv).is_err() {
                                    trap() // Could not serialize the return value.
                                }
                            }
                            code
                        } else {
                            trap() // precondition violation
                        }
                    }
                }
            }
        }
    } else {
        let (host_ref, save_state_if_mutable) = if receive_attributes.mutable {
            (quote!(&mut host), quote! {
                // look up the root entry again, since we might be in a different generation now
                let mut root_entry_end = host.state_builder.into_inner().lookup_entry(&[]).unwrap_abort();
                host.state.serial(&mut root_entry_end).unwrap_abort();
                let new_state_size = root_entry_end.size().unwrap_abort();
                root_entry_end.truncate(new_state_size).unwrap_abort();
            })
        } else {
            (quote!(&host), quote!())
        };

        quote! {
            #[export_name = #wasm_export_fn_name]
            pub extern "C" fn #rust_export_fn_name(#amount_ident: concordium_std::Amount) -> i32 {
                use concordium_std::{SeekFrom, StateBuilder, Logger, ExternHost, trap};
                #setup_fn_optional_args
                let ctx = ExternContext::<ExternReceiveContext>::open(());
                let state_api = ExternStateApi::open();
                if let Ok(state) = DeserialWithState::deserial_with_state(&state_api, &mut state_api.lookup_entry(&[]).unwrap_abort()) {
                    let mut state_builder = StateBuilder::open(state_api);
                    let mut host = ExternHost { state, state_builder };
                    match #fn_name(&ctx, #host_ref, #(#fn_optional_args, )*) {
                        Ok(rv) => {
                            if rv.serial(&mut ExternReturnValue::open()).is_err() {
                                trap() // Could not serialize return value.
                            }
                            #save_state_if_mutable
                            0
                        }
                        Err(reject) => {
                            let reject = Reject::from(reject);
                            let code = reject.error_code.get();
                            if code < 0 {
                                if let Some(rv) = reject.return_value {
                                    if ExternReturnValue::open().write_all(&rv).is_err() {
                                        trap() // Could not serialize the return value.
                                    }
                                }
                                code
                            } else {
                                trap() // precondition violation
                            }
                        }
                    }
                } else {
                    trap() // Could not fully read state.
                }
            }
        }
    };

    let arg_count = ast.sig.inputs.len();
    if arg_count != required_args.len() {
        return Err(syn::Error::new(
            ast.sig.inputs.span(),
            format!(
                "Incorrect number of function arguments, the expected arguments are ({}) ",
                required_args.join(", ")
            ),
        ));
    }

    // Embed a schema for the parameter and return value if the corresponding
    // attribute is set.
    let parameter_option = receive_attributes.optional.parameter;
    let return_value_option = receive_attributes.optional.return_value;
    let error_option = receive_attributes.optional.error;
    out.extend(contract_function_schema_tokens(
        parameter_option,
        return_value_option,
        error_option,
        rust_export_fn_name,
        wasm_export_fn_name,
    )?);
    // add the original function to the output as well.
    ast.to_tokens(&mut out);
    Ok(out.into())
}

/// Generate tokens for some of the optional arguments, based on the attributes.
/// Returns a pair, where the first entry is tokens for setting up the arguments
/// and the second entry is a Vec of the argument names as tokens.
///
/// It also mutates a vector of required arguments with the expected type
/// signature of each.
fn contract_function_optional_args_tokens(
    optional: &OptionalArguments,
    amount_ident: &syn::Ident,
    required_args: &mut Vec<&str>,
) -> (proc_macro2::TokenStream, Vec<proc_macro2::TokenStream>) {
    let mut setup_fn_args = proc_macro2::TokenStream::new();
    let mut fn_args = vec![];
    if optional.payable {
        required_args.push("amount: Amount");
        fn_args.push(quote!(#amount_ident));
    } else {
        setup_fn_args.extend(quote! {
            if #amount_ident.micro_ccd != 0 {
                return concordium_std::Reject::from(concordium_std::NotPayableError).error_code.get();
            }
        });
    };

    if optional.enable_logger {
        required_args.push("logger: &mut impl HasLogger");
        let logger_ident = format_ident!("logger");
        setup_fn_args.extend(quote!(let mut #logger_ident = concordium_std::Logger::init();));
        fn_args.push(quote!(&mut #logger_ident));
    }

    if optional.crypto_primitives {
        required_args.push("crypto_primitives: &impl HasCryptoPrimitives");
        let crypto_primitives_ident = format_ident!("crypto_primitives");
        setup_fn_args
            .extend(quote!(let #crypto_primitives_ident = concordium_std::ExternCryptoPrimitives;));
        fn_args.push(quote!(&#crypto_primitives_ident));
    }

    (setup_fn_args, fn_args)
}

#[cfg(feature = "build-schema")]
fn contract_function_event_schema(
    event_option: Option<syn::LitStr>,
    rust_name: syn::Ident,
    wasm_name: String,
) -> syn::Result<proc_macro2::TokenStream> {
    let event_embed = match event_option {
        Some(event_ty) => {
            let event_ty = event_ty.parse::<syn::Type>()?;
            Some(quote! {
            let event = <#event_ty as schema::SchemaType>::get_type();
            let schema_bytes = concordium_std::to_bytes(&event);})
        }
        _ => None,
    };

    // Only produce the schema function if the event was set.
    if let Some(construct_schema_bytes) = event_embed {
        let schema_name = format!("concordium_event_schema_{}", wasm_name);
        let schema_ident = format_ident!("concordium_event_schema_{}", rust_name);
        Ok(quote! {
            #[export_name = #schema_name]
            pub extern "C" fn #schema_ident() -> *mut u8 {
                #construct_schema_bytes
                concordium_std::put_in_memory(&schema_bytes)
            }
        })
    } else {
        Ok(proc_macro2::TokenStream::new())
    }
}

#[cfg(feature = "build-schema")]
fn contract_function_schema_tokens(
    parameter_option: Option<syn::LitStr>,
    return_value_option: Option<syn::LitStr>,
    error_option: Option<syn::LitStr>,
    rust_name: syn::Ident,
    wasm_name: String,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut embed = false;

    let parameter_schema = format_ident!("parameter");
    let parameter_embed = if let Some(parameter_ty) = parameter_option {
        let ty = parameter_ty.parse::<syn::Type>()?;
        embed = true;
        quote! {
             let #parameter_schema = Some(<#ty as schema::SchemaType>::get_type());
        }
    } else {
        quote! {let #parameter_schema = None;}
    };

    let return_value_schema = format_ident!("return_value");
    let return_embed = if let Some(return_ty) = return_value_option {
        let ty = return_ty.parse::<syn::Type>()?;
        embed = true;
        quote! {
             let #return_value_schema = Some(<#ty as schema::SchemaType>::get_type());
        }
    } else {
        quote! {let #return_value_schema = None;}
    };

    let error_schema = format_ident!("error");
    let error_embed = if let Some(error_ty) = error_option {
        let ty = error_ty.parse::<syn::Type>()?;
        embed = true;
        quote! {
             let #error_schema = Some(<#ty as schema::SchemaType>::get_type());
        }
    } else {
        quote! {let #error_schema = None;}
    };

    // Only produce the schema function if the parameter, return_value, error, or
    // event attribute was set.
    if embed {
        let schema_name = format!("concordium_schema_function_{}", wasm_name);
        let schema_ident = format_ident!("concordium_schema_function_{}", rust_name);
        Ok(quote! {
            #[export_name = #schema_name]
            pub extern "C" fn #schema_ident() -> *mut u8 {
                #return_embed
                #parameter_embed
                #error_embed
                let schema_bytes = concordium_std::to_bytes(&schema::FunctionV2 {parameter: #parameter_schema, return_value: #return_value_schema, error: #error_schema});
                concordium_std::put_in_memory(&schema_bytes)
            }
        })
    } else {
        Ok(proc_macro2::TokenStream::new())
    }
}

#[cfg(not(feature = "build-schema"))]
fn contract_function_schema_tokens(
    _parameter_option: Option<syn::LitStr>,
    _return_value_option: Option<syn::LitStr>,
    _error_option: Option<syn::LitStr>,
    _rust_name: syn::Ident,
    _wasm_name: String,
) -> syn::Result<proc_macro2::TokenStream> {
    Ok(proc_macro2::TokenStream::new())
}

#[cfg(not(feature = "build-schema"))]
fn contract_function_event_schema(
    _event_option: Option<syn::LitStr>,
    _rust_name: syn::Ident,
    _wasm_name: String,
) -> syn::Result<proc_macro2::TokenStream> {
    Ok(proc_macro2::TokenStream::new())
}

/// Derive the appropriate export for an annotated test function, when feature
/// "wasm-test" is enabled, otherwise behaves like `#[test]`.
#[cfg(feature = "wasm-test")]
pub fn concordium_test_worker(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let test_fn_ast: syn::ItemFn =
        attach_error(syn::parse(item), "#[concordium_test] can only be applied to functions.")?;

    let test_fn_name = &test_fn_ast.sig.ident;
    let rust_export_fn_name = format_ident!("concordium_test_{}", test_fn_name);
    let wasm_export_fn_name = format!("concordium_test {}", test_fn_name);

    let test_fn = quote! {
        // Setup test function
        #test_fn_ast

        // Export test function in wasm
        #[export_name = #wasm_export_fn_name]
        pub extern "C" fn #rust_export_fn_name() {
            #test_fn_name()
        }
    };
    Ok(test_fn.into())
}

/// Derive the appropriate export for an annotated test function, when feature
/// "wasm-test" is enabled, otherwise behaves like `#[test]`.
#[cfg(not(feature = "wasm-test"))]
pub fn concordium_test_worker(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let test_fn_ast: syn::ItemFn =
        attach_error(syn::parse(item), "#[concordium_test] can only be applied to functions.")?;

    let test_fn = quote! {
        #[test]
        #test_fn_ast
    };
    Ok(test_fn.into())
}

#[cfg(feature = "concordium-quickcheck")]
pub mod quickcheck {
    use super::*;
    use syn::{parse_quote, FnArg, PatType};

    const QUICKCHECK_NUM_TESTS: &str = "num_tests";

    // Maximum number of QuickCheck tests to run.
    // Includes only *passed* tests (discarded not counted).
    // Note: when changing this constant, make sure that
    // concordium_std::test_infrastructure::QUICKCHECK_MAX_WITH_DISCARDED_TESTS is
    // also changed so it is around x100 bigger (QuckCheck default).
    const QUICKCHECK_MAX_PASSED_TESTS: u64 = 1_000_000;

    /// Look up the `tests` identifier in `NestedMeta` and return the value
    /// associated with it. If no `num_tests` is found or parsing the value has
    /// failed, return a error
    fn get_quickcheck_tests_count(meta: &syn::Meta) -> syn::Result<u64> {
        match meta {
            Meta::NameValue(v) => {
                if v.path.is_ident(QUICKCHECK_NUM_TESTS) {
                    match &v.value {
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Int(i),
                            ..
                        }) => {
                            let num_tests = i
                                .base10_parse::<u64>()
                                .map_err(|e| syn::Error::new_spanned(i, e.to_string()))?;
                            if num_tests > QUICKCHECK_MAX_PASSED_TESTS {
                                Err(syn::Error::new_spanned(
                                    i,
                                    format!(
                                        "max number of tests is {}",
                                        QUICKCHECK_MAX_PASSED_TESTS
                                    ),
                                ))
                            } else {
                                Ok(num_tests)
                            }
                        }
                        l => Err(syn::Error::new_spanned(
                            l,
                            "unexpected attribute value, expected a non-negative integer",
                        )),
                    }
                } else {
                    Err(syn::Error::new_spanned(
                        meta,
                        format!(
                            "unexpected attribute, expected a single `{} = <number>` attribute",
                            QUICKCHECK_NUM_TESTS
                        ),
                    ))
                }
            }
            _ => Err(syn::Error::new_spanned(
                meta,
                format!(
                    "unexpected attribute, expected a single `{} = <number>` attribute",
                    QUICKCHECK_NUM_TESTS
                ),
            )),
        }
    }

    /// Parse the arguments and return a value associated with the `num_tests`
    /// identifier, if successfull.
    fn parse_quickcheck_num_tests(attr: TokenStream) -> syn::Result<u64> {
        let parsed_attr = Punctuated::<Meta, Token![,]>::parse_terminated.parse(attr)?;
        let mut err_opt: Option<syn::Error> = None;
        let mut v = None;
        for attr in parsed_attr {
            match get_quickcheck_tests_count(&attr) {
                Ok(x) => {
                    if v.is_some() {
                        let new_err = syn::Error::new(
                            attr.span(),
                            format!(
                                "duplicate attribute; expected a single `{} = <number>` attribute",
                                QUICKCHECK_NUM_TESTS
                            ),
                        );
                        if let Some(ref mut err) = err_opt {
                            err.combine(new_err);
                        } else {
                            err_opt = Some(new_err)
                        }
                    } else {
                        v = Some(x)
                    }
                }
                Err(e) => {
                    if let Some(ref mut err) = err_opt {
                        err.combine(e);
                    } else {
                        err_opt = Some(e)
                    }
                }
            }
        }
        if let Some(np) = v {
            if let Some(err) = err_opt {
                Err(err)
            } else {
                Ok(np)
            }
        } else {
            // no parameter given, default values
            Ok(100)
        }
    }

    /// Return a function that calls a customized QuickCheck test runner
    /// function with the number of tests to run acquired from `attr` and a
    /// test function `item_fn`.
    pub fn wrap_quickcheck_test(
        attr: TokenStream,
        item_fn: &mut syn::ItemFn,
    ) -> syn::Result<proc_macro2::TokenStream> {
        let num_tests: u64 = parse_quickcheck_num_tests(attr)?;
        let mut inputs: Punctuated<syn::BareFnArg, syn::token::Comma> =
            syn::punctuated::Punctuated::new();

        for input in item_fn.sig.inputs.iter() {
            match input {
                FnArg::Typed(PatType {
                    ref ty,
                    ..
                }) => {
                    inputs.push(parse_quote!(_: #ty));
                }
                FnArg::Receiver(_) => {
                    return Err(syn::Error::new(input.span(), "`self` arguments are not supported"))
                }
            }
        }

        let attrs = std::mem::take(&mut item_fn.attrs);
        let name = &item_fn.sig.ident;
        let codomain = &item_fn.sig.output;
        let res = quote! {
            #[concordium_test]
            #(#attrs)*
            fn #name() {
                #item_fn
               ::concordium_std::test_infrastructure::concordium_qc(#num_tests, #name as (fn (#inputs) #codomain))
            }
        };
        Ok(res)
    }
}
