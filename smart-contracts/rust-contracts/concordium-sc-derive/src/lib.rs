#![no_std]
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{export::Span, parse::Parser, punctuated::*, Ident, Meta, Token};

// Get the name item from a list, if available and a string literal.
// FIXME: Ensure there is only one.
fn get_name<'a, I: IntoIterator<Item = &'a Meta>>(iter: I) -> Option<Ident> {
    iter.into_iter().find_map(|attr| match attr {
        Meta::NameValue(mnv) => {
            if mnv.path.is_ident("name") {
                if let syn::Lit::Str(lit) = &mnv.lit {
                    Some(Ident::new(&lit.value(), Span::call_site()))
                } else {
                    panic!("The `name` attribute must be a string literal.")
                }
            } else {
                None
            }
        }
        _ => None,
    })
}

// Return whether the low-level item is present.
fn get_low_level<'a, I: IntoIterator<Item = &'a Meta>>(iter: I) -> bool {
    iter.into_iter().any(|attr| match attr {
        Meta::Path(path) => path.is_ident("low_level"),
        _ => false,
    })
}

/// Derive the appropriate export for an annotated init function.
///
/// This macro requires the following items to be present
/// - name="init_name" where "init_name" will be the name of the generated
///   function. It should be unique in the module.
///
/// The annotated function must be of a specific type.
///
/// TODO:
/// - Document the expected type.
#[proc_macro_attribute]
pub fn init(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attrs = parser.parse(attr).expect("Expect a comma-separated list of meta items.");

    let name = match get_name(attrs.iter()) {
        Some(ident) => ident,
        None => panic!("A name attribute must be provided."),
    };

    let ast: syn::ItemFn = syn::parse(item).expect("Init can only be applied to functions.");

    let fn_name = &ast.sig.ident;
    let mut out = if get_low_level(attrs.iter()) {
        quote! {
            #[no_mangle]
            pub extern "C" fn #name(amount: Amount) -> i32 {
                let ctx = InitContextLazy::open(());
                let mut state = ContractState::open(());
                let mut logger = Logger::init();
                match #fn_name(ctx, amount, &mut logger, &mut state) {
                    Ok(()) => 0,
                    Err(_) => -1,
                }
            }
        }
    } else {
        quote! {
            #[no_mangle]
            pub extern "C" fn #name(amount: Amount) -> i32 {
                let ctx = InitContextLazy::open(());
                let mut logger = Logger::init();
                match #fn_name(ctx, amount, &mut logger) {
                    Ok(state) => {
                        let mut state_bytes = ContractState::open(());
                        if state.serial(&mut state_bytes).is_err() {
                            panic!("Could not initialize contract.");
                        };
                        0
                    }
                    Err(_) => -1
                }
            }
        }
    };
    ast.to_tokens(&mut out);
    out.into()
}

/// Derive the appropriate export for an annotated receive function.
///
/// This macro requires the following items to be present
/// - name="receive_name" where "receive_name" will be the name of the generated
///   function. It should be unique in the module.
///
/// The annotated function must be of a specific type.
///
/// TODO:
/// - Document the expected type.
#[proc_macro_attribute]
pub fn receive(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let attrs = parser.parse(attr).expect("Expect a comma-separated list of meta items.");

    let name = match get_name(attrs.iter()) {
        Some(ident) => ident,
        None => panic!("A name attribute must be provided."),
    };

    let ast: syn::ItemFn = syn::parse(item).expect("Receive can only be applied to functions.");
    let fn_name = &ast.sig.ident;
    let mut out = if get_low_level(attrs.iter()) {
        quote! {
        #[no_mangle]
        pub extern "C" fn #name(amount: Amount) -> i32 {
            use concordium_sc_base::{SeekFrom, ContractState, Logger};
            let ctx = ReceiveContextLazy::open(());
            let mut state = ContractState::open(());
            let mut logger = Logger::init();
            let res: ReceiveResult<Action> = #fn_name(ctx, amount, &mut logger, &mut state);
            match res {
                Ok(act) => {
                    act.tag() as i32
                }
                Err(_) => -1,
            }
        }
        }
    } else {
        quote! {
            #[no_mangle]
            pub extern "C" fn #name(amount: Amount) -> i32 {
                use concordium_sc_base::{SeekFrom, ContractState, Logger};
                let ctx = ReceiveContextLazy::open(());
                let mut logger = Logger::init();
                let mut state_bytes = ContractState::open(());
                if let Ok(mut state) = (&mut state_bytes).get() {
                    let res: ReceiveResult<Action> = #fn_name(ctx, amount, &mut logger, &mut state);
                    match res {
                        Ok(act) => {
                            let res = state_bytes
                                .seek(SeekFrom::Start(0))
                                .and_then(|_| state.serial(&mut state_bytes));
                            if res.is_err() {
                                panic!("Could not write state.")
                            } else {
                                act.tag() as i32
                            }
                        }
                        Err(_) => -1,
                    }
                }
                else {
                    panic!("Could not read state fully.")
                }
            }
        }
    };
    // add the original function to the output as well.
    ast.to_tokens(&mut out);
    out.into()
}
