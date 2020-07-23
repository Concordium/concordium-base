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
    let mut out = quote! {
        #[no_mangle]
        pub extern "C" fn #name(amount: Amount) {
            use concordium_sc_base::Create;
            let ctx = InitContext::new();
            let mut state_bytes = ContractState::new();
            match #fn_name(ctx, amount) {
                Ok(state) => {
                    if state.serial(&mut state_bytes).is_none() {
                        panic!("Could not initialize contract.");
                    }
                }
                Err(_) => internal::fail(),
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
    let mut out = quote! {
        #[no_mangle]
        pub extern "C" fn #name(amount: Amount) {
            use concordium_sc_base::{internal, SeekFrom, ContractState, Create};
            let ctx = ReceiveContext::new();
            let mut state_bytes = ContractState::new();
            if let Some(mut state) = State::deserial(&mut state_bytes) {
                match #fn_name(ctx, amount, &mut state) {
                    Ok(_) => {
                        let res = state_bytes
                            .seek(SeekFrom::Start(0))
                            .ok()
                            .and_then(|_| state.serial(&mut state_bytes));
                        if res.is_none() {
                            panic!("Could not write state.")
                        } else {
                            internal::accept()
                        }
                    }
                    Err(_) => internal::fail(),
                }
            }
            else {
                panic!("Could not read state fully.")
            }
        }
    };
    // add the original function to the output as well.
    ast.to_tokens(&mut out);
    out.into()
}
