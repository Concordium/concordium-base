// #![no_std]
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{export::Span, parse::Parser, punctuated::*, spanned::Spanned, Ident, Meta, Token};

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
                let ctx = InitContextExtern::open(());
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
                let ctx = InitContextExtern::open(());
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
            let ctx = ReceiveContextExtern::open(());
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
                let ctx = ReceiveContextExtern::open(());
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

/// Derive the Deserial trait.
/// Assumes every field of the data to implement Deserial trait.
///
/// Collections are assumed to have a length within u32.
/// Optionally collection fields can be annotated with a size length to reduce
/// the serialized size (see also `derive(Serial)`). The annotation for `Vec` is
/// `size_length`, `BTreeMap` is `map_size_length` and `BTreeSet` is
/// `set_size_length`.
///
/// The derived deserialization for `BTreeMap` and `BTreeSet` checks the
/// serialized keys to be ordered. Optionally these fields can be annotated with
/// `skip_order_check` to reduce the resulting code even further.
///
/// The size length is specified as the number of bytes, and can be either of
/// the following numbers: 1, 2, 4, 8.
///
/// # Example
/// ```
/// #[derive(Deserial)]
/// struct Foo {
///     #[set_size_length = 1]
///     #[skip_order_check]
///     bar: BTreeSet<u8>,
/// }
/// ```
#[proc_macro_derive(
    Deserial,
    attributes(
        size_length,
        map_size_length,
        set_size_length,
        string_size_length,
        skip_order_check
    )
)]
pub fn deserial_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_deserial(&ast)
}

fn find_attribute_value(attributes: &[syn::Attribute], target_attr: &str) -> Option<syn::Lit> {
    let target_attr = format_ident!("{}", target_attr);
    let attr_values: Vec<_> = attributes
        .iter()
        .filter_map(|attr| match attr.parse_meta() {
            Ok(syn::Meta::NameValue(value)) if value.path.is_ident(&target_attr) => Some(value.lit),
            _ => None,
        })
        .collect();
    if attr_values.is_empty() {
        return None;
    }
    if attr_values.len() > 1 {
        panic!("Attribute '{}' should only be specified once.", target_attr)
    }
    Some(attr_values[0].clone())
}

fn find_length_attribute(attributes: &[syn::Attribute], target_attr: &str) -> Option<u32> {
    let value = find_attribute_value(attributes, target_attr)?;
    let value = match value {
        syn::Lit::Int(int) => int,
        _ => panic!("Unknown attribute value {:?}.", value),
    };
    let value = match value.base10_parse() {
        Ok(v) => v,
        _ => panic!("Unknown attribute value {}.", value),
    };
    match value {
        1 | 2 | 4 | 8 => Some(value),
        _ => panic!("Length info must be a power of two between 1 and 8 inclusive."),
    }
}

fn contains_attribute(attributes: &[syn::Attribute], target_attr: &str) -> bool {
    let target_attr = format_ident!("{}", target_attr);
    attributes.iter().any(|attr| match attr.parse_meta() {
        Ok(meta) => meta.path().is_ident(&target_attr),
        _ => false,
    })
}

fn impl_deserial_field(
    f: &syn::Field,
    ident: &syn::Ident,
    source: &syn::Ident,
) -> proc_macro2::TokenStream {
    if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
        let size = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len = #size::deserial(#source)?;
                deserial_vector_no_length(#source, len as usize)?
            };
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
        let size = format_ident!("u{}", 8 * l);
        if contains_attribute(&f.attrs, "skip_order_check") {
            quote! {
                let #ident = {
                    let len = #size::deserial(#source)?;
                    deserial_map_no_length_no_order_check(#source, len as usize)?
                };
            }
        } else {
            quote! {
                let #ident = {
                    let len = #size::deserial(#source)?;
                    deserial_map_no_length(#source, len as usize)?
                };
            }
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
        let size = format_ident!("u{}", 8 * l);
        if contains_attribute(&f.attrs, "skip_order_check") {
            quote! {
                let #ident = {
                    let len = #size::deserial(#source)?;
                    deserial_set_no_length_no_order_check(#source, len as usize)?
                };
            }
        } else {
            quote! {
                let #ident = {
                    let len = #size::deserial(#source)?;
                    deserial_set_no_length(#source, len as usize)?
                };
            }
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
        let size = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len = #size::deserial(#source)?;
                deserial_string(#source, len as usize)?
            };
        }
    } else {
        let ty = &f.ty;
        quote! {
            let #ident = <#ty as Deserial>::deserial(#source)?;
        }
    }
}

fn impl_deserial(ast: &syn::DeriveInput) -> TokenStream {
    let data_name = &ast.ident;

    let span = ast.span();

    let read_ident = format_ident!("__R", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let source_ident = Ident::new("source", Span::call_site());

    let body_tokens = match ast.data {
        syn::Data::Struct(ref data) => {
            let mut names = proc_macro2::TokenStream::new();
            let mut field_tokens = proc_macro2::TokenStream::new();
            let return_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    for field in data.fields.iter() {
                        let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                        field_tokens.extend(impl_deserial_field(
                            field,
                            &field_ident,
                            &source_ident,
                        ));
                        names.extend(quote!(#field_ident,))
                    }
                    quote!(Ok(#data_name{#names}))
                }
                syn::Fields::Unnamed(_) => {
                    for (i, f) in data.fields.iter().enumerate() {
                        let field_ident = format_ident!("x_{}", i);
                        field_tokens.extend(impl_deserial_field(f, &field_ident, &source_ident));
                        names.extend(quote!(#field_ident,))
                    }
                    quote!(Ok(#data_name(#names)))
                }
                _ => quote!(Ok(#data_name{})),
            };
            quote! {
                #field_tokens
                #return_tokens
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            let source = Ident::new("source", Span::call_site());
            let size = if data.variants.len() <= 256 {
                format_ident!("u8")
            } else {
                format_ident!("u16")
            };
            for (i, variant) in data.variants.iter().enumerate() {
                let mut field_tokens = proc_macro2::TokenStream::new();
                let mut names_tokens = proc_macro2::TokenStream::new();
                for (n, field) in variant.fields.iter().enumerate() {
                    let field_ident = format_ident!("x_{}", n);
                    names_tokens.extend(quote!(#field_ident,));
                    field_tokens.extend(impl_deserial_field(field, &field_ident, &source));
                }
                let idx_lit = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                let variant_ident = &variant.ident;
                let names_tokens = if variant.fields.is_empty() {
                    quote! {}
                } else {
                    quote! { (#names_tokens) }
                };
                matches_tokens.extend(quote! {
                    #idx_lit => {
                        #field_tokens
                        Ok(#data_name::#variant_ident#names_tokens)
                    },
                })
            }
            quote! {
                let idx = #size::deserial(#source)?;
                match idx {
                    #matches_tokens
                    _ => Err(Default::default())
                }
            }
        }
        _ => unimplemented!("#[derive(Deserial)] is not implemented for union."),
    };
    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics Deserial for #data_name #ty_generics #where_clauses {
            fn deserial<#read_ident: Read>(#source_ident: &mut #read_ident) -> Result<Self, #read_ident::Err> {
                #body_tokens
            }
        }
    };
    gen.into()
}

/// Derive the Serial trait.
/// Assumes every field of the data to implement Serial trait.
///
/// Collections are assumed to have a length within u32.
/// Optionally collection fields can be annotated with a size length to reduce
/// the serialized size (see also `derive(Deserial)`). The annotation for `Vec`
/// is `size_length`, `BTreeMap` is `map_size_length` and `BTreeSet` is
/// `set_size_length`.
///
/// The size length is specified as the number of bytes, and can be either of
/// the following numbers: 1, 2, 4, 8.
///
/// Note: The derived serialization for `BTreeMap` and `BTreeSet` ensures the
/// keys are ordered.
///
/// # Example
/// ```
/// #[derive(Serial)]
/// struct Foo {
///     #[set_size_length = 1]
///     bar: BTreeSet<u8>,
/// }
/// ```
#[proc_macro_derive(
    Serial,
    attributes(size_length, map_size_length, set_size_length, string_size_length)
)]
pub fn serial_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_serial(&ast)
}

fn impl_serial_field(
    f: &syn::Field,
    ident: &proc_macro2::TokenStream,
    out: &syn::Ident,
) -> proc_macro2::TokenStream {
    if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_vector_no_length(&#ident, #out)?;
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_map_no_length(&#ident, #out)?;
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_set_no_length(&#ident, #out)?;
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_string(#ident.as_str(), #out)?;
        }
    } else {
        quote! {
            #ident.serial(#out)?;
        }
    }
}

fn impl_serial(ast: &syn::DeriveInput) -> TokenStream {
    let data_name = &ast.ident;

    let span = ast.span();

    let write_ident = format_ident!("W", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let out_ident = format_ident!("out");

    let body = match ast.data {
        syn::Data::Struct(ref data) => {
            let mut field_tokens = proc_macro2::TokenStream::new();
            match data.fields {
                syn::Fields::Named(_) => {
                    for f in data.fields.iter() {
                        let field_ident = f.ident.clone().unwrap(); // safe since named fields.
                        let field_ident = quote!(self.#field_ident);
                        field_tokens.extend(impl_serial_field(f, &field_ident, &out_ident));
                    }
                }

                syn::Fields::Unnamed(_) => {
                    for (i, f) in data.fields.iter().enumerate() {
                        let i = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                        let field_ident = quote!(self.#i);
                        field_tokens.extend(impl_serial_field(f, &field_ident, &out_ident));
                    }
                }
                _ => (),
            };
            quote! {
                #field_tokens
                Ok(())
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            let size = if data.variants.len() <= 256 {
                format_ident!("u8")
            } else {
                format_ident!("u16")
            };
            for (i, variant) in data.variants.iter().enumerate() {
                let mut field_tokens = proc_macro2::TokenStream::new();
                let mut names_tokens = proc_macro2::TokenStream::new();
                for (n, field) in variant.fields.iter().enumerate() {
                    let field_ident = format_ident!("x_{}", n);
                    let field_ident = quote!(#field_ident);
                    names_tokens.extend(quote!(#field_ident,));
                    field_tokens.extend(impl_serial_field(field, &field_ident, &out_ident));
                }
                let idx_lit =
                    syn::LitInt::new(format!("{}{}", i, size).as_str(), Span::call_site());
                let variant_ident = &variant.ident;
                let names_tokens = if variant.fields.is_empty() {
                    quote! {}
                } else {
                    quote! { (#names_tokens) }
                };
                matches_tokens.extend(quote! {
                    #data_name::#variant_ident#names_tokens => {
                        #idx_lit.serial(#out_ident)?;
                        #field_tokens
                    },
                })
            }
            quote! {
                match self {
                    #matches_tokens
                }
                Ok(())
            }
        }
        _ => unimplemented!("#[derive(Serial)] is not implemented for union."),
    };

    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics Serial for #data_name #ty_generics #where_clauses {
            fn serial<#write_ident: Write>(&self, #out_ident: &mut #write_ident) -> Result<(), #write_ident::Err> {
                #body
            }
        }
    };
    gen.into()
}

/// Derive the Serial and Deserial trait.
/// Assumes every field of the data to implement Serial trait and Deserial
/// trait.
///
/// Collections are assumed to have a length within u32.
/// Optionally collection fields can be annotated with a size length to reduce
/// the serialized size (see `derive(Serial)` and `derive(Deserial)`).
/// The annotation for `Vec` is `size_length`, `BTreeMap` is `map_size_length`
/// and `BTreeSet` is `set_size_length`.
///
/// The size length is specified as the number of bytes, and can be either of
/// the following numbers: 1, 2, 4, 8.
///
/// Note: The derived serialization for `BTreeMap` and `BTreeSet` ensures the
/// keys are ordered.
///
/// # Example
/// ```
/// #[derive(Serialize)]
/// struct Foo {
///     #[set_size_length = 1]
///     #[skip_order_check]
///     bar: BTreeSet<u8>,
/// }
/// ```
#[proc_macro_derive(
    Serialize,
    attributes(
        size_length,
        map_size_length,
        set_size_length,
        string_size_length,
        skip_order_check
    )
)]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    let mut tokens = impl_deserial(&ast);
    tokens.extend(impl_serial(&ast));
    tokens
}
