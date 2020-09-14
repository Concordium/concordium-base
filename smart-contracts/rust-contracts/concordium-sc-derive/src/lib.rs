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

#[proc_macro_derive(
    Deserial,
    attributes(size_length, map_size_length, set_size_length, string_size_length)
)]
pub fn deserial_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_deserial(&ast)
}

fn find_length_attribute(l: &[syn::Attribute], attr: &str) -> Option<u32> {
    let length = format_ident!("{}", attr);
    for attr in l.iter() {
        if let Ok(syn::Meta::NameValue(mn)) = attr.parse_meta() {
            if mn.path.is_ident(&length) {
                if let syn::Lit::Int(int) = mn.lit {
                    if let Ok(v) = int.base10_parse() {
                        if v == 1 || v == 2 || v == 4 || v == 8 {
                            return Some(v);
                        } else {
                            panic!("Length info must be a power of two between 1 and 8 inclusive.")
                        }
                    } else {
                        panic!("Unknown attribute value {}.", int);
                    }
                } else {
                    panic!("Unknown attribute value {:?}.", mn.lit);
                }
            }
        }
    }
    None
}

fn impl_deserial_field(
    f: &syn::Field,
    ident: &syn::Ident,
    source: &syn::Ident,
) -> proc_macro2::TokenStream {
    if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len: #id = #id::deserial(#source)?;
                deserial_vector_no_length(#source, usize::try_from(len)?)?
            };
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len: #id = #id::deserial(#source)?;
                deserial_map_no_length(#source, usize::try_from(len)?)?
            };
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len: #id = #id::deserial(#source)?;
                deserial_set_no_length(#source, usize::try_from(len)?)?
            };
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let #ident = {
                let len: #id = #id::deserial(#source)?;
                deserial_string(#source, usize::try_from(len)?)?
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
                _ => panic!("#[derive(Deserial)] not implemented for empty structs."),
            };
            quote! {
                #field_tokens
                #return_tokens
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            let source = Ident::new("source", Span::call_site());
            for (i, variant) in data.variants.iter().enumerate() {
                let mut field_tokens = proc_macro2::TokenStream::new();
                let mut names_tokens = proc_macro2::TokenStream::new();
                for (n, field) in variant.fields.iter().enumerate() {
                    let field_ident = Ident::new(
                        format!("{}Field{}", variant.ident, n).as_str(),
                        Span::call_site(),
                    );
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
                let idx = #source.read_u8()?;
                match idx {
                    #matches_tokens
                    _ => Err(Default::default())
                }
            }
        }
        _ => panic!("#[derive(Deserial)] only implemented for structs and enums."),
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
            serial_vector_no_length(&#ident, #out);
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_map_no_length(&#ident, #out);
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_set_no_length(&#ident, #out);
        }
    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
        let id = format_ident!("u{}", 8 * l);
        quote! {
            let len: #id = #ident.len() as #id;
            len.serial(#out)?;
            serial_string(#ident.as_str(), #out);
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
                _ => panic!("#[derive(Serial)] not implemented for empty structs."),
            };
            quote! {
                #field_tokens
                Ok(())
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            for (i, variant) in data.variants.iter().enumerate() {
                let mut field_tokens = proc_macro2::TokenStream::new();
                let mut names_tokens = proc_macro2::TokenStream::new();
                for (n, field) in variant.fields.iter().enumerate() {
                    let field_ident = Ident::new(
                        format!("{}Field{}", variant.ident, n).as_str(),
                        Span::call_site(),
                    );
                    let field_ident = quote!(#field_ident);
                    names_tokens.extend(quote!(#field_ident,));
                    field_tokens.extend(impl_serial_field(field, &field_ident, &out_ident));
                }
                let idx_lit = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                let variant_ident = &variant.ident;
                let names_tokens = if variant.fields.is_empty() {
                    quote! {}
                } else {
                    quote! { (#names_tokens) }
                };
                matches_tokens.extend(quote! {
                    #data_name::#variant_ident#names_tokens => {
                        #out_ident.write_u8(#idx_lit)?;
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
        _ => panic!("#[derive(Serial)] only implemented for structs."),
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

#[proc_macro_derive(
    Serialize,
    attributes(size_length, map_size_length, set_size_length, string_size_length)
)]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    let mut tokens = impl_deserial(&ast);
    tokens.extend(impl_serial(&ast));
    tokens
}
