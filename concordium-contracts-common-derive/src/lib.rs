// #![no_std]
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::ToTokens;

use syn::{parse_macro_input, spanned::Spanned, Ident, Meta};

/// The prefix used in field attributes: `#[concordium(attr = "something")]`
const CONCORDIUM_ATTRIBUTE: &str = "concordium";

/// A list of valid concordium field attributes
const VALID_CONCORDIUM_FIELD_ATTRIBUTES: [&str; 3] = ["size_length", "ensure_ordered", "rename"];

/// A list of valid concordium attributes
const VALID_CONCORDIUM_ATTRIBUTES: [&str; 1] = ["state_parameter"];

#[cfg(feature = "sdk")]
fn get_root() -> proc_macro2::TokenStream {
    quote!(concordium_rust_sdk::types::smart_contracts::concordium_contracts_common)
}

#[cfg(not(feature = "sdk"))]
fn get_root() -> proc_macro2::TokenStream { quote!(concordium_std) }

/// A helper to report meaningful compilation errors
/// - If applied to an Ok value they simply return the underlying value.
/// - If applied to `Err(e)` then `e` is turned into a compiler error.
fn unwrap_or_report(v: syn::Result<TokenStream>) -> TokenStream {
    match v {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error().into(),
    }
}

// Return whether a attribute item is present.
fn contains_attribute<'a, I: IntoIterator<Item = &'a Meta>>(iter: I, name: &str) -> bool {
    iter.into_iter().any(|attr| attr.path().is_ident(name))
}

/// Finds concordium field attributes.
fn get_concordium_field_attributes(attributes: &[syn::Attribute]) -> syn::Result<Vec<syn::Meta>> {
    get_concordium_attributes(attributes, true)
}

/// Finds concordium attributes, either field or general attributes.
fn get_concordium_attributes(
    attributes: &[syn::Attribute],
    for_field: bool,
) -> syn::Result<Vec<syn::Meta>> {
    let (valid_attributes, attribute_type) = if for_field {
        (&VALID_CONCORDIUM_FIELD_ATTRIBUTES[..], "concordium field attribute")
    } else {
        (&VALID_CONCORDIUM_ATTRIBUTES[..], "concordium attribute")
    };

    attributes
        .iter()
        // Keep only concordium attributes
        .flat_map(|attr| match attr.parse_meta() {
            Ok(syn::Meta::List(list)) if list.path.is_ident(CONCORDIUM_ATTRIBUTE) => {
                list.nested
            }
            _ => syn::punctuated::Punctuated::new(),
        })
        // Ensure only valid attributes and unwrap NestedMeta
        .map(|nested| match nested {
            syn::NestedMeta::Meta(meta) => {
                let path = meta.path();
                if valid_attributes.iter().any(|&attr| path.is_ident(attr)) {
                    Ok(meta)
                } else {
                    Err(syn::Error::new(meta.span(),
                        format!("The attribute '{}' is not supported as a {}.",
                        path.to_token_stream(), attribute_type)
                    ))
                }
            }
            lit => Err(syn::Error::new(lit.span(), format!("Literals are not supported in a {}.", attribute_type))),
        })
        .collect()
}

fn find_field_attribute_value(
    attributes: &[syn::Attribute],
    target_attr: &str,
) -> syn::Result<Option<syn::Lit>> {
    find_attribute_value(attributes, true, target_attr)
}

fn find_attribute_value(
    attributes: &[syn::Attribute],
    for_field: bool,
    target_attr: &str,
) -> syn::Result<Option<syn::Lit>> {
    let target_attr = format_ident!("{}", target_attr);
    let attr_values: Vec<_> = get_concordium_attributes(attributes, for_field)?
        .into_iter()
        .filter_map(|nested_meta| match nested_meta {
            syn::Meta::NameValue(value) if value.path.is_ident(&target_attr) => Some(value.lit),
            _ => None,
        })
        .collect();
    if attr_values.is_empty() {
        return Ok(None);
    }
    if attr_values.len() > 1 {
        let mut init_error = syn::Error::new(
            attr_values[1].span(),
            format!("Attribute '{}' should only be specified once.", target_attr),
        );
        for other in attr_values.iter().skip(2) {
            init_error.combine(syn::Error::new(
                other.span(),
                format!("Attribute '{}' should only be specified once.", target_attr),
            ))
        }
        Err(init_error)
    } else {
        Ok(Some(attr_values[0].clone()))
    }
}

fn find_length_attribute(attributes: &[syn::Attribute]) -> syn::Result<Option<u32>> {
    let value = match find_field_attribute_value(attributes, "size_length")? {
        Some(v) => v,
        None => return Ok(None),
    };

    // Save the span to be used in errors.
    let value_span = value.span();

    let value = match value {
        syn::Lit::Int(int) => int,
        _ => return Err(syn::Error::new(value_span, "Length attribute value must be an integer.")),
    };
    let value = match value.base10_parse() {
        Ok(v) => v,
        _ => {
            return Err(syn::Error::new(
                value_span,
                "Length attribute value must be a base 10 integer.",
            ))
        }
    };
    match value {
        1 | 2 | 4 | 8 => Ok(Some(value)),
        _ => Err(syn::Error::new(value_span, "Length info must be either 1, 2, 4, or 8.")),
    }
}

fn impl_deserial_field(
    f: &syn::Field,
    ident: &syn::Ident,
    source: &syn::Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    let concordium_attributes = get_concordium_field_attributes(&f.attrs)?;
    let ensure_ordered = contains_attribute(&concordium_attributes, "ensure_ordered");
    let size_length = find_length_attribute(&f.attrs)?;
    let has_ctx = ensure_ordered || size_length.is_some();
    let ty = &f.ty;
    let root = get_root();

    if has_ctx {
        // Default size length is u32, i.e. 4 bytes.
        let l = format_ident!("U{}", 8 * size_length.unwrap_or(4));

        Ok(quote! {
            let #ident = <#ty as #root::DeserialCtx>::deserial_ctx(#root::schema::SizeLength::#l, #ensure_ordered, #source)?;
        })
    } else {
        Ok(quote! {
            let #ident = <#ty as #root::Deserial>::deserial(#source)?;
        })
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
    unwrap_or_report(impl_deserial(&ast))
}

fn impl_deserial(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;

    let span = ast.span();

    let read_ident = format_ident!("__R", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let source_ident = Ident::new("________________source", Span::call_site());
    let root = get_root();

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
            let source = Ident::new("________________source", Span::call_site());
            let size = if data.variants.len() <= 256 {
                format_ident!("u8")
            } else if data.variants.len() <= 256 * 256 {
                format_ident!("u16")
            } else {
                return Err(syn::Error::new(
                    ast.span(),
                    "[derive(Deserial)]: Too many variants. Maximum 65536 are supported.",
                ));
            };
            for (i, variant) in data.variants.iter().enumerate() {
                let (field_names, pattern) = match variant.fields {
                    syn::Fields::Named(_) => {
                        let field_names: Vec<_> = variant
                            .fields
                            .iter()
                            .map(|field| field.ident.clone().unwrap())
                            .collect();
                        (field_names.clone(), quote! { {#(#field_names),*} })
                    }
                    syn::Fields::Unnamed(_) => {
                        let field_names: Vec<_> = variant
                            .fields
                            .iter()
                            .enumerate()
                            .map(|(i, _)| format_ident!("x_{}", i))
                            .collect();
                        (field_names.clone(), quote! { ( #(#field_names),* ) })
                    }
                    syn::Fields::Unit => (Vec::new(), proc_macro2::TokenStream::new()),
                };

                let field_tokens: proc_macro2::TokenStream = field_names
                    .iter()
                    .zip(variant.fields.iter())
                    .map(|(name, field)| impl_deserial_field(field, name, &source))
                    .collect::<syn::Result<proc_macro2::TokenStream>>()?;
                let idx_lit = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                let variant_ident = &variant.ident;
                matches_tokens.extend(quote! {
                    #idx_lit => {
                        #field_tokens
                        Ok(#data_name::#variant_ident#pattern)
                    },
                })
            }
            quote! {
                let idx = <#size as #root::Deserial>::deserial(#source)?;
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
        impl #impl_generics #root::Deserial for #data_name #ty_generics #where_clauses {
            fn deserial<#read_ident: #root::Read>(#source_ident: &mut #read_ident) -> #root::ParseResult<Self> {
                #body_tokens
            }
        }
    };
    Ok(gen.into())
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
    unwrap_or_report(impl_serial(&ast))
}

fn impl_serial_field(
    field: &syn::Field,
    ident: &proc_macro2::TokenStream,
    out: &syn::Ident,
) -> syn::Result<proc_macro2::TokenStream> {
    let root = get_root();

    if let Some(size_length) = find_length_attribute(&field.attrs)? {
        let l = format_ident!("U{}", 8 * size_length);
        Ok(quote!({
            #root::SerialCtx::serial_ctx(#ident, #root::schema::SizeLength::#l, #out)?;
        }))
    } else {
        Ok(quote! {
            #root::Serial::serial(#ident, #out)?;
        })
    }
}

fn impl_serial(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;

    let span = ast.span();

    let write_ident = format_ident!("W", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let out_ident = format_ident!("out");
    let root = get_root();

    let body = match ast.data {
        syn::Data::Struct(ref data) => {
            let fields_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    data.fields
                        .iter()
                        .map(|field| {
                            let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                            let field_ident = quote!(&self.#field_ident);
                            impl_serial_field(field, &field_ident, &out_ident)
                        })
                        .collect::<syn::Result<_>>()?
                }
                syn::Fields::Unnamed(_) => data
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(i, field)| {
                        let i = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                        let field_ident = quote!(&self.#i);
                        impl_serial_field(field, &field_ident, &out_ident)
                    })
                    .collect::<syn::Result<_>>()?,
                syn::Fields::Unit => proc_macro2::TokenStream::new(),
            };
            quote! {
                #fields_tokens
                Ok(())
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();

            let size = if data.variants.len() <= 256 {
                format_ident!("u8")
            } else if data.variants.len() <= 256 * 256 {
                format_ident!("u16")
            } else {
                unimplemented!(
                    "[derive(Serial)]: Enums with more than 65536 variants are not supported."
                );
            };

            for (i, variant) in data.variants.iter().enumerate() {
                let (field_names, pattern) = match variant.fields {
                    syn::Fields::Named(_) => {
                        let field_names: Vec<_> = variant
                            .fields
                            .iter()
                            .map(|field| field.ident.clone().unwrap())
                            .collect();
                        (field_names.clone(), quote! { {#(#field_names),*} })
                    }
                    syn::Fields::Unnamed(_) => {
                        let field_names: Vec<_> = variant
                            .fields
                            .iter()
                            .enumerate()
                            .map(|(i, _)| format_ident!("x_{}", i))
                            .collect();
                        (field_names.clone(), quote! { (#(#field_names),*) })
                    }
                    syn::Fields::Unit => (Vec::new(), proc_macro2::TokenStream::new()),
                };
                let field_tokens: proc_macro2::TokenStream = field_names
                    .iter()
                    .zip(variant.fields.iter())
                    .map(|(name, field)| impl_serial_field(field, &quote!(#name), &out_ident))
                    .collect::<syn::Result<_>>()?;

                let idx_lit =
                    syn::LitInt::new(format!("{}{}", i, size).as_str(), Span::call_site());
                let variant_ident = &variant.ident;

                matches_tokens.extend(quote! {
                    #data_name::#variant_ident#pattern => {
                        #root::Serial::serial(&#idx_lit, #out_ident)?;
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
        impl #impl_generics #root::Serial for #data_name #ty_generics #where_clauses {
            fn serial<#write_ident: #root::Write>(&self, #out_ident: &mut #write_ident) -> Result<(), #write_ident::Err> {
                #body
            }
        }
    };
    Ok(gen.into())
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
    let mut tokens = impl_deserial(&ast)?;
    tokens.extend(impl_serial(&ast)?);
    Ok(tokens)
}
