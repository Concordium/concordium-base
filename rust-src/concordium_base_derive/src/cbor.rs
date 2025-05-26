use crate::get_crate_root;
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{Data, DataStruct, Expr, Fields, FieldsNamed, LitStr};

use darling::{FromDeriveInput, FromField};

#[derive(Debug, Default, FromField)]
#[darling(attributes(cbor))]
pub struct CborFieldOpts {
    key: Option<Expr>,
}

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(cbor))]
pub struct CborOpts {
    #[darling(default)]
    transparent: bool,
    tag:         Option<Expr>,
}

#[derive(Debug)]
struct CborField {
    ident: Ident,
    opts:  CborFieldOpts,
}

#[derive(Debug)]
struct CborFields(Vec<CborField>);

impl CborFields {
    fn idents(&self) -> Vec<Ident> { self.0.iter().map(|field| field.ident.clone()).collect() }

    fn cbor_map_keys(&self) -> syn::Result<Vec<TokenStream>> {
        let cbor_module = get_cbor_module()?;

        Ok(self
            .0
            .iter()
            .map(|field| {
                if let Some(key) = field.opts.key.as_ref() {
                    quote!(#cbor_module::MapKeyRef::Positive(#key))
                } else {
                    let lit = LitStr::new(&field.ident.to_string(), field.ident.span());
                    quote!(#cbor_module::MapKeyRef::Text(#lit))
                }
            })
            .collect())
    }
}

impl CborFields {
    fn try_from_named_fields(fields: &FieldsNamed) -> syn::Result<Self> {
        Ok(Self(
            fields
                .named
                .iter()
                .map(|field| {
                    let ident = field
                        .ident
                        .clone()
                        .ok_or(syn::Error::new_spanned(field, "unnamed field"))?;

                    let opts = CborFieldOpts::from_field(&field)?;

                    Ok(CborField { ident, opts })
                })
                .collect::<syn::Result<Vec<_>>>()?,
        ))
    }
}

fn get_cbor_module() -> syn::Result<TokenStream> {
    let crate_root = get_crate_root()?;
    Ok(quote!(#crate_root::common::cbor))
}

pub fn impl_cbor_deserialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let deserialize_body = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields_named),
            ..
        }) => {
            if opts.transparent {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "cbor(transparent) attribute only valid for tuple structs",
                ));
            }

            let cbor_fields = CborFields::try_from_named_fields(fields_named)?;
            let field_idents = cbor_fields.idents();
            let field_map_keys = cbor_fields.cbor_map_keys()?;

            quote! {
                #(let mut #field_idents = None;)*
                let map_size = #cbor_module::CborDecoder::decode_map(decoder)?;
                for _ in 0..map_size {
                    let map_key: #cbor_module::MapKey = #cbor_module::CborDeserialize::deserialize(decoder)?;

                    match map_key.as_ref() {
                        #(
                            #field_map_keys => {
                                #field_idents = Some(#cbor_module::CborDeserialize::deserialize(decoder)?);
                            }
                        )*
                        key => return Err(#cbor_module::CborError::unknown_map_key(key)),
                    }
                }

                #(
                    let #field_idents = match #field_idents {
                        None => match #cbor_module::CborDeserialize::null() {
                            None => return Err(#cbor_module::CborError::map_value_missing(#field_map_keys)),
                            Some(null_value) => null_value,
                        },
                        Some(#field_idents) => #field_idents,
                    };
                )*

                Ok(Self { #(#field_idents),* })
            }
        }
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(fields_unnamed),
            ..
        }) => {
            if !opts.transparent {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "tuple structs must have attribute cbor(transparent)",
                ));
            }

            if fields_unnamed.unnamed.len() != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "tuple structs must exactly one element",
                ));
            };

            quote!(
                Ok(Self(#cbor_module::CborDeserialize::deserialize(decoder)?))
            )
        }
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborSerialize cannot be applied to enums or unit structs",
            ))
        }
    };

    let decode_tag = if let Some(tag) = opts.tag {
        quote!(
            #cbor_module::CborDecoder::decode_tag_expect(decoder, #tag)?;
        )
    } else {
        quote!()
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborDeserialize for #name #ty_generics #where_clauses {
            fn deserialize<C: #cbor_module::CborDecoder>(decoder: &mut C) -> #cbor_module::CborResult<Self> {
                #decode_tag
                #deserialize_body
            }
        }
    })
}

pub fn impl_cbor_serialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let serialize_body = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields_named),
            ..
        }) => {
            if opts.transparent {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "cbor(transparent) attribute only valid for tuple structs",
                ));
            }

            let cbor_fields = CborFields::try_from_named_fields(fields_named)?;
            let field_idents = cbor_fields.idents();
            let field_map_keys = cbor_fields.cbor_map_keys()?;

            quote! {
                #cbor_module::CborEncoder::encode_map(encoder,
                    #(if #cbor_module::CborSerialize::is_null(&self.#field_idents) {0} else {1})+*
                )?;

                #(
                    if !#cbor_module::CborSerialize::is_null(&self.#field_idents) {
                        #cbor_module::CborSerialize::serialize(&#field_map_keys, encoder)?;
                        #cbor_module::CborSerialize::serialize(&self.#field_idents, encoder)?;
                    }
                )*

                Ok(())
            }
        }
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(fields_unnamed),
            ..
        }) => {
            if !opts.transparent {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "tuple structs must have attribute cbor(transparent)",
                ));
            }

            if fields_unnamed.unnamed.len() != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "tuple structs must exactly one element",
                ));
            };

            quote!(
                #cbor_module::CborSerialize::serialize(&self.0, encoder)
            )
        }
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborSerialize cannot be applied to enums or unit structs",
            ))
        }
    };

    let encode_tag = if let Some(tag) = opts.tag {
        quote!(
            #cbor_module::CborEncoder::encode_tag(encoder, #tag)?;
        )
    } else {
        quote!()
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborSerialize for #name #ty_generics #where_clauses {
            fn serialize<C: #cbor_module::CborEncoder>(&self, encoder: &mut C) -> #cbor_module::CborResult<()> {
                #encode_tag
                #serialize_body
            }
        }
    })
}
