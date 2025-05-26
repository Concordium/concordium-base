use crate::get_crate_root;
use proc_macro2::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{Data, DataStruct, Fields, LitStr};

fn get_cbor_module() -> syn::Result<TokenStream> {
    let crate_root = get_crate_root()?;
    Ok(quote!(#crate_root::internal::cbor))
}

pub fn impl_cbor_deserialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let cbor_module = get_cbor_module()?;

    let deserialize_body = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields_named),
            ..
        }) => {
            struct Field {
                ident: Ident,
            }

            let fields = fields_named
                .named
                .iter()
                .map(|field| {
                    let ident = field
                        .ident
                        .clone()
                        .ok_or(syn::Error::new_spanned(field, "unnamed field"))?;

                    Ok(Field { ident })
                })
                .collect::<syn::Result<Vec<_>>>()?;

            let field_idents: Vec<_> = fields.iter().map(|field| &field.ident).collect();
            let field_idents_literals: Vec<_> = fields
                .iter()
                .map(|field| LitStr::new(&field.ident.to_string(), field.ident.span()))
                .collect();

            quote! {
                #(let mut #field_idents = None;)*
                let map_size = #cbor_module::CborDecoder::decode_map(decoder)?;
                for _ in 0..map_size {
                    let map_key: #cbor_module::MapKey = #cbor_module::CborDeserialize::deserialize(decoder)?;

                    match map_key.as_ref() {
                        #(
                            #cbor_module::MapKeyRef::Text(#field_idents_literals) => {
                                #field_idents = Some(#cbor_module::CborDeserialize::deserialize(decoder)?);
                            }
                        )*
                        key => return Err(#cbor_module::CborError::unknown_map_key(key)),
                    }
                }

                #(
                    let #field_idents = match #field_idents {
                        None => match #cbor_module::CborDeserialize::null() {
                            None => return Err(#cbor_module::CborError::map_value_missing(#cbor_module::MapKeyRef::Text(#field_idents_literals))),
                            Some(null_value) => null_value,
                        },
                        Some(#field_idents) => #field_idents,
                    };
                )*

                Ok(Self { #(#field_idents),* })
            }
        }
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborDeserialize can only be applied to structs with named fields",
            ))
        }
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborDeserialize for #name #ty_generics #where_clauses {
            fn deserialize<C: #cbor_module::CborDecoder>(decoder: &mut C) -> #cbor_module::CborResult<Self> {
                #deserialize_body
            }
        }
    })
}

pub fn impl_cbor_serialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let cbor_module = get_cbor_module()?;

    let serialize_body = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields_named),
            ..
        }) => {
            struct Field {
                ident: Ident,
            }

            let fields = fields_named
                .named
                .iter()
                .map(|field| {
                    let ident = field
                        .ident
                        .clone()
                        .ok_or(syn::Error::new_spanned(field, "unnamed field"))?;

                    Ok(Field { ident })
                })
                .collect::<syn::Result<Vec<_>>>()?;

            let field_idents: Vec<_> = fields.iter().map(|field| &field.ident).collect();
            let field_idents_literals: Vec<_> = fields
                .iter()
                .map(|field| LitStr::new(&field.ident.to_string(), field.ident.span()))
                .collect();

            quote! {
                #cbor_module::CborEncoder::encode_map(encoder,
                    #(if #cbor_module::CborSerialize::is_null(&self.#field_idents) {0} else {1})+*
                )?;

                #(
                    if !#cbor_module::CborSerialize::is_null(&self.#field_idents) {
                        #cbor_module::CborSerialize::serialize(&#cbor_module::MapKeyRef::Text(#field_idents_literals), encoder)?;
                        #cbor_module::CborSerialize::serialize(&self.#field_idents, encoder)?;
                    }
                )*

                Ok(())
            }
        }
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborSerialize can only be applied to structs with named fields",
            ))
        }
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborSerialize for #name #ty_generics #where_clauses {
            fn serialize<C: #cbor_module::CborEncoder>(&self, encoder: &mut C) -> #cbor_module::CborResult<()> {
                #serialize_body
            }
        }
    })
}
