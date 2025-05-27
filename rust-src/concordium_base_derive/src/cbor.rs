use crate::get_crate_root;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Data, DataStruct, Expr, Fields, FieldsNamed, LitStr, Member};

use darling::{FromDeriveInput, FromField};
use syn::spanned::Spanned;

#[derive(Debug, Default, FromField)]
#[darling(attributes(cbor))]
pub struct CborFieldOpts {
    /// Set key to be used for key in map. If not specified the field
    /// name in camelCase is used as a string literal for structs with named fields, and the tuple index
    /// is used for struct tuples.
    key: Option<Expr>,
}

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(cbor))]
pub struct CborOpts {
    /// For structs with a single field, if `true` the struct is serialized as the value
    /// of the single field.
    #[darling(default)]
    transparent: bool,
    /// Add CBOR tag to data item <https://www.rfc-editor.org/rfc/rfc8949.html#name-tagging-of-items>.
    tag: Option<Expr>,
}

#[derive(Debug)]
struct CborField {
    member: Member,
    opts: CborFieldOpts,
}

#[derive(Debug)]
struct CborFields(Vec<CborField>);

impl CborFields {
    /// Get fields as struct `Member`s
    fn members(&self) -> Vec<Member> {
        self.0.iter().map(|field| field.member.clone()).collect()
    }

    /// Get CBOR map keys for the fields
    fn cbor_map_keys(&self) -> syn::Result<Vec<TokenStream>> {
        let cbor_module = get_cbor_module()?;

        Ok(self
            .0
            .iter()
            .map(|field| {
                if let Some(key) = field.opts.key.as_ref() {
                    quote!(#cbor_module::MapKeyRef::Positive(#key))
                } else {
                    match &field.member {
                        Member::Named(ident) => {
                            let lit = LitStr::new(&ident.to_string(), field.member.span());
                            quote!(#cbor_module::MapKeyRef::Text(#lit))
                        }
                        Member::Unnamed(index) => {
                            let index = index.index as u64;
                            quote!(#cbor_module::MapKeyRef::Positive(#index))
                        }
                    }
                }
            })
            .collect())
    }
}

impl CborFields {
    fn try_from_fields(fields: &Fields) -> syn::Result<Self> {
        Ok(Self(
            fields
                .iter()
                .zip(fields.members())
                .map(|(field, member)| {
                    let opts = CborFieldOpts::from_field(field)?;

                    Ok(CborField { member, opts })
                })
                .collect::<syn::Result<Vec<_>>>()?,
        ))
    }
}

fn get_cbor_module() -> syn::Result<TokenStream> {
    let crate_root = get_crate_root()?;
    Ok(quote!(#crate_root::common::cbor))
}

#[derive(Debug, Clone, Copy)]
enum CborContainer {
    Array,
    Map,
}

fn cbor_deserialize_struct_body(fields: &Fields, opts: &CborOpts) -> syn::Result<TokenStream> {
    let cbor_module = get_cbor_module()?;

    let cbor_fields = CborFields::try_from_fields(fields)?;
    let field_idents = cbor_fields.members();

    if opts.transparent {
        let (Some(field_ident), None) = (field_idents.get(0), field_idents.get(1)) else {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(transparent) only valid for structs with a single field",
            ));
        };

        return Ok(match field_ident {
            Member::Named(field_ident) => {
                quote! {Ok(Self{#field_ident: #cbor_module::CborDeserialize::deserialize(decoder)?})}
            }
            Member::Unnamed(_) => {
                quote! {Ok(Self(#cbor_module::CborDeserialize::deserialize(decoder)?))}
            }
        });
    }

    let field_vars: Vec<_> = field_idents
        .iter()
        .map(|member| match member {
            Member::Named(ident) => ident.clone(),
            Member::Unnamed(index) => format_ident!("tmp{}", index),
        })
        .collect();

    let self_construct = match fields {
        Fields::Named(_) => {
            quote!(Self { #(#field_idents),* })
        }
        Fields::Unnamed(_) => {
            quote!(Self( #(#field_vars),* ))
        }
        Fields::Unit => {
            quote!(Self)
        }
    };

    let cbor_container = match fields {
        Fields::Named(_) => CborContainer::Map,
        Fields::Unnamed(_) => CborContainer::Array,
        Fields::Unit => CborContainer::Map,
    };

    Ok(match cbor_container {
        CborContainer::Array => {
            let field_count = field_idents.len();

            quote! {
                let array_size = #cbor_module::CborDecoder::decode_array_expect_length(decoder, #field_count)?;

                #(
                    let #field_vars = #cbor_module::CborDeserialize::deserialize(decoder)?;
                )*

                Ok(#self_construct)
            }
        }
        CborContainer::Map => {
            let field_map_keys = cbor_fields.cbor_map_keys()?;

            quote! {
                #(let mut #field_vars = None;)*
                let map_size = #cbor_module::CborDecoder::decode_map(decoder)?;
                for _ in 0..map_size {
                    let map_key: #cbor_module::MapKey = #cbor_module::CborDeserialize::deserialize(decoder)?;

                    match map_key.as_ref() {
                        #(
                            #field_map_keys => {
                                #field_vars = Some(#cbor_module::CborDeserialize::deserialize(decoder)?);
                            }
                        )*
                        key => return Err(#cbor_module::CborError::unknown_map_key(key)),
                    }
                }

                #(
                    let #field_vars = match #field_vars {
                        None => match #cbor_module::CborDeserialize::null() {
                            None => return Err(#cbor_module::CborError::map_value_missing(#field_map_keys)),
                            Some(null_value) => null_value,
                        },
                        Some(#field_vars) => #field_vars,
                    };
                )*

                Ok(#self_construct)
            }
        }
    })
}

pub fn impl_cbor_deserialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let deserialize_body = match &ast.data {
        Data::Struct(DataStruct { fields, .. }) => cbor_deserialize_struct_body(fields, &opts)?,
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborSerialize cannot be applied to enums",
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

fn cbor_serialize_struct_body(fields: &Fields, opts: &CborOpts) -> syn::Result<TokenStream> {
    let cbor_module = get_cbor_module()?;

    let cbor_fields = CborFields::try_from_fields(fields)?;
    let field_idents = cbor_fields.members();

    if opts.transparent {
        let (Some(field_ident), None) = (field_idents.get(0), field_idents.get(1)) else {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(transparent) only valid for structs with a single field",
            ));
        };

        return Ok(quote!(
            #cbor_module::CborSerialize::serialize(&self.#field_ident, encoder)
        ));
    }

    let cbor_container = match fields {
        Fields::Named(_) => CborContainer::Map,
        Fields::Unnamed(_) => CborContainer::Array,
        Fields::Unit => CborContainer::Map,
    };

    Ok(match cbor_container {
        CborContainer::Array => {
            let field_count = field_idents.len();

            quote! {
                #cbor_module::CborEncoder::encode_array(encoder,
                    #field_count
                )?;

                #(
                    #cbor_module::CborSerialize::serialize(&self.#field_idents, encoder)?;
                )*

                Ok(())
            }
        }
        CborContainer::Map => {
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
    })
}

pub fn impl_cbor_serialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let serialize_body = match &ast.data {
        Data::Struct(DataStruct { fields, .. }) => cbor_serialize_struct_body(fields, &opts)?,
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
