use crate::get_crate_root;
use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DataStruct, Expr, Fields, LitStr, Member, Variant};

use darling::{FromDeriveInput, FromField, FromVariant};
use syn::{punctuated::Punctuated, spanned::Spanned, token::Comma};

#[derive(Debug, Default, FromField)]
#[darling(attributes(cbor))]
pub struct CborFieldOpts {
    /// Set key to be used for key in map. If not specified the field
    /// name in camel case is used as key as a text data item.
    key: Option<Expr>,
}

#[derive(Debug, Default, FromVariant)]
#[darling(attributes(cbor))]
pub struct CborVariantOpts {
    /// Serialize unknown variants in CBOR to the enum with this
    /// attribute. Serialization of the variant always fails
    #[darling(default)]
    other: bool,
}

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(cbor))]
pub struct CborOpts {
    /// For structs with a single field, if `true` the struct is serialized as
    /// the value of the single field.
    #[darling(default)]
    transparent: bool,
    /// Add CBOR tag to data item <https://www.rfc-editor.org/rfc/rfc8949.html#name-tagging-of-items>.
    tag:         Option<Expr>,
    /// Serialize enum as a map with a single entry. The variant
    /// name in camel case is used as the key as a text data item.
    ///
    /// This option is here because we want to extend with tagged enum encodings
    /// also at some point. So you can use either `map` or `tagged`.
    #[darling(default)]
    map:         bool,
}

#[derive(Debug)]
struct CborField {
    member: Member,
    opts:   CborFieldOpts,
}

#[derive(Debug)]
struct CborFields(Vec<CborField>);

impl CborFields {
    /// Get fields as struct `Member`s
    fn members(&self) -> Vec<Member> { self.0.iter().map(|field| field.member.clone()).collect() }

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
                            let lit = LitStr::new(
                                &ident.to_string().to_case(Case::Camel),
                                field.member.span(),
                            );
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

#[derive(Debug)]
struct CborVariant {
    ident: Ident,
    opts:  CborVariantOpts,
}

#[derive(Debug)]
struct CborVariants(Vec<CborVariant>);

impl CborVariants {
    /// Get identifiers for variants in enum
    fn variant_idents(&self) -> Vec<Ident> {
        self.0
            .iter()
            .filter(|field| !field.opts.other)
            .map(|field| field.ident.clone())
            .collect()
    }

    /// Identifier for "other" variant
    fn other_ident(&self) -> Option<Ident> {
        self.0
            .iter()
            .filter(|field| field.opts.other)
            .map(|field| field.ident.clone())
            .next()
    }

    /// Get CBOR map keys for the variants
    fn cbor_map_keys(&self) -> Vec<LitStr> {
        self.0
            .iter()
            .filter(|field| !field.opts.other)
            .map(|field| {
                LitStr::new(
                    &field.ident.to_string().to_case(Case::Camel),
                    field.ident.span(),
                )
            })
            .collect()
    }
}

impl CborVariants {
    fn try_from_variants(variants: &Punctuated<Variant, Comma>) -> syn::Result<Self> {
        Ok(Self(
            variants
                .iter()
                .map(|variant| {
                    let opts = CborVariantOpts::from_variant(variant)?;

                    Ok(CborVariant {
                        ident: variant.ident.clone(),
                        opts,
                    })
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
    if opts.map {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(map)] only valid for enums",
        ));
    }

    let cbor_module = get_cbor_module()?;

    let cbor_fields = CborFields::try_from_fields(fields)?;
    let field_idents = cbor_fields.members();

    if opts.transparent {
        #[allow(clippy::get_first)]
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
                let array_size = #cbor_module::CborDecoder::decode_array_header_expect_size(decoder, #field_count)?;

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
                let map_size = #cbor_module::CborDecoder::decode_map_header(decoder)?;
                for _ in 0..map_size {
                    let map_key: #cbor_module::MapKey = #cbor_module::CborDeserialize::deserialize(decoder)?;

                    match map_key.as_ref() {
                        #(
                            #field_map_keys => {
                                #field_vars = Some(#cbor_module::CborDeserialize::deserialize(decoder)?);
                            }
                        )*
                        key => {
                            match decoder.options().unknown_map_keys {
                                #cbor_module::UnknownMapKeys::Fail => return Err(#cbor_module::CborSerializationError::unknown_map_key(key)),
                                #cbor_module::UnknownMapKeys::Ignore => decoder.skip_data_item()?,
                            }

                        }
                    }
                }

                #(
                    let #field_vars = match #field_vars {
                        None => match #cbor_module::CborDeserialize::null() {
                            None => return Err(#cbor_module::CborSerializationError::map_value_missing(#field_map_keys)),
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

fn cbor_deserialize_enum_body(
    variants: &Punctuated<Variant, Comma>,
    opts: &CborOpts,
) -> syn::Result<TokenStream> {
    if opts.transparent {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(transparent)] only valid for structs",
        ));
    }

    Ok(if opts.map {
        let cbor_module = get_cbor_module()?;

        let cbor_variants = CborVariants::try_from_variants(variants)?;
        let variant_idents = cbor_variants.variant_idents();
        let variant_map_keys = cbor_variants.cbor_map_keys();

        let unknown_variant = if let Some(other_ident) = cbor_variants.other_ident() {
            quote! {
                decoder.skip_data_item()?;
                Self::#other_ident
            }
        } else {
            quote! {
                return Err(#cbor_module::CborSerializationError::unknown_map_key(#cbor_module::MapKeyRef::Text(key)));
            }
        };

        quote! {
            decoder.decode_map_header_expect_size(1)?;
            let key =
                    #cbor_module::__private::anyhow::Context::context(String::from_utf8(decoder.decode_text()?), "map key not valid UTF8")?;
            Ok(match key.as_str() {
                #(
                    #variant_map_keys => {
                        Self::#variant_idents(#cbor_module::CborDeserialize::deserialize(decoder)?)
                    }
                )*
                key => {
                    #unknown_variant
                }
            })
        }
    } else {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(map)] must be specified for enums",
        ));
    })
}

pub fn impl_cbor_deserialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let deserialize_body = match &ast.data {
        Data::Struct(DataStruct { fields, .. }) => cbor_deserialize_struct_body(fields, &opts)?,
        Data::Enum(DataEnum { variants, .. }) => cbor_deserialize_enum_body(variants, &opts)?,
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborDeserialize cannot be applied to unions",
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
            fn deserialize<C: #cbor_module::CborDecoder>(decoder: &mut C) -> #cbor_module::CborSerializationResult<Self> {
                #decode_tag
                #deserialize_body
            }
        }
    })
}

fn cbor_serialize_struct_body(fields: &Fields, opts: &CborOpts) -> syn::Result<TokenStream> {
    if opts.map {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(map)] only valid for enums",
        ));
    }

    let cbor_module = get_cbor_module()?;

    let cbor_fields = CborFields::try_from_fields(fields)?;
    let field_idents = cbor_fields.members();

    if opts.transparent {
        #[allow(clippy::get_first)]
        let (Some(field_ident), None) = (field_idents.get(0), field_idents.get(1)) else {
            return Err(syn::Error::new(
                Span::call_site(),
                "#[cbor(transparent)] only valid for structs with a single field",
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
                let mut array_encoder = #cbor_module::CborEncoder::encode_array(encoder,
                    #field_count
                )?;

                #(
                    #cbor_module::CborArrayEncoder::serialize_element(&mut array_encoder, &self.#field_idents)?;
                )*

                #cbor_module::CborArrayEncoder::end(array_encoder)?;

                Ok(())
            }
        }
        CborContainer::Map => {
            let field_map_keys = cbor_fields.cbor_map_keys()?;

            quote! {
                let mut map_encoder = #cbor_module::CborEncoder::encode_map(encoder,
                    #(if #cbor_module::CborSerialize::is_null(&self.#field_idents) {0} else {1})+*
                )?;

                #(
                    if !#cbor_module::CborSerialize::is_null(&self.#field_idents) {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, &#field_map_keys, &self.#field_idents)?;
                    }
                )*

                #cbor_module::CborMapEncoder::end(map_encoder)?;

                Ok(())
            }
        }
    })
}

fn cbor_serialize_enum_body(
    variants: &Punctuated<Variant, Comma>,
    opts: &CborOpts,
) -> syn::Result<TokenStream> {
    if opts.transparent {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(transparent)] only valid for structs",
        ));
    }

    Ok(if opts.map {
        let cbor_module = get_cbor_module()?;

        let cbor_variants = CborVariants::try_from_variants(variants)?;
        let variant_idents = cbor_variants.variant_idents();
        let variant_map_keys = cbor_variants.cbor_map_keys();

        let other_variant = if let Some(other_ident) = cbor_variants.other_ident() {
            quote! {
                Self::#other_ident => {
                    return Err(#cbor_module::__private::anyhow::anyhow!("cannot serialize variant marked with #[cbor(other)]").into());
                }
            }
        } else {
            quote! {}
        };

        quote! {
            let mut map_encoder = encoder.encode_map(1)?;
            match self {
                #(
                    Self::#variant_idents(value) => {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, #variant_map_keys, value)?;
                    }
                )*
                #other_variant
            }
            #cbor_module::CborMapEncoder::end(map_encoder)
        }
    } else {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(map)] must be specified for enums",
        ));
    })
}

pub fn impl_cbor_serialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let opts = CborOpts::from_derive_input(ast)?;

    let cbor_module = get_cbor_module()?;

    let serialize_body = match &ast.data {
        Data::Struct(DataStruct { fields, .. }) => cbor_serialize_struct_body(fields, &opts)?,
        Data::Enum(DataEnum { variants, .. }) => cbor_serialize_enum_body(variants, &opts)?,
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "CborSerialize cannot be applied to unions",
            ))
        }
    };

    let encode_tag = if let Some(tag) = opts.tag {
        quote!(
            #cbor_module::CborEncoder::encode_tag(&mut encoder, #tag)?;
        )
    } else {
        quote!()
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborSerialize for #name #ty_generics #where_clauses {
            fn serialize<C: #cbor_module::CborEncoder>(&self, mut encoder: C) -> #cbor_module::CborSerializationResult<()> {
                #encode_tag
                #serialize_body
            }
        }
    })
}
