use crate::get_crate_root;
use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DataStruct, Expr, Fields, LitStr, Member, Type, Variant};

use darling::{FromDeriveInput, FromField, FromVariant};
use syn::{punctuated::Punctuated, spanned::Spanned, token::Comma};

#[derive(Debug, Default, FromField)]
#[darling(attributes(cbor))]
pub struct CborFieldOpts {
    /// Set key to be used for key in map. If not specified the field
    /// name in camel case is used as key as a text data item.
    key:   Option<Expr>,
    /// Deserialize fields in CBOR map that is not present in the struct
    /// to the field with this attribute.
    #[darling(default)]
    other: bool,
}

#[derive(Debug, Default, FromVariant)]
#[darling(attributes(cbor))]
pub struct CborVariantOpts {
    /// Deserialize unknown variants in CBOR to the variant with this
    /// attribute.
    #[darling(default)]
    other:    bool,
    /// CBOR tag to add to data item in the variant.
    tag:      Option<Expr>,
    /// CBOR tag to use to decided which variant to deserialize to.
    /// The difference between specifying `cbor(tag)` and this attribute
    /// is that the tag is not serialized as part of serializing the variant
    /// but is expected be serialized by the variant value.
    peek_tag: Option<Expr>,
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
    #[darling(default)]
    map:         bool,
    /// Serialize enum as a tagged data item. Each variant but have a
    /// `cbor(tag)` attribute - except for at most one variant which can be
    /// untagged.
    #[darling(default)]
    tagged:      bool,
}

#[derive(Debug)]
struct CborField {
    member: Member,
    ty:     Type,
    opts:   CborFieldOpts,
}

#[derive(Debug)]
struct CborFields(Vec<CborField>);

impl CborFields {
    /// Get fields as struct `Member`s
    fn members(&self) -> Vec<Member> {
        self.0
            .iter()
            .filter(|field| !field.opts.other)
            .map(|field| field.member.clone())
            .collect()
    }

    /// Identifier for "other" variant
    fn other_member(&self) -> Option<(Type, Member)> {
        self.0
            .iter()
            .filter(|field| field.opts.other)
            .map(|field| (field.ty.clone(), field.member.clone()))
            .next()
    }

    /// Get CBOR map keys for the fields
    fn cbor_map_keys(&self) -> syn::Result<Vec<TokenStream>> {
        let cbor_module = get_cbor_module()?;

        Ok(self
            .0
            .iter()
            .filter(|field| !field.opts.other)
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
        let this = Self(
            fields
                .iter()
                .zip(fields.members())
                .map(|(field, member)| {
                    let opts = CborFieldOpts::from_field(field)?;
                    let ty = field.ty.clone();

                    Ok(CborField { member, opts, ty })
                })
                .collect::<syn::Result<Vec<_>>>()?,
        );
        if this.0.iter().filter(|field| field.opts.other).count() > 1 {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(other) can only be specified on a at most a single field",
            ));
        }

        Ok(this)
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

    /// Identifier for untagged variant
    fn untagged_ident(&self) -> Option<Ident> {
        self.0
            .iter()
            .filter(|field| {
                field.opts.tag.is_none() && field.opts.peek_tag.is_none() && !field.opts.other
            })
            .map(|field| field.ident.clone())
            .next()
    }

    /// Get tagged variants
    fn cbor_tagged_variants(&self) -> Vec<(Expr, Ident, Option<Expr>)> {
        self.0
            .iter()
            .filter(|field| !field.opts.other)
            .filter_map(|field| {
                Some((
                    field.opts.tag.clone().or(field.opts.peek_tag.clone())?,
                    field.ident.clone(),
                    field.opts.tag.clone(),
                ))
            })
            .collect()
    }
}

impl CborVariants {
    fn try_from_variants(
        opts: &CborOpts,
        variants: &Punctuated<Variant, Comma>,
    ) -> syn::Result<Self> {
        let this = Self(
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
        );
        for variant in &this.0 {
            if variant.opts.tag.is_some() && variant.opts.peek_tag.is_some() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "Cannot specify both cbor(tag) and cbor(peek_tag)",
                ));
            }
            if variant.opts.other && (variant.opts.tag.is_some() || variant.opts.peek_tag.is_some())
            {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "Cannot specify both cbor(tag) and cbor(other)",
                ));
            }
        }
        if this.0.iter().filter(|variant| variant.opts.other).count() > 1 {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(other) can only be specified on a at most a single variant",
            ));
        }
        if opts.tagged
            && this
                .0
                .iter()
                .filter(|variant| {
                    variant.opts.tag.is_none()
                        && variant.opts.peek_tag.is_none()
                        && !variant.opts.other
                })
                .count()
                > 1
        {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(tag) must be specified on all except at most one variant",
            ));
        }
        Ok(this)
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
    if opts.tagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(tagged)] only valid for enums",
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
            let mut field_idents_with_other = field_idents.clone();
            if let Some((_, other_ident)) = cbor_fields.other_member() {
                field_idents_with_other.push(other_ident);
            }

            quote!(Self { #(#field_idents_with_other),* })
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
                let mut array_decoder = #cbor_module::CborDecoder::decode_array_expect_size(decoder, #field_count)?;

                #(
                    let Some(#field_vars) = #cbor_module::CborArrayDecoder::deserialize_element(&mut array_decoder)? else {
                        return Err(#cbor_module::__private::anyhow::anyhow!("expected array element since size has already been checked to match field count").into());
                    };
                )*

                Ok(#self_construct)
            }
        }
        CborContainer::Map => {
            let field_map_keys = cbor_fields.cbor_map_keys()?;

            let other_field_declare = if let Some((ty, other_ident)) = cbor_fields.other_member() {
                quote! {
                    let mut #other_ident = <#ty>::default();
                }
            } else {
                quote! {}
            };

            let unknown_key_deserialize = if let Some((_, other_ident)) = cbor_fields.other_member()
            {
                quote! {
                    #other_ident.extend(Some((
                        #cbor_module::__private::anyhow::Context::context(map_key.try_into(), "cannot convert MapKey to declared key")?,
                        #cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?
                    )));
                }
            } else {
                quote! {
                    match options.unknown_map_keys {
                        #cbor_module::UnknownMapKeys::Fail => return Err(#cbor_module::CborSerializationError::unknown_map_key(map_key.as_ref())),
                        #cbor_module::UnknownMapKeys::Ignore => #cbor_module::CborMapDecoder::skip_value(&mut map_decoder)?,
                    }
                }
            };

            quote! {
                let options = decoder.options();
                #(let mut #field_vars = None;)*
                let mut map_decoder = #cbor_module::CborDecoder::decode_map(decoder)?;

                #other_field_declare

                while let Some(map_key) = #cbor_module::CborMapDecoder::deserialize_key::<#cbor_module::MapKey>(&mut map_decoder)? {
                    match map_key.as_ref() {
                        #(
                            #field_map_keys => {
                                #field_vars = Some(#cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?);
                            }
                        )*
                        _ => {
                            #unknown_key_deserialize
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

    if opts.map && opts.tagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "Both #[cbor(map)] and #[cbor(tagged)] cannot be specified",
        ));
    }

    let cbor_module = get_cbor_module()?;
    let cbor_variants = CborVariants::try_from_variants(opts, variants)?;

    Ok(if opts.map {
        let variant_idents = cbor_variants.variant_idents();
        let variant_map_keys = cbor_variants.cbor_map_keys();

        let deserialize_unknown = if let Some(other_ident) = cbor_variants.other_ident() {
            quote! {
                Self::#other_ident(key.into(), #cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?)
            }
        } else {
            quote! {
                return Err(#cbor_module::CborSerializationError::unknown_map_key(#cbor_module::MapKeyRef::Text(&key)));
            }
        };

        quote! {
            let mut map_decoder = decoder.decode_map_expect_size(1)?;

            let Some(key): Option<String> = #cbor_module::CborMapDecoder::deserialize_key(&mut map_decoder)? else {
                return Err(#cbor_module::__private::anyhow::anyhow!("expected an array element since size has already been checked to be 1").into());
            };

            Ok(match key.as_str() {
                #(
                    #variant_map_keys => {
                        Self::#variant_idents(#cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?)
                    }
                )*
                _ => {
                    #deserialize_unknown
                }
            })
        }
    } else if opts.tagged {
        let tagged_variant_idents = cbor_variants
            .cbor_tagged_variants()
            .into_iter()
            .map(|(_, ident, _)| ident)
            .collect::<Vec<_>>();

        let tagged_variant_tags = cbor_variants
            .cbor_tagged_variants()
            .into_iter()
            .map(|(tag, _, _)| tag)
            .collect::<Vec<_>>();

        let deserialize_variant_tags = cbor_variants
            .cbor_tagged_variants()
            .into_iter()
            .map(|(_, _, tag)| {
                let tag = tag.into_iter();
                quote! {
                    #(
                        #cbor_module::CborDecoder::decode_tag_expect(&mut decoder, #tag)?;
                    )*
                }
            })
            .collect::<Vec<_>>();

        let deserialize_untagged = if let Some(untagged_ident) = cbor_variants.untagged_ident() {
            quote! {
                Self::#untagged_ident(#cbor_module::CborDeserialize::deserialize(decoder)?)
            }
        } else {
            quote! {
                return Err(#cbor_module::__private::anyhow::anyhow!("Tag needed to deserialize to enum, no tag specified").into());
            }
        };

        let deserialize_unknown = if let Some(other_ident) = cbor_variants.other_ident() {
            quote! {
                Self::#other_ident(tag, #cbor_module::CborDeserialize::deserialize(decoder)?)
            }
        } else {
            quote! {
                return Err(#cbor_module::__private::anyhow::anyhow!("Tag {} not among declared variants", tag).into());
            }
        };

        quote! {
            Ok(match #cbor_module::CborDecoder::peek_data_item_header(&mut decoder)? {
                #(
                    #cbor_module::DataItemHeader::Tag(#tagged_variant_tags) => {
                        #deserialize_variant_tags;
                        Self::#tagged_variant_idents(#cbor_module::CborDeserialize::deserialize(decoder)?)
                    }
                )*
                #cbor_module::DataItemHeader::Tag(tag) => {
                    #cbor_module::CborDecoder::decode_tag_expect(&mut decoder, tag)?;
                    #deserialize_unknown
                }
                _ => {
                    #deserialize_untagged
                }
            })
        }
    } else {
        return Err(syn::Error::new(
            Span::call_site(),
            "Either #[cbor(map)] or #[cbor(tagged)] must be specified for enums",
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
            #cbor_module::CborDecoder::decode_tag_expect(&mut decoder, #tag)?;
        )
    } else {
        quote!()
    };

    Ok(quote! {
        impl #impl_generics #cbor_module::CborDeserialize for #name #ty_generics #where_clauses {
            fn deserialize<C: #cbor_module::CborDecoder>(mut decoder: C) -> #cbor_module::CborSerializationResult<Self> {
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
    if opts.tagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "#[cbor(tagged)] only valid for enums",
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

            let other_ident = cbor_fields.other_member().into_iter().map(|other| other.1);

            let other_field_size = if let Some((_, other_ident)) = cbor_fields.other_member() {
                quote! {
                    self.#other_ident.len()
                }
            } else {
                quote! { 0 }
            };

            let non_null_field_count = if field_idents.is_empty() {
                quote! { 0 }
            } else {
                quote! {
                    #(if #cbor_module::CborSerialize::is_null(&self.#field_idents) {0} else {1})+*
                }
            };

            quote! {
                let mut map_encoder = #cbor_module::CborEncoder::encode_map(encoder,
                    #non_null_field_count
                      + #other_field_size
                )?;

                #(
                    if !#cbor_module::CborSerialize::is_null(&self.#field_idents) {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, &#field_map_keys, &self.#field_idents)?;
                    }
                )*

                #(
                    for (key, value) in self.#other_ident.iter() {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, key, value)?;
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

    if opts.map && opts.tagged {
        return Err(syn::Error::new(
            Span::call_site(),
            "Both #[cbor(map)] and #[cbor(tagged)] cannot be specified",
        ));
    }

    let cbor_module = get_cbor_module()?;
    let cbor_variants = CborVariants::try_from_variants(opts, variants)?;
    let variant_idents = cbor_variants.variant_idents();

    Ok(if opts.map {
        let variant_map_keys = cbor_variants.cbor_map_keys();

        let other_ident = cbor_variants.other_ident().into_iter();

        quote! {
            let mut map_encoder = encoder.encode_map(1)?;
            match self {
                #(
                    Self::#variant_idents(value) => {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, #variant_map_keys, value)?;
                    }
                )*
                #(
                    Self::#other_ident(key, value) => {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, key, value)?;
                    }
                )*
            }
            #cbor_module::CborMapEncoder::end(map_encoder)
        }
    } else if opts.tagged {
        let tagged_variant_idents = cbor_variants
            .cbor_tagged_variants()
            .into_iter()
            .map(|(_, ident, _)| ident)
            .collect::<Vec<_>>();

        let serialize_variant_tags = cbor_variants
            .cbor_tagged_variants()
            .into_iter()
            .map(|(_, _, tag)| {
                let tag = tag.into_iter();
                quote! {
                    #(
                        #cbor_module::CborEncoder::encode_tag(&mut encoder, #tag)?;
                    )*
                }
            })
            .collect::<Vec<_>>();

        let untagged_ident = cbor_variants.untagged_ident().clone().into_iter();
        let other_ident = cbor_variants.other_ident().clone().into_iter();

        quote! {
            match self {
                #(
                    Self::#tagged_variant_idents(value) => {
                        #serialize_variant_tags
                        #cbor_module::CborSerialize::serialize(value, encoder)?;
                    }
                )*
                #(
                    Self::#other_ident(tag, value) => {
                        #cbor_module::CborEncoder::encode_tag(&mut encoder, *tag)?;
                        #cbor_module::CborSerialize::serialize(value, encoder)?;
                    }
                )*
                #(
                    Self::#untagged_ident(value) => {
                        #cbor_module::CborSerialize::serialize(value, encoder)?;
                    }
                )*
            }
            Ok(())
        }
    } else {
        return Err(syn::Error::new(
            Span::call_site(),
            "Either #[cbor(map)] or #[cbor(tagged)] must be specified for enums",
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
