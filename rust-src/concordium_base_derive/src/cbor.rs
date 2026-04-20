use crate::get_crate_root;
use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DataStruct, Expr, ExprLit, Fields, Lit, LitStr, Member, Type, Variant};

use darling::{FromDeriveInput, FromField, FromVariant};
use syn::{punctuated::Punctuated, spanned::Spanned, token::Comma};

#[derive(Debug, Clone)]
enum CborKey {
    Positive(Expr),
    Text(Expr),
}

impl darling::FromMeta for CborKey {
    fn from_expr(expr: &Expr) -> darling::Result<Self> {
        let key = if matches!(
            expr,
            Expr::Lit(ExprLit {
                lit: Lit::Str(_),
                ..
            })
        ) {
            CborKey::Text(expr.clone())
        } else {
            CborKey::Positive(expr.clone())
        };

        Ok(key)
    }
}

#[derive(Debug, Default, FromField)]
#[darling(attributes(cbor))]
pub struct CborFieldOpts {
    /// Set key to be used for key in map. If not specified the field
    /// name in camel case is used as key as a text data item.
    /// Can be either an integer (e.g., key = 1) for Positive key,
    /// or a string literal (e.g., key = "type") for Text key.
    key: Option<CborKey>,
    /// Deserialize fields in CBOR map that is not present in the struct
    /// to the field with this attribute.
    #[darling(default)]
    other: bool,
    /// Flatten the fields of an embedded CBOR map struct into the enclosing
    /// CBOR map.
    #[darling(default)]
    flatten: bool,
}

#[derive(Debug, Default, FromVariant)]
#[darling(attributes(cbor))]
pub struct CborVariantOpts {
    /// Deserialize unknown variants in CBOR to the variant with this
    /// attribute.
    #[darling(default)]
    other: bool,
    /// CBOR tag to add to data item in the variant.
    tag: Option<Expr>,
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
    tag: Option<Expr>,
    /// Serialize enum as a map with a single entry. The variant
    /// name in camel case is used as the key as a text data item.
    #[darling(default)]
    map: bool,
    /// Serialize enum as a tagged data item. Each variant but have a
    /// `cbor(tag)` attribute - except for at most one variant which can be
    /// untagged.
    #[darling(default)]
    tagged: bool,
}

#[derive(Debug)]
struct CborField {
    member: Member,
    ty: Type,
    opts: CborFieldOpts,
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

    fn non_flatten_members(&self) -> Vec<Member> {
        self.0
            .iter()
            .filter(|field| !field.opts.other && !field.opts.flatten)
            .map(|field| field.member.clone())
            .collect()
    }

    fn flatten_members(&self) -> Vec<Member> {
        self.0
            .iter()
            .filter(|field| !field.opts.other && field.opts.flatten)
            .map(|field| field.member.clone())
            .collect()
    }

    fn has_flatten_fields(&self) -> bool {
        self.0.iter().any(|field| field.opts.flatten)
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
            .filter(|field| !field.opts.other && !field.opts.flatten)
            .map(|field| {
                if let Some(key) = field.opts.key.as_ref() {
                    match key {
                        CborKey::Text(expr) => {
                            quote!(#cbor_module::MapKeyRef::Text(#expr))
                        }
                        CborKey::Positive(expr) => {
                            quote!(#cbor_module::MapKeyRef::Positive(#expr))
                        }
                    }
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

    fn cbor_map_owned_keys(&self) -> syn::Result<Vec<TokenStream>> {
        let cbor_module = get_cbor_module()?;

        Ok(self
            .0
            .iter()
            .filter(|field| !field.opts.other && !field.opts.flatten)
            .map(|field| {
                if let Some(key) = field.opts.key.as_ref() {
                    match key {
                        CborKey::Text(expr) => {
                            quote!(#cbor_module::MapKey::Text((#expr).to_string()))
                        }
                        CborKey::Positive(expr) => {
                            quote!(#cbor_module::MapKey::Positive(#expr))
                        }
                    }
                } else {
                    match &field.member {
                        Member::Named(ident) => {
                            let lit = LitStr::new(
                                &ident.to_string().to_case(Case::Camel),
                                field.member.span(),
                            );
                            quote!(#cbor_module::MapKey::Text((#lit).to_string()))
                        }
                        Member::Unnamed(index) => {
                            let index = index.index as u64;
                            quote!(#cbor_module::MapKey::Positive(#index))
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
        if this
            .0
            .iter()
            .any(|field| field.opts.flatten && field.opts.other)
        {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(flatten) cannot be combined with cbor(other)",
            ));
        }
        if this
            .0
            .iter()
            .any(|field| field.opts.flatten && field.opts.key.is_some())
        {
            return Err(syn::Error::new(
                Span::call_site(),
                "cbor(flatten) cannot be combined with cbor(key = ...)",
            ));
        }

        Ok(this)
    }
}

#[derive(Debug)]
struct CborVariant {
    ident: Ident,
    opts: CborVariantOpts,
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

/// Build local variable names used while deserializing struct fields.
///
/// Named fields reuse their field identifier, while tuple-style fields get a
/// synthetic binding such as `tmp0`.
fn cbor_member_binding_vars(members: &[Member]) -> Vec<Ident> {
    members
        .iter()
        .map(|member| match member {
            Member::Named(ident) => ident.clone(),
            Member::Unnamed(index) => format_ident!("tmp{}", index),
        })
        .collect()
}

/// Generate the local declaration for a `#[cbor(other)]` field, if present.
///
/// The generated variable accumulates unknown map entries during
/// deserialization and is initialized with `Default`.
fn cbor_other_field_declare_tokens(cbor_fields: &CborFields) -> TokenStream {
    if let Some((ty, other_ident)) = cbor_fields.other_member() {
        quote! {
            let mut #other_ident = <#ty>::default();
        }
    } else {
        quote! {}
    }
}

/// Generate the final unknown-key handling for flattened map decoding.
///
/// In the flattened case we first collect the full map into a temporary
/// `HashMap`, remove all known keys, and then either:
/// - move the remaining entries into the `#[cbor(other)]` field, or
/// - reject the first leftover key when unknown keys are configured to fail.
fn cbor_flattened_unknown_key_finish_tokens(
    cbor_fields: &CborFields,
    cbor_module: &TokenStream,
) -> TokenStream {
    if let Some((_, other_ident)) = cbor_fields.other_member() {
        quote! {
            #other_ident.extend(map_values.into_iter().map(|(key, value)| {
                Ok((
                    #cbor_module::__private::anyhow::Context::context(key.try_into(), "cannot convert MapKey to declared key")?,
                    value,
                ))
            }).collect::<#cbor_module::CborSerializationResult<Vec<_>>>()?);
        }
    } else {
        quote! {
            if let #cbor_module::UnknownMapKeys::Fail = options.unknown_map_keys {
                if let Some((unknown_key, _)) = map_values.iter().next() {
                    return Err(#cbor_module::CborSerializationError::unknown_map_key(unknown_key.as_ref()));
                }
            }
        }
    }
}

/// Generate per-entry unknown-key handling for regular map decoding.
///
/// This path streams entries directly from the CBOR decoder, so unknown keys
/// are handled immediately as each unmatched key is encountered.
fn cbor_regular_unknown_key_deserialize_tokens(
    cbor_fields: &CborFields,
    cbor_module: &TokenStream,
) -> TokenStream {
    if let Some((_, other_ident)) = cbor_fields.other_member() {
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
    }
}

/// Generate deserialization code for a named struct map that contains one or
/// more `#[cbor(flatten)]` fields.
///
/// This path materializes the whole CBOR map as `Value::Map` first so known
/// keys can be removed before delegating the remaining entries to flattened
/// nested structs.
fn cbor_deserialize_flattened_map_struct_body(
    cbor_fields: &CborFields,
    self_construct: &TokenStream,
    cbor_module: &TokenStream,
) -> syn::Result<TokenStream> {
    let field_map_keys = cbor_fields.cbor_map_keys()?;
    let field_map_owned_keys = cbor_fields.cbor_map_owned_keys()?;
    let non_flatten_members = cbor_fields.non_flatten_members();
    let non_flatten_field_vars = cbor_member_binding_vars(&non_flatten_members);
    let flatten_members = cbor_fields.flatten_members();
    let other_field_declare = cbor_other_field_declare_tokens(cbor_fields);
    let unknown_key_finish = cbor_flattened_unknown_key_finish_tokens(cbor_fields, cbor_module);

    Ok(quote! {
        let options = decoder.options();
        // Flattened decoding needs ownership of the full map so we can peel off
        // top-level known keys and then hand the remainder to nested structs.
        let map_value = #cbor_module::value::Value::deserialize(decoder)?;
        let #cbor_module::value::Value::Map(map_entries) = map_value else {
            return Err(#cbor_module::CborSerializationError::expected_data_item(
                #cbor_module::DataItemType::Map,
                map_value.data_item_type(),
            ));
        };

        // Normalize map keys into `MapKey` so lookups/removals use the same
        // representation regardless of the original CBOR key encoding.
        let mut map_values = std::collections::HashMap::with_capacity(map_entries.len());
        for (map_key_value, map_value) in map_entries {
            let map_key = match map_key_value {
                #cbor_module::value::Value::Positive(value) => #cbor_module::MapKey::Positive(value),
                #cbor_module::value::Value::Text(value) => #cbor_module::MapKey::Text(value),
                other => {
                    return Err(#cbor_module::CborSerializationError::invalid_data(format_args!(
                        "expected map key of type text or positive, was {:?}",
                        other.data_item_type(),
                    )));
                }
            };
            if map_values.insert(map_key.clone(), map_value).is_some() {
                return Err(#cbor_module::CborSerializationError::invalid_data(format_args!(
                    "duplicate map key {:?}",
                    map_key.as_ref(),
                )));
            }
        }

        #other_field_declare

        #(
            let #non_flatten_field_vars = match map_values.remove(&#field_map_owned_keys) {
                None => match #cbor_module::CborDeserialize::null() {
                    None => return Err(#cbor_module::CborSerializationError::map_value_missing(#field_map_keys)),
                    Some(null_value) => null_value,
                },
                Some(value) => #cbor_module::__private::decode_cbor_from_value(value, options)?,
            };
        )*

        #(
            // Each flattened field consumes the subset of entries that belong
            // to the nested struct from the shared map of remaining values.
            let #flatten_members = #cbor_module::__private::StructMapCbor::cbor_deserialize_fields(&mut map_values, options)?;
        )*

        #unknown_key_finish

        Ok(#self_construct)
    })
}

/// Generate deserialization code for a named struct map without flattened
/// fields.
///
/// This path can stream the CBOR map directly because every supported field is
/// matched independently and no nested struct needs access to the remaining
/// entries as a whole.
fn cbor_deserialize_regular_map_struct_body(
    cbor_fields: &CborFields,
    self_construct: &TokenStream,
    cbor_module: &TokenStream,
) -> syn::Result<TokenStream> {
    let field_map_keys = cbor_fields.cbor_map_keys()?;
    let non_flatten_members = cbor_fields.non_flatten_members();
    let non_flatten_field_vars = cbor_member_binding_vars(&non_flatten_members);
    let field_vars = cbor_member_binding_vars(&cbor_fields.members());
    let other_field_declare = cbor_other_field_declare_tokens(cbor_fields);
    let unknown_key_deserialize =
        cbor_regular_unknown_key_deserialize_tokens(cbor_fields, cbor_module);

    Ok(quote! {
        let options = decoder.options();
        // Track seen values per field while streaming the map decoder.
        #(let mut #non_flatten_field_vars = None;)*
        let mut map_decoder = #cbor_module::CborDecoder::decode_map(decoder)?;

        #other_field_declare

        while let Some(map_key) = #cbor_module::CborMapDecoder::deserialize_key::<#cbor_module::MapKey>(&mut map_decoder)? {
            match map_key.as_ref() {
                #(
                    #field_map_keys => {
                        #non_flatten_field_vars = Some(#cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?);
                    }
                )*
                _ => {
                    #unknown_key_deserialize
                }
            }
        }

        #(
            let #non_flatten_field_vars = match #non_flatten_field_vars {
                None => match #cbor_module::CborDeserialize::null() {
                    None => return Err(#cbor_module::CborSerializationError::map_value_missing(#field_map_keys)),
                    Some(null_value) => null_value,
                },
                Some(#field_vars) => #field_vars,
            };
        )*

        Ok(#self_construct)
    })
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

    let field_vars = cbor_member_binding_vars(&field_idents);

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
            // Flattened map fields require a whole-map strategy, while regular
            // named structs can be decoded in a streaming fashion.
            if cbor_fields.has_flatten_fields() {
                cbor_deserialize_flattened_map_struct_body(
                    &cbor_fields,
                    &self_construct,
                    &cbor_module,
                )?
            } else {
                cbor_deserialize_regular_map_struct_body(
                    &cbor_fields,
                    &self_construct,
                    &cbor_module,
                )?
            }
        }
    })
}

struct DeserializeImpls {
    deserialize_body: TokenStream,
    deserialize_maybe_known_body: Option<TokenStream>,
    impl_block: Option<TokenStream>,
}

fn cbor_deserialize_enum_body(
    variants: &Punctuated<Variant, Comma>,
    opts: &CborOpts,
) -> syn::Result<DeserializeImpls> {
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
                #cbor_module::__private::MaybeKnown::Known(Self::#other_ident(key.into(), #cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?))
            }
        } else {
            quote! {
                #cbor_module::__private::MaybeKnown::Unknown((key, #cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?))
            }
        };

        DeserializeImpls {
            deserialize_body: quote! {
                Self::deserialize_impl(decoder)
                    .and_then(|maybe_known| maybe_known.known_or_else(|(key, _value)|
                        #cbor_module::CborSerializationError::unknown_map_key(#cbor_module::MapKeyRef::Text(&key))
                ))
            },
            deserialize_maybe_known_body: Some(quote! {
                Self::deserialize_impl(decoder).map(|maybe_known| maybe_known.map_unknown(|(key, value)|
                    #cbor_module::value::Value::Map(vec![(#cbor_module::value::Value::Text(key), value)])
                ))
            }),
            impl_block: Some(quote! {
                fn deserialize_impl<C: #cbor_module::CborDecoder>(
                    mut decoder: C,
                ) -> #cbor_module::CborSerializationResult<#cbor_module::__private::MaybeKnown<Self, (String, #cbor_module::value::Value)>>
                {
                    let mut map_decoder = decoder.decode_map_expect_size(1)?;

                    let Some(key): Option<String> = #cbor_module::CborMapDecoder::deserialize_key(&mut map_decoder)? else {
                        return Err(#cbor_module::__private::anyhow::anyhow!("expected an array element since size has already been checked to be 1").into());
                    };

                    Ok(match key.as_str() {
                        #(
                            #variant_map_keys => {
                                #cbor_module::__private::MaybeKnown::Known(Self::#variant_idents(#cbor_module::CborMapDecoder::deserialize_value(&mut map_decoder)?))
                            }
                        )*
                        _ => {
                            #deserialize_unknown
                        }
                    })
                }
            }),
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
                #cbor_module::__private::MaybeKnown::Known(Self::#untagged_ident(#cbor_module::CborDeserialize::deserialize(decoder)?))
            }
        } else {
            quote! {
                return Err(#cbor_module::__private::anyhow::anyhow!("tag needed to deserialize to enum, no tag specified").into());
            }
        };

        let deserialize_unknown = if let Some(other_ident) = cbor_variants.other_ident() {
            quote! {
                #cbor_module::__private::MaybeKnown::Known(Self::#other_ident(tag, #cbor_module::CborDeserialize::deserialize(decoder)?))
            }
        } else {
            quote! {
                #cbor_module::__private::MaybeKnown::Unknown((tag, #cbor_module::CborDeserialize::deserialize(decoder)?))
            }
        };

        DeserializeImpls {
            deserialize_body: quote! {
                Self::deserialize_impl(decoder)
                    .and_then(|maybe_known| maybe_known.known_or_else(|(tag, _value)|
                        #cbor_module::__private::anyhow::anyhow!("tag {} not among declared variants", tag).into()
                ))
            },
            deserialize_maybe_known_body: Some(quote! {
                Self::deserialize_impl(decoder).map(|maybe_known| maybe_known.map_unknown(|(tag, value)|
                    #cbor_module::value::Value::Tag(tag, Box::new(value))
                ))
            }),
            impl_block: Some(quote! {
                fn deserialize_impl<C: #cbor_module::CborDecoder>(
                    mut decoder: C,
                ) -> #cbor_module::CborSerializationResult<#cbor_module::__private::MaybeKnown<Self, (u64, #cbor_module::value::Value)>>
                {
                    Ok(match #cbor_module::CborDecoder::peek_data_item_header(&mut decoder)? {
                        #(
                            #cbor_module::DataItemHeader::Tag(#tagged_variant_tags) => {
                                #deserialize_variant_tags;
                                #cbor_module::__private::MaybeKnown::Known(Self::#tagged_variant_idents(#cbor_module::CborDeserialize::deserialize(decoder)?))
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
            }),
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

    let deserialize_impls = match &ast.data {
        Data::Struct(DataStruct { fields, .. }) => DeserializeImpls {
            deserialize_body: cbor_deserialize_struct_body(fields, &opts)?,
            deserialize_maybe_known_body: None,
            impl_block: None,
        },
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

    let deserialize_body = deserialize_impls.deserialize_body;

    let trait_impl = if let Some(deserialize_maybe_known_body) =
        deserialize_impls.deserialize_maybe_known_body
    {
        quote! {
            impl #impl_generics #cbor_module::CborDeserialize for #name #ty_generics #where_clauses {
                fn deserialize<C: #cbor_module::CborDecoder>(decoder: C) -> #cbor_module::CborSerializationResult<Self> {
                    #deserialize_body
                }

                fn deserialize_maybe_known<C: #cbor_module::CborDecoder>(
                    mut decoder: C,
                ) -> #cbor_module::CborSerializationResult<#cbor_module::CborMaybeKnown<Self>>
                {
                    #decode_tag
                    #deserialize_maybe_known_body
                }
            }
        }
    } else {
        quote! {
            impl #impl_generics #cbor_module::CborDeserialize for #name #ty_generics #where_clauses {
                fn deserialize<C: #cbor_module::CborDecoder>(mut decoder: C) -> #cbor_module::CborSerializationResult<Self> {
                    #decode_tag
                    #deserialize_body
                }
            }
        }
    };

    let impl_block = deserialize_impls.impl_block.into_iter();
    let type_impl = quote! {
        #(
            impl #impl_generics #name #ty_generics #where_clauses {
                #impl_block
            }
        )*
    };

    let flatten_impl = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) if !opts.transparent => Some({
            let cbor_fields = CborFields::try_from_fields(&Fields::Named(fields.clone()))?;
            let field_idents = cbor_fields.members();
            let non_flatten_members = cbor_fields.non_flatten_members();
            let field_vars: Vec<_> = non_flatten_members
                .iter()
                .map(|member| match member {
                    Member::Named(ident) => ident.clone(),
                    Member::Unnamed(index) => format_ident!("tmp{}", index),
                })
                .collect();
            let field_map_keys = cbor_fields.cbor_map_keys()?;
            let field_map_owned_keys = cbor_fields.cbor_map_owned_keys()?;
            let flatten_members = cbor_fields.flatten_members();
            let other_member = cbor_fields.other_member();
            let other_field_declare = if let Some((ty, other_ident)) = &other_member {
                quote! { let mut #other_ident = <#ty>::default(); }
            } else {
                quote! {}
            };
            let other_field_finish = if let Some((_, other_ident)) = &other_member {
                quote! {
                    #other_ident.extend(map_values.drain().map(|(key, value)| {
                        Ok((
                            #cbor_module::__private::anyhow::Context::context(key.try_into(), "cannot convert MapKey to declared key")?,
                            value,
                        ))
                    }).collect::<#cbor_module::CborSerializationResult<Vec<_>>>()?);
                }
            } else {
                quote! {
                    if let #cbor_module::UnknownMapKeys::Fail = options.unknown_map_keys {
                        if let Some((unknown_key, _)) = map_values.iter().next() {
                            return Err(#cbor_module::CborSerializationError::unknown_map_key(unknown_key.as_ref()));
                        }
                    }
                }
            };
            let self_construct = {
                let mut members = field_idents.clone();
                if let Some((_, other_ident)) = &other_member {
                    members.push(other_ident.clone());
                }
                quote! { Self { #(#members),* } }
            };
            let other_ident = other_member.iter().map(|(_, member)| member);
            quote! {
                impl #impl_generics #cbor_module::__private::StructMapCbor for #name #ty_generics #where_clauses {
                    fn cbor_serialize_fields<C: #cbor_module::CborMapEncoder>(
                        &self,
                        map_encoder: &mut C,
                    ) -> std::result::Result<(), C::WriteError> {
                        #(
                            if !#cbor_module::CborSerialize::is_null(&self.#non_flatten_members) {
                                #cbor_module::CborMapEncoder::serialize_entry(map_encoder, &#field_map_keys, &self.#non_flatten_members)?;
                            }
                        )*
                        #(
                            #cbor_module::__private::StructMapCbor::cbor_serialize_fields(&self.#flatten_members, map_encoder)?;
                        )*
                        #(
                            for (key, value) in self.#other_ident.iter() {
                                #cbor_module::CborMapEncoder::serialize_entry(map_encoder, key, value)?;
                            }
                        )*
                        Ok(())
                    }

                    fn cbor_deserialize_fields(
                        map_values: &mut std::collections::HashMap<#cbor_module::MapKey, #cbor_module::value::Value>,
                        options: #cbor_module::SerializationOptions,
                    ) -> #cbor_module::CborSerializationResult<Self> {
                        #other_field_declare
                        #(
                            let #field_vars = match map_values.remove(&#field_map_owned_keys) {
                                None => match #cbor_module::CborDeserialize::null() {
                                    None => return Err(#cbor_module::CborSerializationError::map_value_missing(#field_map_keys)),
                                    Some(null_value) => null_value,
                                },
                                Some(value) => #cbor_module::__private::decode_cbor_from_value(value, options)?,
                            };
                        )*
                        #(
                            let #flatten_members = #cbor_module::__private::StructMapCbor::cbor_deserialize_fields(map_values, options)?;
                        )*
                        #other_field_finish
                        Ok(#self_construct)
                    }
                }
            }
        }),
        _ => None,
    };

    let flatten_impl = flatten_impl.into_iter();

    let all_impls = quote! {
        #trait_impl
        #type_impl
        #(
            #flatten_impl
        )*
    };

    Ok(all_impls)
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
            quote! {
                let mut array_encoder = #cbor_module::CborEncoder::encode_array(encoder)?;

                #(
                    #cbor_module::CborArrayEncoder::serialize_element(&mut array_encoder, &self.#field_idents)?;
                )*

                #cbor_module::CborArrayEncoder::end(array_encoder)?;

                Ok(())
            }
        }
        CborContainer::Map => {
            let field_map_keys = cbor_fields.cbor_map_keys()?;
            let non_flatten_members = cbor_fields.non_flatten_members();
            let flatten_members = cbor_fields.flatten_members();
            let other_ident = cbor_fields.other_member().into_iter().map(|other| other.1);

            quote! {
                let mut map_encoder = #cbor_module::CborEncoder::encode_map(encoder)?;

                #(
                    if !#cbor_module::CborSerialize::is_null(&self.#non_flatten_members) {
                        #cbor_module::CborMapEncoder::serialize_entry(&mut map_encoder, &#field_map_keys, &self.#non_flatten_members)?;
                    }
                )*

                #(
                    #cbor_module::__private::StructMapCbor::cbor_serialize_fields(&self.#flatten_members, &mut map_encoder)?;
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
            let mut map_encoder = #cbor_module::CborEncoder::encode_map(encoder)?;
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
            fn serialize<C: #cbor_module::CborEncoder>(&self, mut encoder: C) -> std::result::Result<(), <C as #cbor_module::CborEncoder>::WriteError> {
                #encode_tag
                #serialize_body
            }
        }
    })
}
