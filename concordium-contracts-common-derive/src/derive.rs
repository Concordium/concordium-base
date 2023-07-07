//! This module contains the main logic for the derive macros.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::ToTokens;
use std::{collections::HashMap, convert::TryFrom, ops::Neg};
use syn::{spanned::Spanned, DataEnum, Ident, Meta};

/// Check a condition, if false return early with a provided error message
/// wrapped in a `syn::Error`. Similar to `ensure!` from the `anyhow` crate.
macro_rules! check {
    ($condition: expr, $span: expr, $message: expr) => {
        if !$condition {
            abort!($span, $message);
        }
    };
    ($condition: expr, $span: expr, $message: expr, $($arg:tt)*) => {
        if !$condition {
            abort!($span, $message, $($arg)*);
        }
    };
}

/// Return early with a provided error message wrapped in a `syn::Error`.
/// Similar to `anyhow!` from the `anyhow` crate
macro_rules! abort {
    ($span: expr, $message: expr) => {
        return Err(syn::Error::new(
            $span,
            format!($message),
        ));
    };
    ($span: expr, $message: expr, $($arg:tt)*) => {
        return Err(syn::Error::new(
            $span,
            format!($message, $($arg)*),
        ));
    };
}

/// The prefix used in field attributes: `#[concordium(attr = "something")]`.
const CONCORDIUM_ATTRIBUTE: &str = "concordium";

/// A list of valid concordium field attributes.
const VALID_CONCORDIUM_FIELD_ATTRIBUTES: [&str; 3] = ["size_length", "ensure_ordered", "rename"];

/// A list of valid concordium attributes.
const VALID_CONCORDIUM_ATTRIBUTES: [&str; 4] = ["state_parameter", "bound", "transparent", "repr"];

fn get_root() -> proc_macro2::TokenStream { quote!(concordium_std) }

/// Return whether an attribute item is present.
fn contains_attribute<'a, I: IntoIterator<Item = &'a Meta>>(iter: I, name: &str) -> bool {
    iter.into_iter().any(|attr| attr.path().is_ident(name))
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
    let attr_values: Vec<_> = get_valid_concordium_attributes(attributes, for_field)?
        .into_iter()
        .filter_map(|nested_meta| match nested_meta {
            syn::Meta::NameValue(name_value) if name_value.path.is_ident(&target_attr) => {
                if let syn::Expr::Lit(expr_lit) = name_value.value {
                    Some(expr_lit.lit)
                } else {
                    None
                }
            }
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

/// Finds concordium field attributes, ensuring these are supported.
fn get_concordium_field_attributes(attributes: &[syn::Attribute]) -> syn::Result<Vec<syn::Meta>> {
    get_valid_concordium_attributes(attributes, true)
}

/// Find and parses concordium attributes into a list of `syn::Meta`. This does
/// no validation on the meta itself as oppose to
/// `get_valid_concordium_attributes`.
fn get_concordium_attributes(attributes: &[syn::Attribute]) -> syn::Result<Vec<syn::Meta>> {
    let mut metas = Vec::new();
    for attr in attributes {
        // Keep only concordium attributes
        if !attr.meta.path().is_ident(CONCORDIUM_ATTRIBUTE) {
            continue;
        }
        // Ensure only list attributes and parse the nested meta.
        let syn::Meta::List(list) = &attr.meta else {
            abort!(attr.meta.span(), "A 'concordium' attribute must be provided as 'concordium(..)'");
        };
        // Parse list args tokens as syn::Meta.
        let nested = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )?;
        metas.extend(nested);
    }
    Ok(metas)
}

/// Find and parses concordium attributes into a list of `syn::Meta`. Checking
/// that the 'path' of each of these metas are expected for either field or
/// container attributes based on the `for_field` argument. Note that the path
/// is corresponding to `foo` in the following example attributes
/// `#[concordium(foo)]`, `#[concordium(foo = x)]`, `#[concordium(foo(x, y,
/// z))]`.
fn get_valid_concordium_attributes(
    attributes: &[syn::Attribute],
    for_field: bool,
) -> syn::Result<Vec<syn::Meta>> {
    let (valid_attributes, attribute_type) = if for_field {
        (&VALID_CONCORDIUM_FIELD_ATTRIBUTES[..], "concordium field attribute")
    } else {
        (&VALID_CONCORDIUM_ATTRIBUTES[..], "concordium attribute")
    };

    let concordium_attributes = get_concordium_attributes(attributes)?;
    for meta in &concordium_attributes {
        let path = meta.path();
        check!(
            valid_attributes.iter().any(|&attr| path.is_ident(attr)),
            meta.span(),
            "The attribute '{}' is not supported as a {}.",
            path.to_token_stream(),
            attribute_type
        );
    }
    Ok(concordium_attributes)
}

/// Find a 'state_parameter' attribute and return it as an identifier.
/// Checks that the attribute is only defined once and that the value is a
/// string.
fn find_state_parameter_attribute(
    attributes: &[syn::Attribute],
) -> syn::Result<Option<syn::TypePath>> {
    let value = match find_attribute_value(attributes, false, "state_parameter")? {
        Some(v) => v,
        None => return Ok(None),
    };

    match value {
        syn::Lit::Str(value) => Ok(Some(value.parse().map_err(|err| {
            syn::Error::new(err.span(), "state_parameter attribute value is not a valid type path")
        })?)),
        _ => Err(syn::Error::new(
            value.span(),
            "state_parameter attribute value must be a string which describes valid type path",
        )),
    }
}

/// Set an optional error if None, otherwise combine the errors.
fn push_error(collection: &mut Option<syn::Error>, new_error: syn::Error) {
    match collection {
        Some(error) => error.combine(new_error),
        None => *collection = Some(new_error),
    }
}

/// The value of the bound attribute, e.g. "A: Serial, B: Deserial".
type BoundAttributeValue = syn::punctuated::Punctuated<syn::WherePredicate, syn::token::Comma>;

/// Bound attribute on some type.
#[derive(Debug)]
enum BoundAttribute {
    /// Represents a bound shared across all of the derived traits.
    /// E.g. the attribute: `bound = "A : Serial + Deserial"`
    Shared(BoundAttributeValue),
    /// Represents bounds explicitly set for each derived trait.
    /// E.g. the attribute: `bound(serial = "A : Serial", deserial = "A :
    /// Deserial")`
    Separated(SeparateBoundValue),
}

impl BoundAttribute {
    /// Return bounds set for the implementation of `Deserial`. `None` meaning
    /// no bound attribute for this trait.
    fn deserial_bound(&self) -> Option<&BoundAttributeValue> {
        if let BoundAttribute::Shared(bound)
        | BoundAttribute::Separated(SeparateBoundValue {
            deserial: Some(bound),
            ..
        }) = self
        {
            Some(bound)
        } else {
            None
        }
    }

    /// Return bounds set for the implementation of `Serial`. `None` meaning
    /// no bound attribute for this trait.
    fn serial_bound(&self) -> Option<&BoundAttributeValue> {
        if let BoundAttribute::Shared(bound)
        | BoundAttribute::Separated(SeparateBoundValue {
            serial: Some(bound),
            ..
        }) = self
        {
            Some(bound)
        } else {
            None
        }
    }

    /// Return bounds set for the implementation of `SchemaType`. `None` meaning
    /// no bound attribute for this trait.
    fn schema_type_bound(&self) -> Option<&BoundAttributeValue> {
        if let BoundAttribute::Shared(bound)
        | BoundAttribute::Separated(SeparateBoundValue {
            schema_type: Some(bound),
            ..
        }) = self
        {
            Some(bound)
        } else {
            None
        }
    }
}

/// Represents bounds explicitly set for each derived trait.
///
/// E.g. `bound(serial = "A : Serial", deserial = "A : Deserial", schema_type =
/// "A : SchemaType")`
#[derive(Debug)]
struct SeparateBoundValue {
    /// Bounds set for Deserial and DeserialWithState.
    deserial:    Option<BoundAttributeValue>,
    /// Bounds set for Serial.
    serial:      Option<BoundAttributeValue>,
    /// Bounds set for SchemaType.
    schema_type: Option<BoundAttributeValue>,
}

/// Concordium attributes supported on containers.
#[derive(Debug)]
struct ContainerAttributes {
    /// All of the `bound` attributes, either of the form `bound(serial = "..",
    /// deserial = "..", schema_type = "..")` or `bound = ".."`
    bounds:          Vec<BoundAttribute>,
    /// The state parameter attribute. `state_parameter = ".."`
    state_parameter: Option<syn::TypePath>,
    /// The 'transparent' attribute. Is false when not present.
    transparent:     bool,
    /// The 'repr(..)' attribute.
    repr:            Option<ReprAttribute>,
}

impl ContainerAttributes {
    /// Collect shared and explicit bounds set for the implementation of
    /// `Deserial`. `None` meaning no bound attributes are provided.
    fn deserial_bounds(&self) -> Option<BoundAttributeValue> {
        let mut bounds: Option<BoundAttributeValue> = None;
        for attribute in self.bounds.iter() {
            if let Some(bound) = attribute.deserial_bound() {
                bounds.get_or_insert(BoundAttributeValue::new()).extend(bound.clone());
            }
        }
        bounds
    }

    /// Collect shared and explicit bounds set for the implementation of
    /// `Serial`. `None` meaning no bound attributes are provided.
    fn serial_bounds(&self) -> Option<BoundAttributeValue> {
        let mut bounds: Option<BoundAttributeValue> = None;
        for attribute in self.bounds.iter() {
            if let Some(bound) = attribute.serial_bound() {
                bounds.get_or_insert(BoundAttributeValue::new()).extend(bound.clone());
            }
        }
        bounds
    }

    /// Collect shared and explicit bounds set for the implementation of
    /// `SchemaType`. `None` meaning no bound attributes are provided.
    fn schema_type_bounds(&self) -> Option<BoundAttributeValue> {
        let mut bounds: Option<BoundAttributeValue> = None;
        for attribute in self.bounds.iter() {
            if let Some(bound) = attribute.schema_type_bound() {
                bounds.get_or_insert(BoundAttributeValue::new()).extend(bound.clone());
            }
        }
        bounds
    }

    /// Get the repr attribute if set otherwise the smallest size length which
    /// can represent the number of variants.
    fn tag_repr(&self, variants_len: usize) -> syn::Result<ReprAttributeValue> {
        if let Some(repr_attribute) = &self.repr {
            let max = repr_attribute.max_num_variants();
            let ident = repr_attribute.ident();
            check!(
                max >= variants_len,
                Span::call_site(),
                "Too many variants. Maximum {max} are supported with 'repr({ident})'",
            );
            Ok(repr_attribute.value)
        } else if variants_len <= usize::from(u8::MAX) + 1 {
            Ok(ReprAttributeValue::U8)
        } else if variants_len <= usize::from(u16::MAX) + 1 {
            Ok(ReprAttributeValue::U16)
        } else {
            abort!(Span::call_site(), "Too many variants. Maximum 65536 are supported.",);
        }
    }

    /// Run checks on variant attributes against the container attributes.
    /// More specifically checking `tag` and `forward` attributes against the
    /// `repr` attribute.
    fn check_variant_attributes(
        &self,
        variant_attributes: &EnumVariantAttributes,
    ) -> syn::Result<()> {
        self.check_tag_with_repr(&variant_attributes.tag)?;
        self.check_forwards_with_repr(&variant_attributes.forwards)?;
        Ok(())
    }

    /// Ensure that when a `tag` attribute is used, a `repr` attribute is set
    /// and this `repr(u*)` is large enough to represent the tag.
    fn check_tag_with_repr(&self, tag_attribute: &Option<TagAttribute>) -> syn::Result<()> {
        if let Some(tag) = tag_attribute {
            let Some(repr) = &self.repr else {
                abort!(
                    Span::call_site(),
                    "'repr(..)' attribute must be set on the type when using 'tag' attribute",
                );
            };
            let value: usize = tag.value.base10_parse()?;
            check!(
                value <= repr.max_tag_value(),
                tag.span,
                "'tag' attribute value of {} cannot be represented by the type {1} set in \
                 'repr({1})'",
                tag.value,
                repr.ident()
            );
        }
        Ok(())
    }

    /// Ensure that when `forward` attribute is used, a `repr` attribute is set
    /// and this `repr(u*)` is large enough to represent the forwarded tag.
    fn check_forwards_with_repr(
        &self,
        forward_attributes: &Vec<ForwardAttribute>,
    ) -> syn::Result<()> {
        if forward_attributes.is_empty() {
            return Ok(());
        }
        let Some(repr) = &self.repr else {
            abort!(
                Span::call_site(),
                "'repr(..)' attribute must be set on the type when using 'forward' attribute",
            );
        };

        for forward in forward_attributes {
            for tag in &forward.values {
                let value: usize = tag.base10_parse()?;
                check!(
                    value <= repr.max_tag_value(),
                    tag.span(),
                    "'forward' attribute tag value of {} cannot be represented by the type {1} \
                     set in 'repr({1})'",
                    tag,
                    repr.ident()
                );
            }
        }
        Ok(())
    }
}

/// Valid values for the 'repr(..)' attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReprAttributeValue {
    U8,
    U16,
}

impl ReprAttributeValue {
    /// Construct a ['syn::Ident'] from the value.
    fn ident(&self) -> syn::Ident {
        use ReprAttributeValue::*;
        match self {
            U8 => format_ident!("u8"),
            U16 => format_ident!("u16"),
        }
    }
}

/// 'repr(..)' attribute, used to specify the size length used for enum tags.
#[derive(Debug)]
struct ReprAttribute {
    /// The size length to use.
    value: ReprAttributeValue,
    /// The span of the attribute.
    span:  proc_macro2::Span,
}

impl ReprAttribute {
    /// Construct a ['syn::Ident'] from the value.
    fn ident(&self) -> syn::Ident { self.value.ident() }

    /// Maximum tag value with the value of the 'repr' attribute.
    fn max_tag_value(&self) -> usize {
        use ReprAttributeValue::*;
        match self.value {
            U8 => u8::MAX.into(),
            U16 => u16::MAX.into(),
        }
    }

    /// Maximum number of variants distiguishable with the value of the 'repr'
    /// attribute
    fn max_num_variants(&self) -> usize { self.max_tag_value() + 1 }
}

impl TryFrom<&syn::Meta> for ReprAttribute {
    type Error = syn::Error;

    fn try_from(meta: &syn::Meta) -> Result<Self, Self::Error> {
        let syn::Meta::List(list) = meta else {
            abort!(
                meta.span(),
                "repr attribute value can only be provided as 'repr(...)'",
            );
        };
        let nested = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )?;
        check!(nested.len() == 1, nested.span(), "'repr(..)' must be provided a single value",);
        // Safe to unwrap below because we already checked the length to be 1.
        let syn::Meta::Path(path) = nested.first().unwrap() else {
            abort!(nested.span(), "'repr(..)' only supports the values 'u8' or 'u16'");
        };
        let Some(ident) = path.get_ident() else {
            abort!(path.span(), "'repr(..)' only supports the values 'u8' or 'u16'");
        };
        let value = if ident == "u8" {
            ReprAttributeValue::U8
        } else if ident == "u16" {
            ReprAttributeValue::U16
        } else {
            abort!(ident.span(), "'repr(..)' only supports the values 'u8' or 'u16'",);
        };
        Ok(Self {
            value,
            span: meta.span(),
        })
    }
}

impl TryFrom<&[syn::Attribute]> for ContainerAttributes {
    type Error = syn::Error;

    fn try_from(attributes: &[syn::Attribute]) -> Result<Self, Self::Error> {
        let metas = get_valid_concordium_attributes(attributes, false)?;
        // Collect and combine all errors if any.
        let mut error_option: Option<syn::Error> = None;
        let mut bounds = Vec::new();
        let mut transparent = false;
        let mut repr_option: Option<ReprAttribute> = None;
        for meta in metas.iter() {
            if meta.path().is_ident("bound") {
                match BoundAttribute::try_from(meta) {
                    Err(new_err) => push_error(&mut error_option, new_err),
                    Ok(bound) => bounds.push(bound),
                }
            } else if meta.path().is_ident("transparent") {
                if let syn::Meta::Path(_) = meta {
                    transparent = true
                } else {
                    let new_err = syn::Error::new(
                        meta.span(),
                        "'transparent' attribute cannot be a list or hold a value",
                    );
                    push_error(&mut error_option, new_err)
                }
            } else if meta.path().is_ident("repr") {
                if let Some(repr_attribute) = &repr_option {
                    let new_error = syn::Error::new(
                        meta.span(),
                        "Attribute 'repr' should only be specified once per type.",
                    );
                    error_option.get_or_insert_with(|| {
                        syn::Error::new(
                            repr_attribute.span,
                            "Attribute 'repr' should only be specified once per type.",
                        )
                    });
                    push_error(&mut error_option, new_error)
                } else {
                    match ReprAttribute::try_from(meta) {
                        Ok(repr) => repr_option = Some(repr),
                        Err(err) => push_error(&mut error_option, err),
                    }
                }
            }
        }

        if let Some(err) = error_option {
            Err(err)
        } else {
            Ok(ContainerAttributes {
                bounds,
                state_parameter: find_state_parameter_attribute(attributes)?,
                transparent,
                repr: repr_option,
            })
        }
    }
}

impl TryFrom<&syn::MetaList> for SeparateBoundValue {
    type Error = syn::Error;

    fn try_from(list: &syn::MetaList) -> Result<Self, Self::Error> {
        let items = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )?;

        check!(!items.is_empty(), list.span(), "bound attribute cannot be empty");

        let mut deserial: Option<BoundAttributeValue> = None;
        let mut serial: Option<BoundAttributeValue> = None;
        let mut schema_type: Option<BoundAttributeValue> = None;

        for item in &items {
            let syn::Meta::NameValue(name_value) = item else {
                abort!(item.span(), "bound attribute list must contain named values");
            };
            if name_value.path.is_ident("serial") {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit_str),
                    ..
                }) = &name_value.value else {
                    abort!(name_value.value.span(), "bound attribute must be a string literal");
                };
                let value = lit_str.parse_with(BoundAttributeValue::parse_terminated)?;
                if let Some(serial_value) = serial.as_mut() {
                    serial_value.extend(value)
                } else {
                    serial = Some(value);
                };
            } else if name_value.path.is_ident("deserial") {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit_str),
                    ..
                }) = &name_value.value else {
                    abort!(name_value.value.span(), "bound attribute must be a string literal");
                };
                let value = lit_str.parse_with(BoundAttributeValue::parse_terminated)?;
                if let Some(deserial_value) = deserial.as_mut() {
                    deserial_value.extend(value)
                } else {
                    deserial = Some(value);
                };
            } else if name_value.path.is_ident("schema_type") {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit_str),
                    ..
                }) = &name_value.value else {
                    abort!(name_value.value.span(), "bound attribute must be a string literal");
                };
                let value = lit_str.parse_with(BoundAttributeValue::parse_terminated)?;
                if let Some(schema_type_value) = schema_type.as_mut() {
                    schema_type_value.extend(value)
                } else {
                    schema_type = Some(value);
                };
            } else {
                abort!(
                    item.span(),
                    "bound attribute list only allow the keys 'serial', 'deserial' and \
                     'schema_type'",
                );
            }
        }

        Ok(Self {
            deserial,
            serial,
            schema_type,
        })
    }
}

impl TryFrom<&syn::Meta> for BoundAttribute {
    type Error = syn::Error;

    fn try_from(meta: &syn::Meta) -> Result<Self, Self::Error> {
        match meta {
            syn::Meta::List(list) => {
                Ok(BoundAttribute::Separated(SeparateBoundValue::try_from(list)?))
            }
            syn::Meta::NameValue(name_value) => {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit_str),
                    ..
                }) = &name_value.value else {
                    abort!(name_value.value.span(), "bound attribute must be a string literal");
                };
                let value = lit_str.parse_with(BoundAttributeValue::parse_terminated)?;
                Ok(BoundAttribute::Shared(value))
            }
            syn::Meta::Path(_) => Err(syn::Error::new(
                meta.span(),
                "bound attribute value can either be provided as 'bound = \"...\"' or as \
                 'bound(serial = \"...\", deserial = \"...\", schema_type = \"...\")'",
            )),
        }
    }
}

/// Concordium attributes supported on enum variants.
#[derive(Debug)]
struct EnumVariantAttributes {
    /// Override tag to use for (de)serializing this variant e.g. 'tag = 42'
    tag:      Option<TagAttribute>,
    /// Override variant name in the derived 'SchemaType'.
    rename:   Option<RenameAttribute>,
    /// Forward the (de)serialization to nested type for a provided list of tag
    /// values e.g. 'forward = [255, 254, 253, 252]'.
    forwards: Vec<ForwardAttribute>,
}

/// Attribute 'tag' for providing the tag used when serializing an enum variant.
#[derive(Debug)]
struct TagAttribute {
    /// The literal to use as the tag.
    value: syn::LitInt,
    /// The span of the attribute.
    span:  proc_macro2::Span,
}

/// Attribute 'rename' for providing a name to use in the schema instead of the
/// inferred from variant or field name.
#[derive(Debug)]
struct RenameAttribute {
    /// The string to use as the name.
    value: String,
    /// The span of the attribute.
    span:  proc_macro2::Span,
}

/// Attribute 'forward' for specifying a list of tag values for which to forward
/// (de)serialization to nested type.
#[derive(Debug)]
struct ForwardAttribute {
    /// The tag values to forward.
    values: Vec<syn::LitInt>,
    /// The span of the attribute.
    span:   proc_macro2::Span,
}

impl TryFrom<&[syn::Attribute]> for EnumVariantAttributes {
    type Error = syn::Error;

    fn try_from(attributes: &[syn::Attribute]) -> Result<Self, Self::Error> {
        let metas = get_concordium_attributes(attributes)?;
        // Collect and combine all errors if any.
        let mut error_option: Option<syn::Error> = None;
        let mut tag_option: Option<TagAttribute> = None;
        let mut rename_option: Option<RenameAttribute> = None;
        let mut forwards: Vec<ForwardAttribute> = Vec::new();

        for meta in metas.iter() {
            if meta.path().is_ident("tag") {
                if let Some(tag_attribute) = &tag_option {
                    let new_error = syn::Error::new(
                        meta.span(),
                        "Attribute 'tag' should only be specified once per field.",
                    );
                    error_option.get_or_insert_with(|| {
                        syn::Error::new(
                            tag_attribute.span,
                            "Attribute 'tag' should only be specified once per field.",
                        )
                    });
                    push_error(&mut error_option, new_error)
                } else if let Some(forward_attribute) = forwards.first() {
                    let new_error = syn::Error::new(
                        forward_attribute.span,
                        "Attribute 'forward' cannot be used together with 'tag' attribute on the \
                         same variant.",
                    );
                    error_option.get_or_insert_with(|| {
                        syn::Error::new(
                            meta.span(),
                            "Attribute 'forward' cannot be used together with 'tag' attribute on \
                             the same variant.",
                        )
                    });
                    push_error(&mut error_option, new_error)
                } else {
                    match TagAttribute::try_from(meta) {
                        Ok(tag) => tag_option = Some(tag),
                        Err(err) => push_error(&mut error_option, err),
                    }
                }
            } else if meta.path().is_ident("rename") {
                if let Some(rename_attribute) = &rename_option {
                    let new_error = syn::Error::new(
                        meta.span(),
                        "Attribute 'rename' should only be specified once per field.",
                    );
                    error_option.get_or_insert_with(|| {
                        syn::Error::new(
                            rename_attribute.span,
                            "Attribute 'rename' should only be specified once per field.",
                        )
                    });
                    push_error(&mut error_option, new_error)
                } else {
                    match RenameAttribute::try_from(meta) {
                        Ok(rename) => rename_option = Some(rename),
                        Err(err) => push_error(&mut error_option, err),
                    }
                }
            } else if meta.path().is_ident("forward") {
                if let Some(tag_attribute) = &tag_option {
                    let new_error = syn::Error::new(
                        meta.span(),
                        "Attribute 'forward' cannot be used together with 'tag' attribute on the \
                         same variant.",
                    );
                    error_option.get_or_insert_with(|| {
                        syn::Error::new(
                            tag_attribute.span,
                            "Attribute 'forward' cannot be used together with 'tag' attribute on \
                             the same variant.",
                        )
                    });
                    push_error(&mut error_option, new_error)
                } else {
                    match ForwardAttribute::try_from(meta) {
                        Ok(forward) => forwards.push(forward),
                        Err(err) => push_error(&mut error_option, err),
                    }
                }
            } else {
                let err = syn::Error::new(
                    meta.span(),
                    format!(
                        "The attribute '{}' is not supported as an attribute for variants.",
                        meta.path().to_token_stream(),
                    ),
                );
                push_error(&mut error_option, err)
            }
        }
        if let Some(err) = error_option {
            Err(err)
        } else {
            Ok(EnumVariantAttributes {
                tag: tag_option,
                rename: rename_option,
                forwards,
            })
        }
    }
}

impl TryFrom<&syn::Meta> for TagAttribute {
    type Error = syn::Error;

    fn try_from(meta: &syn::Meta) -> Result<Self, Self::Error> {
        let syn::Meta::NameValue(name_value) = meta else {
            abort!(
                meta.span(),
                "'tag' attribute value can only be provided as 'tag = ...'.",
            );
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) = &name_value.value else {
            abort!(name_value.value.span(), "'tag' attribute must be an integer.");
        };
        Ok(TagAttribute {
            value: value.clone(),
            span:  meta.span(),
        })
    }
}

impl TryFrom<&syn::Meta> for RenameAttribute {
    type Error = syn::Error;

    fn try_from(meta: &syn::Meta) -> Result<Self, Self::Error> {
        let syn::Meta::NameValue(name_value) = meta else {
            abort!(
                meta.span(),
                "'rename' attribute value can only be provided as 'rename = ...'.",
            );
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit_str),
            ..
        }) = &name_value.value else {
            abort!(
                name_value.value.span(),
                "'rename' attribute must be a string."
            );
        };
        Ok(Self {
            value: lit_str.value(),
            span:  meta.span(),
        })
    }
}

impl TryFrom<&syn::Meta> for ForwardAttribute {
    type Error = syn::Error;

    fn try_from(meta: &syn::Meta) -> Result<Self, Self::Error> {
        let syn::Meta::NameValue(name_value) = meta else {
            abort!(
                meta.span(),
                "'forward' attribute value can be provided as 'forward = x' or forward = [x, y, z].",
            );
        };
        let mut values = Vec::new();
        match &name_value.value {
            syn::Expr::Lit(expr_lit) => {
                if let syn::Lit::Int(value) = &expr_lit.lit {
                    values.push(value.clone());
                } else {
                    abort!(
                        expr_lit.lit.span(),
                        "'forward' attribute must be an integer or an array of integers."
                    );
                }
            }
            syn::Expr::Array(expr_array) => {
                check!(
                    !expr_array.elems.is_empty(),
                    expr_array.span(),
                    "'forward' attribute must be non-empty when specified as array of integers"
                );
                for elem in &expr_array.elems {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(value),
                        ..
                    }) = elem
                    {
                        values.push(value.clone());
                    } else {
                        abort!(
                            elem.span(),
                            "'forward' attribute must be an integer or an array of integers."
                        );
                    }
                }
            }
            _ => {
                abort!(
                    name_value.span(),
                    "'forward' attribute value can be provided as 'forward = x' or forward = [x, \
                     y, z]."
                );
            }
        }

        Ok(ForwardAttribute {
            values,
            span: meta.span(),
        })
    }
}

/// Collect variant tags and check for collision.
#[derive(Debug, Default)]
struct TagChecker<'a> {
    tags_in_use: HashMap<syn::LitInt, (proc_macro2::Span, &'a syn::Ident)>,
}

impl<'a> TagChecker<'a> {
    /// Add a tag to a collection of used tags and provide an error if already
    /// used.
    fn add_and_check(
        &mut self,
        tag_lit: syn::LitInt,
        tag_span: proc_macro2::Span,
        variant_ident: &'a syn::Ident,
    ) -> syn::Result<()> {
        if let Some((clasing_tag_span, clasing_variant_ident)) =
            self.tags_in_use.insert(tag_lit, (tag_span, variant_ident))
        {
            let mut err = syn::Error::new(
                tag_span,
                format!(
                    "The tag of '{}' collides with the tag of '{}'.",
                    variant_ident, clasing_variant_ident
                ),
            );
            err.combine(syn::Error::new(
                clasing_tag_span,
                format!(
                    "The tag of '{}' collides with the tag of '{}'.",
                    clasing_variant_ident, variant_ident
                ),
            ));
            Err(err)
        } else {
            Ok(())
        }
    }
}

pub fn impl_deserial(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;

    let span = ast.span();

    let read_ident = format_ident!("__R", span = span);

    let source_ident = Ident::new("________________source", Span::call_site());
    let root = get_root();
    let container_attributes = ContainerAttributes::try_from(ast.attrs.as_slice())?;

    let body_tokens = match &ast.data {
        syn::Data::Struct(data) => {
            let mut names = proc_macro2::TokenStream::new();
            let mut field_tokens = proc_macro2::TokenStream::new();
            check!(
                container_attributes.repr.is_none(),
                ast.span(),
                "'repr(..)' attribute can only be used on an enum"
            );

            let return_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    for field in data.fields.iter() {
                        let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                        field_tokens.extend(impl_deserial_field(
                            field,
                            &field_ident,
                            &source_ident,
                        )?);
                        names.extend(quote!(#field_ident,))
                    }
                    quote!(Ok(#data_name{#names}))
                }
                syn::Fields::Unnamed(_) => {
                    for (i, f) in data.fields.iter().enumerate() {
                        let field_ident = format_ident!("x_{}", i);
                        field_tokens.extend(impl_deserial_field(f, &field_ident, &source_ident)?);
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
        syn::Data::Enum(data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            let source = Ident::new("________________source", Span::call_site());

            let repr = container_attributes.tag_repr(data.variants.len())?;
            let mut tag_checker = TagChecker::default();
            // Flag which is updated when iterating the variants signalling whether any of
            // the variants have a 'forward' attribute.
            let mut some_variant_is_forwarded = false;
            let tag_bytes_ident = format_ident!("tag_bytes");

            for (i, variant) in data.variants.iter().enumerate() {
                let variant_attributes = EnumVariantAttributes::try_from(variant.attrs.as_slice())?;
                container_attributes.check_variant_attributes(&variant_attributes)?;

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

                let variant_ident = &variant.ident;
                if variant_attributes.forwards.is_empty() {
                    let field_tokens: proc_macro2::TokenStream = field_names
                        .iter()
                        .zip(variant.fields.iter())
                        .map(|(name, field)| impl_deserial_field(field, name, &source))
                        .collect::<syn::Result<proc_macro2::TokenStream>>()?;

                    // Get the literal for the tag either from a 'tag' attribute of the index of the
                    // variant. To avoid cloning, the collision checking of tags are done further
                    // down.
                    let (tag_lit, tag_span) = variant_attributes.tag.map_or_else(
                        || {
                            (
                                syn::LitInt::new(i.to_string().as_str(), variant.span()),
                                variant.ident.span(),
                            )
                        },
                        |tag| (tag.value, tag.span),
                    );

                    matches_tokens.extend(quote! {
                        #tag_lit => {
                            #field_tokens
                            Ok(#data_name::#variant_ident #pattern)
                        },
                    });

                    tag_checker.add_and_check(tag_lit, tag_span, variant_ident)?;
                } else {
                    some_variant_is_forwarded = true;
                    check!(
                        variant.fields.len() == 1,
                        variant.span(),
                        "Only enum variants containing a single field can be used with the \
                         'forward' attribute"
                    );
                    let chained_source = format_ident!("___chained_source");

                    let field_tokens: proc_macro2::TokenStream = field_names
                        .iter()
                        .zip(variant.fields.iter())
                        .map(|(name, field)| impl_deserial_field(field, name, &chained_source))
                        .collect::<syn::Result<proc_macro2::TokenStream>>()?;

                    let mut tags = Vec::new();
                    for forward_attribute in variant_attributes.forwards {
                        for tag_lit in forward_attribute.values {
                            tag_checker.add_and_check(
                                tag_lit.clone(),
                                forward_attribute.span,
                                variant_ident,
                            )?;
                            tags.push(tag_lit);
                        }
                    }
                    matches_tokens.extend(quote! {
                        #(#tags)|* => {
                            let mut tag_cursor = Cursor::new(&#tag_bytes_ident);
                            let mut chained_source = #root::Chain::new(&mut tag_cursor, #source_ident);
                            let #chained_source = &mut chained_source;
                            #field_tokens
                            Ok(#data_name::#variant_ident #pattern)
                        },
                    });
                }
            }
            let repr_ident = repr.ident();
            if some_variant_is_forwarded {
                let tag_byte_type_tokens = match repr {
                    ReprAttributeValue::U8 => quote! {[u8; 1]},
                    ReprAttributeValue::U16 => quote! {[u8; 2]},
                };

                quote! {
                    let #tag_bytes_ident = <#tag_byte_type_tokens as #root::Deserial>::deserial(#source_ident)?;
                    let tag = #repr_ident::from_le_bytes(#tag_bytes_ident);
                    match tag {
                        #matches_tokens
                        _ => Err(Default::default())
                    }
                }
            } else {
                quote! {
                    let tag = <#repr_ident as #root::Deserial>::deserial(#source)?;
                    match tag {
                        #matches_tokens
                        _ => Err(Default::default())
                    }
                }
            }
        }
        _ => unimplemented!("#[derive(Deserial)] is not implemented for union."),
    };

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let where_clauses_tokens =
        if let Some(attribute_bounds) = container_attributes.deserial_bounds() {
            attribute_bounds.into_token_stream()
        } else {
            // Extend where clauses with Deserial predicate of each generic.
            let where_clause_deserial: proc_macro2::TokenStream = ast
                .generics
                .type_params()
                .map(|type_param| {
                    let type_param_ident = &type_param.ident;
                    quote! (#type_param_ident: #root::Deserial,)
                })
                .collect();

            if let Some(where_clauses) = where_clauses {
                let predicates = &where_clauses.predicates;
                quote!(#predicates, where_clause_deserial)
            } else {
                where_clause_deserial
            }
        };

    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics #root::Deserial for #data_name #ty_generics where #where_clauses_tokens {
            fn deserial<#read_ident: #root::Read>(#source_ident: &mut #read_ident) -> #root::ParseResult<Self> {
                #body_tokens
            }
        }
    };
    Ok(gen.into())
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

pub fn impl_serial(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;

    let span = ast.span();

    let write_ident = format_ident!("W", span = span);

    let out_ident = format_ident!("out");
    let root = get_root();
    let container_attributes = ContainerAttributes::try_from(ast.attrs.as_slice())?;

    let body = match ast.data {
        syn::Data::Struct(ref data) => {
            check!(
                container_attributes.repr.is_none(),
                ast.span(),
                "'repr(..)' attribute can only be used on an enum",
            );

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

            let repr = container_attributes.tag_repr(data.variants.len())?;
            let mut tag_checker = TagChecker::default();

            for (i, variant) in data.variants.iter().enumerate() {
                let variant_attributes = EnumVariantAttributes::try_from(variant.attrs.as_slice())?;
                container_attributes.check_variant_attributes(&variant_attributes)?;

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

                // Get the literal for the tag either from a 'tag' attribute of the index of the
                // variant. To avoid cloning, the collision checking of tags are done further
                // down.
                let (tag_lit, tag_span) = variant_attributes.tag.map_or_else(
                    || {
                        (
                            syn::LitInt::new(i.to_string().as_str(), variant.span()),
                            variant.ident.span(),
                        )
                    },
                    |tag| (tag.value, tag.span),
                );

                let variant_ident = &variant.ident;
                let repr_ident = repr.ident();
                let tag_lit_size =
                    syn::LitInt::new(format!("{tag_lit}{repr_ident}").as_str(), variant.span());

                let serial_tag_tokens = if variant_attributes.forwards.is_empty() {
                    quote! {#root::Serial::serial(&#tag_lit_size, #out_ident)?;}
                } else {
                    check!(
                        variant.fields.len() == 1,
                        variant.span(),
                        "Only enum variants containing a single field can be used with the \
                         'forward' attribute"
                    );

                    proc_macro2::TokenStream::new()
                };

                matches_tokens.extend(quote! {
                    #data_name::#variant_ident #pattern => {
                        #serial_tag_tokens
                        #field_tokens
                    },
                });

                tag_checker.add_and_check(tag_lit, tag_span, &variant.ident)?;
                for forward_attribute in variant_attributes.forwards {
                    for tag_lit in forward_attribute.values {
                        let span = tag_lit.span();
                        tag_checker.add_and_check(tag_lit, span, variant_ident)?;
                    }
                }
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

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let where_clauses_tokens = if let Some(attribute_bounds) = container_attributes.serial_bounds()
    {
        attribute_bounds.into_token_stream()
    } else {
        let state_parameter_ident = container_attributes
            .state_parameter
            .as_ref()
            .and_then(|type_path| type_path.path.segments.first());
        // Extend where clauses with Serial predicate of each generic.
        let where_clause_serial: proc_macro2::TokenStream = ast
            .generics
            .type_params()
            .filter_map(|type_param| {
                match state_parameter_ident {
                    // Skip adding the predicate for the state_parameter.
                    Some(state_parameter) if state_parameter.ident == type_param.ident => None,
                    _ => {
                        let type_param_ident = &type_param.ident;
                        Some(quote! (#type_param_ident: #root::Serial,))
                    }
                }
            })
            .collect();

        if let Some(where_clauses) = where_clauses {
            let predicates = &where_clauses.predicates;
            quote!(#predicates, where_clause_serial)
        } else {
            where_clause_serial
        }
    };

    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics #root::Serial for #data_name #ty_generics where #where_clauses_tokens {
            fn serial<#write_ident: #root::Write>(&self, #out_ident: &mut #write_ident) -> Result<(), #write_ident::Err> {
                #body
            }
        }
    };
    Ok(gen.into())
}

fn impl_deserial_with_state_field(
    f: &syn::Field,
    state_ident: &syn::Ident,
    ident: &syn::Ident,
    source: &syn::Ident,
    state_parameter: &syn::TypePath,
) -> syn::Result<proc_macro2::TokenStream> {
    let concordium_attributes = get_concordium_field_attributes(&f.attrs)?;
    let ensure_ordered = contains_attribute(&concordium_attributes, "ensure_ordered");
    let size_length = find_length_attribute(&f.attrs)?;
    let has_ctx = ensure_ordered || size_length.is_some();
    let ty = &f.ty;
    if has_ctx {
        // Default size length is u32, i.e. 4 bytes.
        let l = format_ident!("U{}", 8 * size_length.unwrap_or(4));
        Ok(quote! {
            let #ident = <#ty as concordium_std::DeserialCtxWithState<#state_parameter>>::deserial_ctx_with_state(concordium_std::schema::SizeLength::#l, #ensure_ordered, #state_ident, #source)?;
        })
    } else {
        Ok(quote! {
            let #ident = <#ty as concordium_std::DeserialWithState<#state_parameter>>::deserial_with_state(#state_ident, #source)?;
        })
    }
}

pub fn impl_deserial_with_state(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;
    let span = ast.span();
    let read_ident = format_ident!("__R", span = span);
    let container_attributes = ContainerAttributes::try_from(ast.attrs.as_slice())?;

    let state_parameter = match container_attributes.state_parameter {
        Some(ref state_parameter) => state_parameter,
        None => {
            abort!(
                Span::call_site(),
                "DeriveWithState requires the attribute #[concordium(state_parameter = \"S\")], \
                 where \"S\" should be the generic parameter satisfying `HasStateApi`.",
            );
        }
    };

    let source_ident = Ident::new("________________source", Span::call_site());
    let state_ident = Ident::new("_______________________________state", Span::call_site());
    let body_tokens = match ast.data {
        syn::Data::Struct(ref data) => {
            let mut names = proc_macro2::TokenStream::new();
            let mut field_tokens = proc_macro2::TokenStream::new();

            check!(
                container_attributes.repr.is_none(),
                ast.span(),
                "'repr(..)' attribute can only be used on an enum",
            );

            let return_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    for field in data.fields.iter() {
                        let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                        field_tokens.extend(impl_deserial_with_state_field(
                            field,
                            &state_ident,
                            &field_ident,
                            &source_ident,
                            state_parameter,
                        )?);
                        names.extend(quote!(#field_ident,))
                    }
                    quote!(Ok(#data_name{#names}))
                }
                syn::Fields::Unnamed(_) => {
                    for (i, f) in data.fields.iter().enumerate() {
                        let field_ident = format_ident!("x_{}", i);
                        field_tokens.extend(impl_deserial_with_state_field(
                            f,
                            &state_ident,
                            &field_ident,
                            &source_ident,
                            state_parameter,
                        )?);
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

            let repr = container_attributes.tag_repr(data.variants.len())?;
            let state_ident = Ident::new("_______________________________state", Span::call_site());
            let mut tag_checker = TagChecker::default();
            // Flag which is updated when iterating the variants signalling whether any of
            // the variants have a 'forward' attribute.
            let mut some_variant_is_forwarded = false;
            let tag_bytes_ident = format_ident!("tag_bytes");

            for (i, variant) in data.variants.iter().enumerate() {
                let variant_attributes = EnumVariantAttributes::try_from(variant.attrs.as_slice())?;
                container_attributes.check_variant_attributes(&variant_attributes)?;

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

                let variant_ident = &variant.ident;
                if variant_attributes.forwards.is_empty() {
                    let field_tokens: proc_macro2::TokenStream = field_names
                        .iter()
                        .zip(variant.fields.iter())
                        .map(|(name, field)| {
                            impl_deserial_with_state_field(
                                field,
                                &state_ident,
                                name,
                                &source,
                                state_parameter,
                            )
                        })
                        .collect::<syn::Result<proc_macro2::TokenStream>>()?;

                    // Get the literal for the tag either from a 'tag' attribute of the index of the
                    // variant. To avoid cloning, the collision checking of tags are done further
                    // down.
                    let (tag_lit, tag_span) = variant_attributes.tag.map_or_else(
                        || {
                            (
                                syn::LitInt::new(i.to_string().as_str(), variant.span()),
                                variant_ident.span(),
                            )
                        },
                        |tag| (tag.value, tag.span),
                    );

                    matches_tokens.extend(quote! {
                        #tag_lit => {
                            #field_tokens
                            Ok(#data_name::#variant_ident #pattern)
                        },
                    });

                    tag_checker.add_and_check(tag_lit, tag_span, &variant.ident)?;
                } else {
                    some_variant_is_forwarded = true;
                    check!(
                        variant.fields.len() == 1,
                        variant.span(),
                        "Only enum variants containing a single field can be used with the \
                         'forward' attribute"
                    );
                    let chained_source = format_ident!("___chained_source");

                    let field_tokens: proc_macro2::TokenStream = field_names
                        .iter()
                        .zip(variant.fields.iter())
                        .map(|(name, field)| impl_deserial_field(field, name, &chained_source))
                        .collect::<syn::Result<proc_macro2::TokenStream>>()?;

                    let mut tags = Vec::new();
                    for forward_attribute in variant_attributes.forwards {
                        for tag_lit in forward_attribute.values {
                            tag_checker.add_and_check(
                                tag_lit.clone(),
                                forward_attribute.span,
                                variant_ident,
                            )?;
                            tags.push(tag_lit);
                        }
                    }
                    matches_tokens.extend(quote! {
                        #(#tags)|* => {
                            let mut tag_cursor = Cursor::new(&#tag_bytes_ident);
                            let mut chained_source = concordium_std::Chain::new(&mut tag_cursor, #source_ident);
                            let #chained_source = &mut chained_source;
                            #field_tokens
                            Ok(#data_name::#variant_ident #pattern)
                        },
                    });
                }
            }
            let repr_ident = repr.ident();
            if some_variant_is_forwarded {
                let tag_byte_type_tokens = match repr {
                    ReprAttributeValue::U8 => quote! {[u8; 1]},
                    ReprAttributeValue::U16 => quote! {[u8; 2]},
                };

                quote! {
                    let #tag_bytes_ident = <#tag_byte_type_tokens as concordium_std::Deserial>::deserial(#source_ident)?;
                    let tag = #repr_ident::from_le_bytes(#tag_bytes_ident);
                    match tag {
                        #matches_tokens
                        _ => Err(Default::default())
                    }
                }
            } else {
                quote! {
                    let idx = <#repr_ident as concordium_std::Deserial>::deserial(#source)?;
                    match idx {
                        #matches_tokens
                        _ => Err(Default::default())
                    }
                }
            }
        }
        _ => unimplemented!("#[derive(DeserialWithState)] is not implemented for union."),
    };

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let where_clauses_tokens = if let Some(attribute_bounds) =
        container_attributes.deserial_bounds()
    {
        attribute_bounds.into_token_stream()
    } else {
        let state_parameter_ident = state_parameter.path.segments.first();
        // Extend where clauses with Deserial predicate of each generic.
        let where_clause_deserial: proc_macro2::TokenStream = ast
                .generics
                .type_params()
                .filter_map(|type_param| {
                    match state_parameter_ident {
                        // Skip adding the predicate for the state_parameter.
                        Some(state_parameter) if state_parameter.ident == type_param.ident => None,
                        _ => {
                            let type_param_ident = &type_param.ident;
                            Some(quote! (#type_param_ident: concordium_std::DeserialWithState<#state_parameter>,))
                        }
                    }
                })
                .collect();

        if let Some(where_clauses) = where_clauses {
            let predicates = &where_clauses.predicates;
            quote!(#predicates, where_clause_deserial)
        } else {
            where_clause_deserial
        }
    };

    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics concordium_std::DeserialWithState<#state_parameter> for #data_name #ty_generics where #state_parameter : concordium_std::HasStateApi, #where_clauses_tokens {
            fn deserial_with_state<#read_ident: concordium_std::Read>(#state_ident: &#state_parameter, #source_ident: &mut #read_ident) -> concordium_std::ParseResult<Self> {
                #body_tokens
            }
        }
    };
    Ok(gen.into())
}

/// We reserve a number of error codes for custom errors, such as ParseError,
/// that are provided by concordium-std. These reserved error codes can have
/// indices i32::MIN, i32::MIN + 1, ..., RESERVED_ERROR_CODES
const RESERVED_ERROR_CODES: i32 = i32::MIN + 100;

pub fn reject_derive_worker(input: TokenStream) -> syn::Result<TokenStream> {
    let ast: syn::DeriveInput = syn::parse(input)?;
    let enum_data = match &ast.data {
        syn::Data::Enum(data) => Ok(data),
        _ => Err(syn::Error::new(ast.span(), "Reject can only be derived for enums.")),
    }?;
    let enum_ident = &ast.ident;

    // Ensure that the number of enum variants fits into the number of error codes
    // we can generate.
    let too_many_variants = format!(
        "Error enum {} cannot have more than {} variants.",
        enum_ident,
        RESERVED_ERROR_CODES.neg()
    );
    match i32::try_from(enum_data.variants.len()) {
        Ok(n) if n <= RESERVED_ERROR_CODES.neg() => (),
        _ => {
            return Err(syn::Error::new(ast.span(), &too_many_variants));
        }
    };

    let variant_error_conversions = generate_variant_error_conversions(enum_data, enum_ident)?;
    let buf_var_ident = format_ident!("{}", "buf");
    let variant_matches = generate_variant_matches(enum_data, enum_ident, &buf_var_ident);

    let gen = quote! {
        /// The from implementation maps the first variant to -1, second to -2, etc.
        /// NB: This differs from the cast `variant as i32` since we cannot easily modify
        /// the variant tags in the derive macro itself.
        #[automatically_derived]
        impl From<#enum_ident> for Reject {
            #[inline(always)]
            fn from(e: #enum_ident) -> Self {
                let mut #buf_var_ident = Vec::new();
                concordium_std::Serial::serial(&e, &mut #buf_var_ident).unwrap_abort();
                match &e {
                   #variant_matches
                }
            }
        }

        #(#variant_error_conversions)*
    };
    Ok(gen.into())
}

/// Generate the cases for matching on the enum.
/// The error codes for variants start at -1 and go downwards.
/// The whole enum is serialized and included in the return_value field, which,
/// thus, is always `Some`.
fn generate_variant_matches(
    enum_data: &DataEnum,
    enum_name: &syn::Ident,
    buf_var_ident: &syn::Ident,
) -> proc_macro2::TokenStream {
    let mut match_cases = proc_macro2::TokenStream::new();
    for (index, variant) in enum_data.variants.iter().enumerate() {
        let variant_ident = &variant.ident;
        match variant.fields {
            syn::Fields::Named(_) => {
                match_cases.extend(quote! {
                    #enum_name::#variant_ident{..} => Reject {
                        error_code: unsafe { num::NonZeroI32::new_unchecked(-(#index as i32) - 1) },
                        return_value: Some(#buf_var_ident),
                    },
                });
            }
            syn::Fields::Unnamed(_) => {
                match_cases.extend(quote! {
                    #enum_name::#variant_ident(..) => Reject {
                        error_code: unsafe { num::NonZeroI32::new_unchecked(-(#index as i32) - 1) },
                        return_value: Some(#buf_var_ident),
                    },
                });
            }
            syn::Fields::Unit => {
                match_cases.extend(quote! {
                    #enum_name::#variant_ident => Reject {
                        error_code: unsafe { num::NonZeroI32::new_unchecked(-(#index as i32) - 1) },
                        return_value: Some(#buf_var_ident),
                    },
                });
            }
        };
    }
    match_cases
}

/// Generate error conversions for enum variants e.g. for converting
/// `ParseError` to `MyParseErrorWrapper` in
///
/// ```ignore
/// enum MyErrorType {
///   #[from(ParseError)]
///   MyParseErrorWrapper,
///   ...
/// }
/// ```
fn generate_variant_error_conversions(
    enum_data: &DataEnum,
    enum_name: &syn::Ident,
) -> syn::Result<Vec<proc_macro2::TokenStream>> {
    Ok(enum_data
        .variants
        .iter()
        .map(|variant| {
            // in the future we might incorporate explicit discriminants,
            // but the general case of this requires evaluating constant expressions,
            // which is not easily supported at the moment.
            if let Some((_, discriminant)) = variant.discriminant.as_ref() {
                abort!(discriminant.span(), "Explicit discriminants are not yet supported.",);
            }
            let variant_attributes = variant.attrs.iter();
            variant_attributes
                .map(move |attr| {
                    parse_attr_and_gen_error_conversions(attr, enum_name, &variant.ident)
                })
                .collect::<syn::Result<Vec<_>>>()
        })
        .collect::<syn::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .flatten()
        .collect())
}

/// Generate error conversion for a given enum variant.
fn parse_attr_and_gen_error_conversions(
    attr: &syn::Attribute,
    enum_name: &syn::Ident,
    variant_name: &syn::Ident,
) -> syn::Result<Vec<proc_macro2::TokenStream>> {
    let wrong_from_usage = |x: &dyn Spanned| {
        syn::Error::new(
            x.span(),
            "The `from` attribute expects a list of error types, e.g.: #[from(ParseError)].",
        )
    };
    match &attr.meta {
        syn::Meta::List(list) if list.path.is_ident("from") => {
            let mut from_error_names = vec![];
            let nested_metas = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )?;
            for nested in &nested_metas {
                // check that all items in the list are paths
                match nested {
                    Meta::Path(from_error) => {
                        from_error_names.push(from_error);
                    }
                    other => return Err(wrong_from_usage(&other)),
                }
            }
            Ok(from_error_token_stream(&from_error_names, enum_name, variant_name).collect())
        }
        syn::Meta::NameValue(mnv) if mnv.path.is_ident("from") => Err(wrong_from_usage(&mnv)),
        _ => Ok(vec![]),
    }
}

/// Generating the conversion code a la
/// ```ignore
/// impl From<ParseError> for MyErrorType {
///    fn from(x: ParseError) -> Self {
///      MyError::MyParseErrorWrapper
///    }
/// }
/// ```
fn from_error_token_stream<'a>(
    paths: &'a [&'a syn::Path],
    enum_name: &'a syn::Ident,
    variant_name: &'a syn::Ident,
) -> impl Iterator<Item = proc_macro2::TokenStream> + 'a {
    paths.iter().map(move |from_error| {
        quote! {
        impl From<#from_error> for #enum_name {
           #[inline]
           fn from(fe: #from_error) -> Self {
             #enum_name::#variant_name
           }
        }}
    })
}

fn impl_deletable_field(ident: &proc_macro2::TokenStream) -> syn::Result<proc_macro2::TokenStream> {
    Ok(quote!({
        #ident.delete();
    }))
}

pub fn impl_deletable(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;
    let state_parameter = match find_state_parameter_attribute(&ast.attrs)? {
        Some(state_param) => state_param,
        None => {
            return Err(syn::Error::new(
                Span::call_site(),
                "Deletable requires the attribute #[concordium(state_parameter = \"S\")], where \
                 \"S\" should be the HasStateApi generic parameter.",
            ))
        }
    };

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let where_predicates = where_clauses.map(|c| c.predicates.clone());
    let body = match ast.data {
        syn::Data::Struct(ref data) => {
            let fields_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    data.fields
                        .iter()
                        .map(|field| {
                            let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                            let field_ident = quote!(self.#field_ident);
                            impl_deletable_field(&field_ident)
                        })
                        .collect::<syn::Result<_>>()?
                }
                syn::Fields::Unnamed(_) => data
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        let i = syn::LitInt::new(i.to_string().as_str(), Span::call_site());
                        let field_ident = quote!(self.#i);
                        impl_deletable_field(&field_ident)
                    })
                    .collect::<syn::Result<_>>()?,
                syn::Fields::Unit => proc_macro2::TokenStream::new(),
            };
            quote! {
                #fields_tokens
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            for (_, variant) in data.variants.iter().enumerate() {
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
                    .map(|(name, _)| impl_deletable_field(&quote!(#name)))
                    .collect::<syn::Result<_>>()?;
                let variant_ident = &variant.ident;

                matches_tokens.extend(quote! {
                    #data_name::#variant_ident #pattern => {
                        #field_tokens
                    },
                })
            }
            quote! {
                match self {
                    #matches_tokens
                }
            }
        }
        _ => unimplemented!("#[derive(Deletable)] is not implemented for union."),
    };

    let gen = quote! {
        #[automatically_derived]
        impl #impl_generics Deletable for #data_name #ty_generics where #state_parameter : HasStateApi, #where_predicates {
            fn delete(self) {
                use concordium_std::Deletable;
                #body
            }
        }
    };

    Ok(gen.into())
}

pub fn impl_state_clone(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let data_name = &ast.ident;
    let state_parameter = match find_state_parameter_attribute(&ast.attrs)? {
        Some(state_param) => state_param,
        None => {
            abort!(
                Span::call_site(),
                "StateClone requires the attribute #[concordium(state_parameter = \"S\")], where \
                 \"S\" should be the HasStateApi generic parameter.",
            );
        }
    };

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let where_predicates = where_clauses.map(|c| c.predicates.clone());
    let body_tokens = match ast.data {
        syn::Data::Struct(ref data) => {
            let mut field_names = proc_macro2::TokenStream::new();
            let mut field_tokens = proc_macro2::TokenStream::new();
            let return_tokens = match data.fields {
                syn::Fields::Named(_) => {
                    for field in data.fields.iter() {
                        let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                        field_tokens.extend(quote!(let #field_ident = concordium_std::StateClone::clone_state(&self.#field_ident, cloned_state_api);));
                        field_names.extend(quote!(#field_ident,));
                    }
                    quote!(Self{#field_names})
                }
                syn::Fields::Unnamed(_) => {
                    for i in 0..data.fields.len() {
                        let field_index = syn::Index::from(i);
                        let variable_ident = format_ident!("x_{}", i);
                        field_tokens
                            .extend(quote!(let #variable_ident = concordium_std::StateClone::clone_state(&self.#field_index, cloned_state_api);));
                        field_names.extend(quote!(#variable_ident,))
                    }
                    quote!(Self(#field_names))
                }
                syn::Fields::Unit => quote!(Ok(Self {})),
            };
            quote! {
                #field_tokens
                #return_tokens
            }
        }
        syn::Data::Enum(ref data) => {
            let mut matches_tokens = proc_macro2::TokenStream::new();
            for (_, variant) in data.variants.iter().enumerate() {
                let mut field_names = proc_macro2::TokenStream::new();
                let mut field_tokens = proc_macro2::TokenStream::new();
                let variant_ident = &variant.ident;

                let (return_tokens, pattern) = match variant.fields {
                    syn::Fields::Named(_) => {
                        for field in variant.fields.iter() {
                            let field_ident = field.ident.clone().unwrap(); // safe since named fields.
                            field_tokens.extend(quote!(let #field_ident = concordium_std::StateClone::clone_state(#field_ident, cloned_state_api);));
                            field_names.extend(quote!(#field_ident,));
                        }
                        let pattern = quote!({#field_names});
                        (quote!(#data_name::#variant_ident #pattern), pattern)
                    }
                    syn::Fields::Unnamed(_) => {
                        for i in 0..variant.fields.len() {
                            let field_ident = format_ident!("x_{}", i);
                            field_tokens.extend(quote!(let #field_ident = concordium_std::StateClone::clone_state(#field_ident, cloned_state_api);));
                            field_names.extend(quote!(#field_ident,));
                        }
                        let pattern = quote!((#field_names));
                        (quote!(#data_name::#variant_ident #pattern), pattern)
                    }
                    syn::Fields::Unit => (
                        quote!(#data_name::#variant_ident #field_names),
                        proc_macro2::TokenStream::new(),
                    ),
                };
                let variant_ident = &variant.ident;

                matches_tokens.extend(quote! {
                    #data_name::#variant_ident #pattern => {
                        #field_tokens
                        #return_tokens
                    },
                })
            }
            quote! {
                match self {
                    #matches_tokens
                }
            }
        }
        _ => unimplemented!("#[derive(StateClone)] is not implemented for union."),
    };

    let gen = quote! {
        #[automatically_derived]
        unsafe impl #impl_generics concordium_std::StateClone<#state_parameter> for #data_name #ty_generics where #state_parameter: concordium_std::HasStateApi, #where_predicates {
            unsafe fn clone_state(&self, cloned_state_api: &#state_parameter) -> Self {
                #body_tokens
            }
        }
    };

    Ok(gen.into())
}

pub fn schema_type_derive_worker(input: TokenStream) -> syn::Result<TokenStream> {
    let ast: syn::DeriveInput = syn::parse(input)?;

    let data_name = &ast.ident;
    let container_attributes = ContainerAttributes::try_from(ast.attrs.as_slice())?;

    let body = match ast.data {
        syn::Data::Struct(ref data) => {
            check!(
                container_attributes.repr.is_none(),
                ast.span(),
                "'repr(..)' attribute can only be used on an enum",
            );
            if container_attributes.transparent {
                check!(
                    data.fields.len() == 1,
                    ast.span(),
                    "'transparent' attribute can only be used on a struct with a single field",
                );

                // Safe to unwrap below since we already checked the length is one.
                let field = data.fields.iter().next().unwrap();
                schema_type_field_type(field)?
            } else {
                let fields_tokens = schema_type_fields(&data.fields)?;
                quote! {
                    concordium_std::schema::Type::Struct(#fields_tokens)
                }
            }
        }
        syn::Data::Enum(ref data) => {
            check!(
                !container_attributes.transparent,
                ast.span(),
                "'transparent' attribute can only be used on a struct",
            );
            let mut used_variant_names = HashMap::new();
            let mut tag_checker = TagChecker::default();
            let mut some_variant_is_tagged = false;
            let mut some_variant_is_forwarded = false;

            let mut variant_data = Vec::new();
            for (i, variant) in data.variants.iter().enumerate() {
                let variant_attributes = EnumVariantAttributes::try_from(variant.attrs.as_slice())?;
                container_attributes.check_variant_attributes(&variant_attributes)?;

                // Handle the 'rename' attribute.
                let (variant_name, variant_span) = match variant_attributes.rename {
                    Some(rename_attribute) => (rename_attribute.value, rename_attribute.span),
                    None => (variant.ident.to_string(), variant.ident.span()),
                };
                check_for_name_collisions(&mut used_variant_names, &variant_name, variant_span)?;

                some_variant_is_tagged = some_variant_is_tagged || variant_attributes.tag.is_some();
                some_variant_is_forwarded =
                    some_variant_is_forwarded || !variant_attributes.forwards.is_empty();

                let data = if variant_attributes.forwards.is_empty() {
                    // Get the literal for the tag either from a 'tag' attribute of the index of the
                    // variant.
                    let (tag_lit, tag_span) = variant_attributes.tag.map_or_else(
                        || {
                            (
                                syn::LitInt::new(i.to_string().as_str(), variant.span()),
                                variant.ident.span(),
                            )
                        },
                        |tag| (tag.value, tag.span),
                    );

                    tag_checker.add_and_check(tag_lit.clone(), tag_span, &variant.ident)?;

                    let fields_tokens = schema_type_fields(&variant.fields)?;

                    SchemaTypeVariantData::Tagged {
                        tag_lit,
                        variant_tokens: quote! {
                            (concordium_std::String::from(#variant_name), #fields_tokens)
                        },
                    }
                } else {
                    check!(
                        variant.fields.len() == 1,
                        variant.span(),
                        "Only enum variants containing a single field can be used with the \
                         'forward' attribute"
                    );

                    for forward_attribute in variant_attributes.forwards {
                        for tag_lit in forward_attribute.values {
                            tag_checker.add_and_check(
                                tag_lit.clone(),
                                tag_lit.span(),
                                &variant.ident,
                            )?;
                        }
                    }

                    let inner_field = variant.fields.iter().next().unwrap().clone(); // Safe to unwrap because of the above check of the length.
                    SchemaTypeVariantData::Forwards {
                        inner_field,
                    }
                };
                variant_data.push(data);
            }

            if some_variant_is_tagged || some_variant_is_forwarded {
                // Ensure tagged enum is only used with repr(u8).
                if let Some(repr) = &container_attributes.repr {
                    check!(
                        repr.value == ReprAttributeValue::U8,
                        repr.span,
                        "SchemaType only supports 'repr(u8)' when using 'tag' attribute."
                    );
                }
                let variant_map_ident = format_ident!("variant_map");
                let insert_variant_data_tokens: Vec<_> =
                    variant_data.iter().map(|data| {
                        match data {
                            SchemaTypeVariantData::Tagged { tag_lit, variant_tokens } => Ok(quote! {
                                #variant_map_ident.insert(#tag_lit, #variant_tokens);
                            }),
                            SchemaTypeVariantData::Forwards { inner_field } => {
                                let field_schema_type_tokens = schema_type_field_type(inner_field)?;
                                Ok(quote!{
                                    let mut inner_map_option = match #field_schema_type_tokens {
                                        concordium_std::schema::Type::TaggedEnum(map) => map,
                                        concordium_std::schema::Type::Enum(vec) => {
                                            concordium_std::collections::BTreeMap::from_iter(
                                                vec.into_iter().enumerate().map(|(i, variant)| (i as u8, variant)),
                                            )
                                        },
                                        _ => panic!("Using 'forward' attribute for deriving SchemaType is only supported, when the inner type is an enum"),
                                    };
                                    #variant_map_ident.append(&mut inner_map_option);
                                })
                            }
                        }
                    }).collect::<syn::Result<_>>()?;
                quote! {
                    let mut #variant_map_ident = concordium_std::collections::BTreeMap::default();
                    #(#insert_variant_data_tokens)*
                    concordium_std::schema::Type::TaggedEnum(#variant_map_ident)
                }
            } else {
                let variant_tokens: Vec<_> = variant_data
                    .iter()
                    .map(|data| match data {
                        SchemaTypeVariantData::Tagged {
                            variant_tokens,
                            ..
                        } => Ok(variant_tokens),
                        SchemaTypeVariantData::Forwards {
                            ..
                        } => {
                            abort!(
                                ast.span(),
                                "Invariant violated for deriving SchemaType: Forwarding data is \
                                 unexpected here"
                            );
                        }
                    })
                    .collect::<syn::Result<_>>()?;
                quote! {
                    concordium_std::schema::Type::Enum(Vec::from([ #(#variant_tokens),* ]))
                }
            }
        }
        _ => {
            abort!(ast.span(), "Union is not supported");
        }
    };

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let where_clauses_tokens =
        if let Some(attribute_bounds) = container_attributes.schema_type_bounds() {
            attribute_bounds.into_token_stream()
        } else {
            // Extend where clauses bounding generics to implement SchemaType.
            let where_clause_extra: proc_macro2::TokenStream = ast
                .generics
                .type_params()
                .map(|type_param| {
                    let type_param_ident = &type_param.ident;
                    quote! (#type_param_ident: concordium_std::schema::SchemaType,)
                })
                .collect();

            if let Some(where_clauses) = where_clauses {
                let predicates = &where_clauses.predicates;
                quote!(#predicates, where_clause_extra)
            } else {
                where_clause_extra
            }
        };

    let out = quote! {
        #[automatically_derived]
        impl #impl_generics concordium_std::schema::SchemaType for #data_name #ty_generics where #where_clauses_tokens {
            fn get_type() -> concordium_std::schema::Type {
                #body
            }
        }
    };
    Ok(out.into())
}

/// Data tracked per variant when generating the SchemaType implementation.
enum SchemaTypeVariantData {
    /// A tagged variant, either implicitly or explicit.
    Tagged {
        /// The integer literal to used for this variant.
        tag_lit:        syn::LitInt,
        /// Tokens of a string of the variant name paired with the tokens to
        /// implement fields
        variant_tokens: proc_macro2::TokenStream,
    },
    /// A variant forwarding to its inner field.
    Forwards {
        /// The inner field being forwarded to.
        inner_field: syn::Field,
    },
}

/// Find a 'rename' attribute and return its value and span.
/// Checks that the attribute is only defined once and that the value is a
/// string.
fn find_rename_attribute(attributes: &[syn::Attribute]) -> syn::Result<Option<(String, Span)>> {
    let value = match find_field_attribute_value(attributes, "rename")? {
        Some(v) => v,
        None => return Ok(None),
    };

    match value {
        syn::Lit::Str(value) => Ok(Some((value.value(), value.span()))),
        _ => Err(syn::Error::new(value.span(), "Rename attribute value must be a string.")),
    }
}

/// Check for name collisions by inserting the name in the HashMap.
/// On collisions it returns a combined error pointing to the previous and new
/// definition.
fn check_for_name_collisions(
    used_names: &mut HashMap<String, Span>,
    new_name: &str,
    new_span: Span,
) -> syn::Result<()> {
    if let Some(used_span) = used_names.insert(String::from(new_name), new_span) {
        let error_msg = format!("the name `{}` is defined multiple times", new_name);
        let mut error_at_first_def = syn::Error::new(used_span, &error_msg);
        let error_at_second_def = syn::Error::new(new_span, &error_msg);

        // Combine the errors to show both at once
        error_at_first_def.combine(error_at_second_def);

        return Err(error_at_first_def);
    }
    Ok(())
}

fn schema_type_field_type(field: &syn::Field) -> syn::Result<proc_macro2::TokenStream> {
    let field_type = &field.ty;
    if let Some(l) = find_length_attribute(&field.attrs)? {
        let size = format_ident!("U{}", 8 * l);
        Ok(quote! {
            <#field_type as concordium_std::schema::SchemaType>::get_type().set_size_length(concordium_std::schema::SizeLength::#size)
        })
    } else {
        Ok(quote! {
            <#field_type as concordium_std::schema::SchemaType>::get_type()
        })
    }
}

fn schema_type_fields(fields: &syn::Fields) -> syn::Result<proc_macro2::TokenStream> {
    match fields {
        syn::Fields::Named(_) => {
            let mut used_field_names = HashMap::new();
            let fields_tokens: Vec<_> = fields
                .iter()
                .map(|field| {
                    // Handle the 'rename' attribute.
                    let (field_name, field_span) = match find_rename_attribute(&field.attrs)? {
                        Some(name_and_span) => name_and_span,
                        None => (field.ident.clone().unwrap().to_string(), field.ident.span()), // safe since named fields.
                    };
                    check_for_name_collisions(&mut used_field_names, &field_name, field_span)?;

                    let field_schema_type = schema_type_field_type(field)?;
                    Ok(quote! {
                        (concordium_std::String::from(#field_name), #field_schema_type)
                    })
                })
                .collect::<syn::Result<_>>()?;
            Ok(
                quote! { concordium_std::schema::Fields::Named(concordium_std::Vec::from([ #(#fields_tokens),* ])) },
            )
        }
        syn::Fields::Unnamed(_) => {
            let fields_tokens: Vec<_> =
                fields.iter().map(schema_type_field_type).collect::<syn::Result<_>>()?;
            Ok(quote! { concordium_std::schema::Fields::Unnamed([ #(#fields_tokens),* ].to_vec()) })
        }
        syn::Fields::Unit => Ok(quote! { concordium_std::schema::Fields::None }),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test parsing for bound attribute when using syntax for sharing.
    #[test]
    fn test_parse_shared_bounds() {
        let ast: syn::ItemStruct = syn::parse_quote! {
            #[concordium(bound = "T: B")]
            struct MyStruct<T>{
                field: T
            }
        };

        let parsed = ContainerAttributes::try_from(ast.attrs.as_slice())
            .expect("Failed to parse container attributes");

        assert!(parsed.deserial_bounds().is_some(), "Failed to add shared bound");
        assert!(parsed.serial_bounds().is_some(), "Failed to add shared bound");
        assert!(parsed.schema_type_bounds().is_some(), "Failed to add shared bound");
    }

    /// Test parsing for bound attribute when using syntax for Deserial
    /// explicit.
    #[test]
    fn test_parse_deserial_explicit_bounds() {
        let ast: syn::ItemStruct = syn::parse_quote! {
            #[concordium(bound(deserial  = "T: B"))]
            struct MyStruct<T>{
                field: T
            }
        };

        let parsed = ContainerAttributes::try_from(ast.attrs.as_slice())
            .expect("Failed to parse container attributes");

        assert!(parsed.deserial_bounds().is_some(), "Failed to add explicit bound");
        assert!(parsed.serial_bounds().is_none(), "Unexpected bound added for Serial");
        assert!(parsed.schema_type_bounds().is_none(), "Unexpected bound added for SchemaType");
    }

    /// Test parsing for bound attribute when using syntax for Serial explicit.
    #[test]
    fn test_parse_serial_explicit_bounds() {
        let ast: syn::ItemStruct = syn::parse_quote! {
            #[concordium(bound(serial  = "T: B"))]
            struct MyStruct<T>{
                field: T
            }
        };

        let parsed = ContainerAttributes::try_from(ast.attrs.as_slice())
            .expect("Failed to parse container attributes");

        assert!(parsed.serial_bounds().is_some(), "Failed to add explicit bound");
        assert!(parsed.deserial_bounds().is_none(), "Unexpected bound added for Deserial");
        assert!(parsed.schema_type_bounds().is_none(), "Unexpected bound added for SchemaType");
    }

    /// Test parsing for bound attribute when using syntax for SchemaType
    /// explicit.
    #[test]
    fn test_parse_schema_type_explicit_bounds() {
        let ast: syn::ItemStruct = syn::parse_quote! {
            #[concordium(bound(schema_type  = "T: B"))]
            struct MyStruct<T>{
                field: T
            }
        };

        let parsed = ContainerAttributes::try_from(ast.attrs.as_slice())
            .expect("Failed to parse container attributes");

        assert!(parsed.deserial_bounds().is_none(), "Unexpected bound added for Deserial");
        assert!(parsed.serial_bounds().is_none(), "Unexpected bound added for Serial");
        assert!(parsed.schema_type_bounds().is_some(), "Failed to add explicit bound");
    }

    /// Test parsing for transparent attribute.
    #[test]
    fn test_parse_attribute_transparent() {
        let ast: syn::ItemStruct = syn::parse_quote! {
            #[concordium(transparent)]
            struct MyStruct{
                field: u32
            }
        };

        let parsed = ContainerAttributes::try_from(ast.attrs.as_slice())
            .expect("Failed to parse container attributes");

        assert!(parsed.transparent, "Failed to parse attribute");
    }
}
