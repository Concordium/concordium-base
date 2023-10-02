//! Derive macros for deriving serialization in the Concordium binary format.
//! This crate is intended to be used together with the [`concordium_base`](https://crates.io/crates/concordium_base)
//! crate and should **not** be imported directly.
//!
//! The derivation macros will only work in a context where `concordium_base` is
//! available as a module.

#[macro_use]
extern crate quote;
use proc_macro::TokenStream;
use syn::spanned::Spanned;

fn get_root() -> proc_macro2::TokenStream { quote!(concordium_base) }

/// Derive a [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) and
/// [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) implementations for the type.
/// **This differs from [`serde`](https://serde.rs/)'s serialization macros.** Here the value is
/// first serialized according to its `concordium_base::Serialize`
/// implementation and then hex encoded into a string.
#[proc_macro_derive(SerdeBase16Serialize)]
pub fn serde_base16_serialize_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Cannot parse input.");
    let name = &ast.ident;
    let span = ast.span();
    let ast_cloned = ast.clone();
    let (_, ty_generics, where_clauses) = ast_cloned.generics.split_for_impl();

    let serial_generics = ast.generics.clone();
    let (serial_impl_generics, _, _) = serial_generics.split_for_impl();

    // There is an additional lifetime parameter for deserialization.
    let mut deserial_generics = ast.generics;
    let lifetime = syn::LifetimeParam::new(syn::Lifetime::new("'de", span));
    deserial_generics
        .params
        .push(syn::GenericParam::Lifetime(lifetime.clone()));
    let (deserial_impl_generics, _, _) = deserial_generics.split_for_impl();

    let ident = format_ident!("GenericSerializerType", span = span);
    let ident_serializer = format_ident!("serializer", span = span);
    let ident_deserializer = format_ident!("deserializer", span = span);
    let root = get_root();
    let gen = quote! {
        #[automatically_derived]
        impl #serial_impl_generics #root::common::SerdeSerialize for #name #ty_generics #where_clauses {
            fn serialize<#ident: #root::common::SerdeSerializer>(&self, #ident_serializer: #ident) -> Result<#ident::Ok, #ident::Error> {
                #root::common::base16_encode(self, #ident_serializer)
            }
        }

        #[automatically_derived]
        impl #deserial_impl_generics #root::common::SerdeDeserialize<#lifetime> for #name #ty_generics #where_clauses {
            fn deserialize<#ident: #root::common::SerdeDeserializer<#lifetime>>(#ident_deserializer: #ident) -> Result<Self, #ident::Error> {
                #root::common::base16_decode::<#lifetime, #ident, #name #ty_generics>(#ident_deserializer)
            }
        }
    };
    gen.into()
}

/// Like [`SerdeBase16Serialize`](serde_base16_serialize_derive), but assuming
/// that the `concordium_base::Serialize` implementation puts the length of the
/// data as 4 bytes in big endian. These 4 bytes are dropped when converting to
/// hex since the JSON format is self-describing so the length is not needed.
#[proc_macro_derive(SerdeBase16IgnoreLengthSerialize)]
pub fn serde_base16_ignore_length_serialize_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Cannot parse input.");
    let name = &ast.ident;
    let span = ast.span();
    let ast_cloned = ast.clone();
    let (_, ty_generics, where_clauses) = ast_cloned.generics.split_for_impl();

    let serial_generics = ast.generics.clone();
    let (serial_impl_generics, _, _) = serial_generics.split_for_impl();

    // There is an additional lifetime parameter for deserialization.
    let mut deserial_generics = ast.generics;
    let lifetime = syn::LifetimeParam::new(syn::Lifetime::new("'de", span));
    deserial_generics
        .params
        .push(syn::GenericParam::Lifetime(lifetime.clone()));
    let (deserial_impl_generics, _, _) = deserial_generics.split_for_impl();
    let root = get_root();
    let ident = format_ident!("GenericSerializerType", span = span);
    let ident_serializer = format_ident!("serializer", span = span);
    let ident_deserializer = format_ident!("deserializer", span = span);
    let gen = quote! {
        #[automatically_derived]
        impl #serial_impl_generics #root::common::SerdeSerialize for #name #ty_generics #where_clauses {
            fn serialize<#ident: #root::common::SerdeSerializer>(&self, #ident_serializer: #ident) -> Result<#ident::Ok, #ident::Error> {
                base16_ignore_length_encode(self, #ident_serializer)
            }
        }

        #[automatically_derived]
        impl #deserial_impl_generics #root::common::SerdeDeserialize<#lifetime> for #name #ty_generics #where_clauses {
            fn deserialize<#ident: #root::common::SerdeDeserializer<#lifetime>>(#ident_deserializer: #ident) -> Result<Self, #ident::Error> {
                base16_ignore_length_decode::<#lifetime, #ident, #name #ty_generics>(#ident_deserializer)
            }
        }
    };
    gen.into()
}

/// Derive the [`Deserial`](https://docs.rs/concordium-std/latest/concordium_base/common/trait.Deserial.html)
/// trait. At present this only applies to `struct`'s.
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
        if let syn::Meta::NameValue(mn) = &attr.meta {
            if mn.path.is_ident(&length) {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(int),
                    ..
                }) = &mn.value
                {
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
                    panic!("Unknown attribute value {:?}.", mn.value);
                }
            }
        }
    }
    None
}

fn impl_deserial(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let span = ast.span();

    let ident = format_ident!("GenericReaderType", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();
    let root = get_root();

    if let syn::Data::Struct(ref data) = ast.data {
        let mut tokens = proc_macro2::TokenStream::new();
        let mut names = proc_macro2::TokenStream::new();
        let source = format_ident!("source");
        let mut pusher = |f: &syn::Field, ident| {
            if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
                let id = format_ident!("u{}", 8 * l);
                tokens.extend(quote! {
                    let #ident = {
                        let len: #id = #id::deserial(#source)?;
                        #root::common::deserial_vector_no_length(#source, usize::try_from(len)?)?
                    };
                });
            } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
                let id = format_ident!("u{}", 8 * l);
                tokens.extend(quote! {
                    let #ident = {
                        let len: #id = #id::deserial(#source)?;
                        #root::common::deserial_map_no_length(#source, usize::try_from(len)?)?
                    };
                });
            } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
                let id = format_ident!("u{}", 8 * l);
                tokens.extend(quote! {
                    let #ident = {
                        let len: #id = #id::deserial(#source)?;
                        #root::common::deserial_set_no_length(#source, usize::try_from(len)?)?
                    };
                });
            } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
                let id = format_ident!("u{}", 8 * l);
                tokens.extend(quote! {
                    let #ident = {
                        let len: #id = #id::deserial(#source)?;
                        #root::common::deserial_string(#source, usize::try_from(len)?)?
                    };
                });
            } else {
                let ty = &f.ty;
                tokens.extend(quote! {
                    let #ident = <#ty as #root::common::Deserial>::deserial(#source)?;
                });
            }
            names.extend(quote!(#ident,))
        };
        let gen = match data.fields {
            syn::Fields::Named(_) => {
                for f in data.fields.iter() {
                    let ident = f.ident.clone().unwrap(); // safe since named fields.
                    pusher(f, ident);
                }
                quote! {
                    #[automatically_derived]
                    impl #impl_generics #root::common::Deserial for #name #ty_generics #where_clauses {
                        #[allow(non_snake_case)]
                        fn deserial<#ident: #root::common::ReadBytesExt>(#source: &mut #ident) -> #root::common::ParseResult<Self> {
                            use std::convert::TryFrom;
                            #tokens
                            Ok(#name{#names})
                        }
                    }
                }
            }
            syn::Fields::Unnamed(_) => {
                for (i, f) in data.fields.iter().enumerate() {
                    let ident = format_ident!("x_{}", i);
                    pusher(f, ident);
                }
                quote! {
                    #[automatically_derived]
                    impl #impl_generics #root::common::Deserial for #name #ty_generics #where_clauses {
                        fn deserial<#ident: #root::common::ReadBytesExt>(#source: &mut #ident) -> #root::common::ParseResult<Self> {
                            use std::convert::TryFrom;
                            #tokens
                            Ok(#name(#names))
                        }
                    }
                }
            }
            _ => panic!("#[derive(Deserial)] not implemented for empty structs."),
        };
        gen.into()
    } else {
        panic!("#[derive(Deserial)] only implemented for structs.")
    }
}

/// Derive the [`Serial`](https://docs.rs/concordium-std/latest/concordium_base/common/trait.Serial.html)
/// trait. At present this only applies to `struct`'s.
#[proc_macro_derive(
    Serial,
    attributes(size_length, map_size_length, set_size_length, string_size_length)
)]
pub fn serial_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_serial(&ast)
}

fn impl_serial(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let span = ast.span();

    let ident = format_ident!("GenericBufferType", span = span);

    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let root = get_root();

    let out = format_ident!("out");
    if let syn::Data::Struct(ref data) = ast.data {
        let gen = match data.fields {
            syn::Fields::Named(_) => {
                let mut body = proc_macro2::TokenStream::new();
                for f in data.fields.iter() {
                    let ident = f.ident.clone().unwrap(); // safe since named fields.
                    if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        body.extend(quote! {
                            let len: #id = self.#ident.len() as #id;
                            len.serial(#out);
                            #root::common::serial_vector_no_length(&self.#ident, #out);
                        });
                    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        body.extend(quote! {
                            let len: #id = self.#ident.len() as #id;
                            len.serial(#out);
                            #root::common::serial_map_no_length(&self.#ident, #out);
                        })
                    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        body.extend(quote! {
                            let len: #id = self.#ident.len() as #id;
                            len.serial(#out);
                            #root::common::serial_set_no_length(&self.#ident, #out);
                        })
                    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        body.extend(quote! {
                            let len: #id = self.#ident.len() as #id;
                            len.serial(#out);
                            #root::common::serial_string(self.#ident.as_str(), #out);
                        })
                    } else {
                        body.extend(quote! {
                            self.#ident.serial(#out);
                        });
                    }
                }
                quote! {
                    #[automatically_derived]
                    impl #impl_generics #root::common::Serial for #name #ty_generics #where_clauses {
                        fn serial<#ident: #root::common::Buffer>(&self, #out: &mut #ident) {
                            #body
                        }
                    }
                }
            }

            syn::Fields::Unnamed(_) => {
                // this is a hack because I don't know how to generate tuple access expressions
                // easily
                let mut names = proc_macro2::TokenStream::new();
                let mut body = proc_macro2::TokenStream::new();
                for (i, f) in data.fields.iter().enumerate() {
                    let ident = format_ident!("x_{}", i);

                    if let Some(l) = find_length_attribute(&f.attrs, "size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        let len_ident = format_ident!("len_{}", i);
                        body.extend(quote! {
                            let #len_ident: #id = #ident.len() as #id;
                            #len_ident.serial(#out);
                            serial_vector_no_length(#ident, #out);
                        });
                    } else if let Some(l) = find_length_attribute(&f.attrs, "map_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        let len_ident = format_ident!("len_{}", i);
                        body.extend(quote! {
                            let #len_ident: #id = #ident.len() as #id;
                            #len_ident.serial(#out);
                            serial_map_no_length(&self.#ident, #out);
                        })
                    } else if let Some(l) = find_length_attribute(&f.attrs, "set_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        let len_ident = format_ident!("len_{}", i);
                        body.extend(quote! {
                            let #len_ident: #id = #ident.len() as #id;
                            #len_ident.serial(#out);
                            serial_set_no_length(&self.#ident, #out);
                        })
                    } else if let Some(l) = find_length_attribute(&f.attrs, "string_size_length") {
                        let id = format_ident!("u{}", 8 * l);
                        let len_ident = format_ident!("len_{}", i);
                        body.extend(quote! {
                            let #len_ident: #id = #ident.len() as #id;
                            #len_ident.serial(#out);
                            serial_string(self.#ident.as_str(), #out);
                        })
                    } else {
                        body.extend(quote!(#ident.serial(#out);));
                    }
                    names.extend(quote!(ref #ident,))
                }
                quote! {
                    #[automatically_derived]
                    impl #impl_generics Serial for #name #ty_generics #where_clauses {
                        fn serial<#ident: #root::common::Buffer>(&self, #out: &mut #ident) {
                            let #name( #names ) = self;
                            #body
                        }
                    }
                }
            }
            _ => panic!("#[derive(Serial)] not implemented for empty structs."),
        };
        gen.into()
    } else {
        panic!("#[derive(Serial)] only implemented for structs.")
    }
}

/// Derive both [`Serial`](https://docs.rs/concordium-std/latest/concordium_base/common/trait.Serial.html)
/// and [`Deserial`](https://docs.rs/concordium-std/latest/concordium_base/common/trait.Deserial.html) traits.
/// At present this only applies to `struct`'s.
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
