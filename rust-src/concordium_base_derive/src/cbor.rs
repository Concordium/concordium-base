use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DataStruct, Fields};
use crate::get_crate_root;

fn get_cbor_module() -> syn::Result<TokenStream> {
    let crate_root = get_crate_root()?;
    Ok(quote!(#crate_root::internal::cbor))
}

pub fn impl_cbor_deserialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    todo!()
}

pub fn impl_cbor_serialize(ast: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clauses) = ast.generics.split_for_impl();

    let cbor_module = get_cbor_module()?;

    match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields_named),
            ..
        }) => Ok(quote! {

            impl #impl_generics #cbor_module::CborSerialize for #name #ty_generics #where_clauses {
                fn serialize<C: #cbor_module::CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
                    todo!()
                }
            }
        }),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "CborSerialize can only be applied to structs with named fields",
        )),
    }
}
