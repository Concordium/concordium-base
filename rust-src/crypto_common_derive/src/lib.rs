extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;
use syn::spanned::Spanned;

use proc_macro::TokenStream;

use proc_macro2;

#[proc_macro_derive(Get)]
pub fn get_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_get(&ast)
}

fn impl_get(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let span = ast.span();

    let ident = format_ident!("GenericType", span = span);

    let r = syn::parse::<syn::TypeParam>((quote!(#ident: ReadBytesExt)).into()).unwrap();

    let mut params = ast.generics.params.clone();
    params.push(syn::GenericParam::Type(r));

    let constraints = syn::Generics {
        params,
        ..ast.generics.clone()
    };

    let (_, ty_generics, where_clauses) = ast.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = ast.data {
        let mut tokens = proc_macro2::TokenStream::new();
        let mut names = proc_macro2::TokenStream::new();
        let gen = match data.fields {
            syn::Fields::Named(_) => {
                for f in data.fields.iter() {
                    let ident = f.ident.clone().unwrap(); // safe since named fields.
                    tokens.extend(quote! {
                        let #ident = self.get()?;
                    });
                    names.extend(quote!(#ident,))
                }
                quote! {
                    impl #constraints Get<#name #ty_generics #where_clauses> for #ident {
                        fn get(&mut self) -> Fallible<#name #ty_generics> {
                            #tokens
                            Ok(#name{#names})
                        }
                    }
                }
            }
            syn::Fields::Unnamed(_) => {
                for (i, _) in data.fields.iter().enumerate() {
                    let ident = format_ident!("x_{}", i);
                    tokens.extend(quote! {
                        let #ident = self.get()?;
                    });
                    names.extend(quote!(#ident,))
                }
                quote! {
                    impl #constraints Get<#name #ty_generics #where_clauses> for #ident {
                        fn get(&mut self) -> Fallible<#name #ty_generics> {
                            #tokens
                            Ok(#name(#names))
                        }
                    }
                }
            }
            _ => panic!("#[derive(Get)] not implemented for empty structs."),
        };
        gen.into()
    } else {
        panic!("#[derive(Get)] only implemented for structs.")
    }
}

#[proc_macro_derive(Put)]
pub fn put_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_put(&ast)
}

fn impl_put(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let span = ast.span();

    let ident = format_ident!("GenericType", span = span);

    let r = syn::parse::<syn::TypeParam>((quote!(#ident: Buffer)).into()).unwrap();

    let mut params = ast.generics.params.clone();
    params.push(syn::GenericParam::Type(r));

    let constraints = syn::Generics {
        params,
        ..ast.generics.clone()
    };

    let (_, ty_generics, where_clauses) = ast.generics.split_for_impl();

    if let syn::Data::Struct(ref data) = ast.data {
        let gen = match data.fields {
            syn::Fields::Named(_) => {
                let mut body = proc_macro2::TokenStream::new();
                let arg_name = format_ident!("arg");
                for f in data.fields.iter() {
                    let ident = f.ident.clone().unwrap(); // safe since named fields.
                    body.extend(quote! {
                        self.put(&#arg_name.#ident);
                    });
                }
                quote! {
                    impl #constraints Put<#name #ty_generics #where_clauses> for #ident {
                        fn put(&mut self, #arg_name: &#name #ty_generics) {
                            #body
                        }
                    }
                }
            }
            syn::Fields::Unnamed(_) => {
                let arg_name = format_ident!("arg");
                // this is a hack because I don't know how to generate tuple access expressions
                // easily
                let mut names = proc_macro2::TokenStream::new();
                let mut body = proc_macro2::TokenStream::new();
                for (i, _) in data.fields.iter().enumerate() {
                    let ident = format_ident!("x_{}", i);
                    body.extend(quote!(self.put(#ident);));
                    names.extend(quote!(ref #ident,))
                }
                quote! {
                    impl #constraints Put<#name #ty_generics #where_clauses> for #ident {
                        fn put(&mut self, #arg_name: &#name #ty_generics) {
                            let #name( #names ) = #arg_name;
                            #body
                        }
                    }
                }
            }
            _ => panic!("#[derive(Get)] not implemented for empty structs."),
        };
        gen.into()
    } else {
        panic!("#[derive(Get)] only implemented for structs.")
    }
}
