extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;
use syn::spanned::Spanned;

use proc_macro::TokenStream;

use proc_macro2;

#[proc_macro_derive(Get, attributes(size_length))]
pub fn get_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    impl_get(&ast)
}

fn find_length_attribute(l: &[syn::Attribute]) -> Option<u32> {
    let length = format_ident!("size_length");
    for attr in l.iter() {
        if let Ok(syn::Meta::NameValue(mn)) = attr.parse_meta() {
            if mn.path.is_ident(&length) {
                if let syn::Lit::Int(int) = mn.lit {
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
                    panic!("Unknown attribute value {:?}.", mn.lit);
                }
            }
        }
    }
    return None;
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
        let mut pusher = |f: &syn::Field, ident| {
            if let Some(l) = find_length_attribute(&f.attrs) {
                let id = format_ident!("u{}", 2u64.pow(l));
                tokens.extend(quote! {
                    let #ident = {
                        let len: #id = self.get()?;
                        get_vector_no_length(self, usize::try_from(len)?)?
                    };
                });
            } else {
                tokens.extend(quote! {
                    let #ident = self.get()?;
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
                    impl #constraints Get<#name #ty_generics #where_clauses> for #ident {
                        fn get(&mut self) -> Fallible<#name #ty_generics> {
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

#[proc_macro_derive(Put, attributes(size_length))]
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
                    if let Some(l) = find_length_attribute(&f.attrs) {
                        let id = format_ident!("u{}", 2u64.pow(l));
                        body.extend(quote! {
                            let len: #id = #arg_name.#ident.len() as #id;
                            self.put(&len);
                            put_vector_no_length(self, &#arg_name.#ident)
                        });
                    } else {
                        body.extend(quote! {
                            self.put(&#arg_name.#ident);
                        });
                    }
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
                for (i, f) in data.fields.iter().enumerate() {
                    let ident = format_ident!("x_{}", i);

                    if let Some(l) = find_length_attribute(&f.attrs) {
                        let id = format_ident!("u{}", 2u64.pow(l));
                        let len_ident = format_ident!("len_{}", i);
                        body.extend(quote! {
                            let #len_ident: #id = #ident.len() as #id;
                            self.put(&#len_ident);
                            put_vector_no_length(self, &#ident);
                        });
                    } else {
                        body.extend(quote!(self.put(#ident);));
                    }
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

#[proc_macro_derive(Serialize, attributes(size_length))]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Cannot parse input.");
    let mut tokens = impl_get(&ast);
    tokens.extend(impl_put(&ast));
    tokens
}
