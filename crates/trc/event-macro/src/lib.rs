/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

static mut GLOBAL_ID_COUNTER: usize = 0;

#[proc_macro_attribute]
pub fn event_type(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();
    let prefix = to_snake_case(name_str.strip_suffix("Event").unwrap_or(&name_str));

    let enum_variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("This macro only works with enums"),
    };

    let mut variant_ids = Vec::new();
    let mut variant_names = Vec::new();
    let mut event_names = Vec::new();

    for variant in enum_variants {
        unsafe {
            variant_ids.push(GLOBAL_ID_COUNTER);
            GLOBAL_ID_COUNTER += 1;
        }
        let variant_name = &variant.ident;
        event_names.push(format!(
            "{prefix}.{}",
            to_snake_case(&variant_name.to_string())
        ));
        variant_names.push(variant_name);
    }

    let id_fn = quote! {
        pub const fn id(&self) -> usize {
            match self {
                #(Self::#variant_names => #variant_ids,)*
            }
        }
    };

    let name_fn = quote! {
        pub fn name(&self) -> &'static str {
            match self {
                #(Self::#variant_names => #event_names,)*
            }
        }
    };

    let parse_fn = quote! {
        pub fn try_parse(name: &str) -> Option<Self> {
            match name {
                #(#event_names => Some(Self::#variant_names),)*
                _ => None,
            }
        }
    };

    let variants_fn = quote! {
        pub fn variants() -> &'static [Self] {
            static VARIANTS: &'static [#name] = &[
                #(#name::#variant_names,)*
            ];
            VARIANTS
        }
    };

    let expanded = quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum #name {
            #(#variant_names),*
        }

        impl #name {
            #id_fn
            #name_fn
            #parse_fn
            #variants_fn
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn event_family(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("EventType must be an enum"),
    };

    let variant_idents: Vec<_> = variants.iter().map(|v| &v.ident).collect();

    let event_types: Vec<_> = variants
        .iter()
        .map(|v| match &v.fields {
            Fields::Unnamed(fields) => &fields.unnamed[0],
            _ => panic!("EventType variants must be unnamed and contain a single type"),
        })
        .map(|f| &f.ty)
        .collect();

    let variant_names: Vec<_> = variant_idents
        .iter()
        .map(|ident| {
            let name_str = ident.to_string();
            to_snake_case(name_str.strip_suffix("Event").unwrap_or(&name_str))
        })
        .collect();

    let expanded = quote! {
        pub enum #name {
            #(#variant_idents(#event_types)),*
        }

        impl #name {
            pub const fn id(&self) -> usize {
                match self {
                    #(#name::#variant_idents(e) => e.id()),*
                }
            }

            pub fn name(&self) -> &'static str {
                match self {
                    #(#name::#variant_idents(e) => e.name()),*
                }
            }

            pub fn try_parse(name: &str) -> Option<Self> {
                match name.trim().split_once('.')?.0 {
                #(
                    #variant_names =>  <#event_types>::try_parse(&name).map(#name::#variant_idents),
                )*
                    _ => None,
                }
            }

            pub fn variants() -> Vec<#name> {
                let mut variants = Vec::new();
                #(
                    variants.extend(<#event_types>::variants().iter().copied().map(#name::#variant_idents));
                )*
                variants
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn camel_names(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;

    let enum_variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("This macro only works with enums"),
    };

    let mut variant_names = Vec::new();
    let mut camel_case_names = Vec::new();

    for variant in enum_variants.iter() {
        let variant_name = &variant.ident;
        variant_names.push(variant_name);
        let camel_case_name = variant_name
            .to_string()
            .char_indices()
            .map(|(i, c)| if i == 0 { c.to_ascii_lowercase() } else { c })
            .collect::<String>();
        camel_case_names.push(camel_case_name);
    }

    let name_fn = quote! {
        pub fn name(&self) -> &'static str {
            match self {
                #(Self::#variant_names => #camel_case_names,)*
            }
        }
    };

    let expanded = quote! {
        #input

        impl #name {
            #name_fn
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro]
pub fn total_event_count(_item: TokenStream) -> TokenStream {
    let count = unsafe { GLOBAL_ID_COUNTER };
    let expanded = quote! {
        #count
    };
    TokenStream::from(expanded)
}

fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (idx, ch) in name.char_indices() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
