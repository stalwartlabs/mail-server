/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, parse_macro_input};

#[proc_macro_derive(EnumMethods)]
pub fn enum_id(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let variants = match input.data {
        Data::Enum(ref data) => &data.variants,
        _ => panic!("EnumMethods only works on enums"),
    };

    let variant_count = variants.len();
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let variant_ids: Vec<usize> = (0..variant_count).collect();
    let snake_case_names: Vec<String> = variant_names
        .iter()
        .map(|name| to_snake_case(&name.to_string()))
        .collect();

    let expanded = quote! {
        impl #name {
            pub const COUNT: usize = #variant_count;

            pub const fn id(&self) -> usize {
                match self {
                    #(#name::#variant_names => #variant_ids,)*
                }
            }

            pub fn from_id(id: usize) -> Option<Self> {
                match id {
                    #(#variant_ids => Some(#name::#variant_names),)*
                    _ => None,
                }
            }

            pub fn name(&self) -> &'static str {
                match self {
                    #(#name::#variant_names => #snake_case_names,)*
                }
            }

            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    #(#snake_case_names => Some(#name::#variant_names),)*
                    _ => None,
                }
            }
        }
    };

    TokenStream::from(expanded)
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.char_indices() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('-');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}
