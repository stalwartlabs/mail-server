/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, Data, DeriveInput, Expr, ExprPath, Fields, Ident, Token,
};

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
        pub const fn variants() -> &'static [Self] {
            &[
                #(#name::#variant_names,)*
            ]
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

            pub const fn variants() -> [#name; crate::TOTAL_EVENT_COUNT] {
                let mut variants = [crate::EventType::Eval(crate::EvalEvent::Error); crate::TOTAL_EVENT_COUNT];
                #(
                    {
                        let sub_variants = <#event_types>::variants();
                        let mut i = 0;
                        while i < sub_variants.len() {
                            variants[sub_variants[i].id()] = #name::#variant_idents(sub_variants[i]);
                            i += 1;
                        }

                    }
                )*
                variants
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn key_names(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;

    let enum_variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => panic!("This macro only works with enums"),
    };

    let mut variant_names = Vec::new();
    let mut camel_case_names = Vec::new();
    let mut snake_case_names = Vec::new();

    for variant in enum_variants.iter() {
        let variant_name = &variant.ident;
        variant_names.push(variant_name);
        snake_case_names.push(to_snake_case(&variant_name.to_string()));
        camel_case_names.push(
            variant_name
                .to_string()
                .char_indices()
                .map(|(i, c)| if i == 0 { c.to_ascii_lowercase() } else { c })
                .collect::<String>(),
        );
    }

    let id_fn = quote! {
        pub fn id(&self) -> &'static str {
            match self {
                #(Self::#variant_names => #snake_case_names,)*
            }
        }
    };

    let name_fn = quote! {
        pub fn name(&self) -> &'static str {
            match self {
                #(Self::#variant_names => #camel_case_names,)*
            }
        }
    };

    let parse_fn = quote! {
        pub fn try_parse(name: &str) -> Option<Self> {
            match name {
                #(#snake_case_names => Some(Self::#variant_names),)*
                _ => None,
            }
        }
    };

    let expanded = quote! {
        #input

        impl #name {
            #name_fn
            #id_fn
            #parse_fn
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

struct EventMacroInput {
    event: Ident,
    param: Expr,
    key_values: Vec<(Ident, Expr)>,
}

impl Parse for EventMacroInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let event: Ident = input.parse()?;
        let content;
        syn::parenthesized!(content in input);
        let param: Expr = content.parse()?;

        let mut key_values = Vec::new();
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: Expr = input.parse()?;
            key_values.push((key, value));
        }

        Ok(EventMacroInput {
            event,
            param,
            key_values,
        })
    }
}

#[proc_macro]
pub fn event(input: TokenStream) -> TokenStream {
    let EventMacroInput {
        event,
        param,
        key_values,
    } = parse_macro_input!(input as EventMacroInput);

    let key_value_tokens = key_values.iter().map(|(key, value)| {
        quote! {
            (trc::Key::#key, trc::Value::from(#value))
        }
    });
    // This avoid having to evaluate expensive values when we know we are not interested in the event
    let key_value_metric_tokens = key_values.iter().filter_map(|(key, value)| {
        if key.is_metric_key() {
            Some(quote! {
                (trc::Key::#key, trc::Value::from(#value))
            })
        } else {
            None
        }
    });

    let expanded = if matches!(&param, Expr::Path(ExprPath { path, .. })  if path.segments.len() > 1 && path.segments.last().unwrap().arguments.is_empty() )
    {
        quote! {{
            const ET: trc::EventType = trc::EventType::#event(#param);
            const ET_ID: usize = ET.id();
            if trc::Collector::has_interest(ET_ID) {
                let keys = vec![#(#key_value_tokens),*];
                if trc::Collector::is_metric(ET_ID) {
                    trc::Collector::record_metric(ET, ET_ID, &keys);
                }
                trc::Event::with_keys(ET, keys).send();
            } else if trc::Collector::is_metric(ET_ID) {
                trc::Collector::record_metric(ET, ET_ID, &[#(#key_value_metric_tokens),*]);
            }
        }}
    } else {
        quote! {{
            let et = trc::EventType::#event(#param);
            let et_id = et.id();
            if trc::Collector::has_interest(et_id) {
                let keys = vec![#(#key_value_tokens),*];
                if trc::Collector::is_metric(et_id) {
                    trc::Collector::record_metric(et, et_id, &keys);
                }
                trc::Event::with_keys(et, keys).send();
            } else if trc::Collector::is_metric(et_id) {
                trc::Collector::record_metric(et, et_id, &[#(#key_value_metric_tokens),*]);
            }
        }}
    };

    TokenStream::from(expanded)
}

trait IsMetricKey {
    fn is_metric_key(&self) -> bool;
}

impl IsMetricKey for Ident {
    fn is_metric_key(&self) -> bool {
        matches!(
            self.to_string().as_ref(),
            "Total"
                | "Elapsed"
                | "Size"
                | "TotalSuccesses"
                | "TotalFailures"
                | "DmarcPass"
                | "DmarcQuarantine"
                | "DmarcReject"
                | "DmarcNone"
                | "DkimPass"
                | "DkimFail"
                | "DkimNone"
                | "SpfPass"
                | "SpfFail"
                | "SpfNone"
                | "Protocol"
                | "Code"
        )
    }
}
