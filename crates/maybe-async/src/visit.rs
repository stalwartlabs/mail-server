use std::iter::FromIterator;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse_quote,
    punctuated::Punctuated,
    visit_mut::{self, visit_item_mut, visit_path_segment_mut, VisitMut},
    Expr, ExprBlock, File, GenericArgument, GenericParam, Item, PathArguments, PathSegment, Type,
    TypeParamBound, WherePredicate,
};

pub struct ReplaceGenericType<'a> {
    generic_type: &'a str,
    arg_type: &'a PathSegment,
}

impl<'a> ReplaceGenericType<'a> {
    pub fn new(generic_type: &'a str, arg_type: &'a PathSegment) -> Self {
        Self {
            generic_type,
            arg_type,
        }
    }

    pub fn replace_generic_type(item: &mut Item, generic_type: &'a str, arg_type: &'a PathSegment) {
        let mut s = Self::new(generic_type, arg_type);
        s.visit_item_mut(item);
    }
}

impl<'a> VisitMut for ReplaceGenericType<'a> {
    fn visit_item_mut(&mut self, i: &mut Item) {
        if let Item::Fn(item_fn) = i {
            // remove generic type from generics <T, F>
            let args = item_fn
                .sig
                .generics
                .params
                .iter()
                .filter(|param| {
                    if let GenericParam::Type(type_param) = &param {
                        !type_param.ident.to_string().eq(self.generic_type)
                    } else {
                        true
                    }
                })
                .collect::<Vec<_>>();
            item_fn.sig.generics.params =
                Punctuated::from_iter(args.into_iter().cloned().collect::<Vec<_>>());

            // remove generic type from where clause
            if let Some(where_clause) = &mut item_fn.sig.generics.where_clause {
                let new_where_clause = where_clause
                    .predicates
                    .iter()
                    .filter(|predicate| {
                        if let WherePredicate::Type(predicate_type) = predicate {
                            if let Type::Path(p) = &predicate_type.bounded_ty {
                                !p.path.segments[0].ident.to_string().eq(self.generic_type)
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    })
                    .collect::<Vec<_>>();

                where_clause.predicates = Punctuated::from_iter(
                    new_where_clause.into_iter().cloned().collect::<Vec<_>>(),
                );
            };
        }
        visit_item_mut(self, i)
    }
    fn visit_path_segment_mut(&mut self, i: &mut PathSegment) {
        // replace generic type with target type
        if i.ident.to_string().eq(&self.generic_type) {
            *i = self.arg_type.clone();
        }
        visit_path_segment_mut(self, i);
    }
}

pub struct AsyncAwaitRemoval;

impl AsyncAwaitRemoval {
    pub fn remove_async_await(&mut self, item: TokenStream) -> TokenStream {
        let mut syntax_tree: File = syn::parse(item.into()).unwrap();
        self.visit_file_mut(&mut syntax_tree);
        quote!(#syntax_tree)
    }
}

impl VisitMut for AsyncAwaitRemoval {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        // Delegate to the default impl to visit nested expressions.
        visit_mut::visit_expr_mut(self, node);

        match node {
            Expr::Await(expr) => *node = (*expr.base).clone(),

            Expr::Async(expr) => {
                let inner = &expr.block;
                let sync_expr = if inner.stmts.len() == 1 {
                    // remove useless braces when there is only one statement
                    let stmt = &inner.stmts.get(0).unwrap();
                    // convert statement to Expr
                    parse_quote!(#stmt)
                } else {
                    Expr::Block(ExprBlock {
                        attrs: expr.attrs.clone(),
                        block: inner.clone(),
                        label: None,
                    })
                };
                *node = sync_expr;
            }
            _ => {}
        }
    }

    fn visit_item_mut(&mut self, i: &mut Item) {
        // find generic parameter of Future and replace it with its Output type
        if let Item::Fn(item_fn) = i {
            let mut inputs: Vec<(String, PathSegment)> = vec![];

            // generic params: <T:Future<Output=()>, F>
            for param in &item_fn.sig.generics.params {
                // generic param: T:Future<Output=()>
                if let GenericParam::Type(type_param) = param {
                    let generic_type_name = type_param.ident.to_string();

                    // bound: Future<Output=()>
                    for bound in &type_param.bounds {
                        inputs.extend(search_trait_bound(&generic_type_name, bound));
                    }
                }
            }

            if let Some(where_clause) = &item_fn.sig.generics.where_clause {
                for predicate in &where_clause.predicates {
                    if let WherePredicate::Type(predicate_type) = predicate {
                        let generic_type_name = if let Type::Path(p) = &predicate_type.bounded_ty {
                            p.path.segments[0].ident.to_string()
                        } else {
                            panic!("Please submit an issue");
                        };

                        for bound in &predicate_type.bounds {
                            inputs.extend(search_trait_bound(&generic_type_name, bound));
                        }
                    }
                }
            }

            for (generic_type_name, path_seg) in &inputs {
                ReplaceGenericType::replace_generic_type(i, generic_type_name, path_seg);
            }
        }
        visit_item_mut(self, i);
    }
}

fn search_trait_bound(
    generic_type_name: &str,
    bound: &TypeParamBound,
) -> Vec<(String, PathSegment)> {
    let mut inputs = vec![];

    if let TypeParamBound::Trait(trait_bound) = bound {
        let segment = &trait_bound.path.segments[trait_bound.path.segments.len() - 1];
        let name = segment.ident.to_string();
        if name.eq("Future") {
            // match Future<Output=Type>
            if let PathArguments::AngleBracketed(args) = &segment.arguments {
                // binding: Output=Type
                if let GenericArgument::Binding(binding) = &args.args[0] {
                    if let Type::Path(p) = &binding.ty {
                        inputs.push((generic_type_name.to_owned(), p.path.segments[0].clone()));
                    }
                }
            }
        }
    }
    inputs
}
