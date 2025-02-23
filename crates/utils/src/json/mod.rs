pub mod parser;
pub mod pointer;

use downcast_rs::{Downcast, impl_downcast};
use std::{fmt::Debug, slice::Iter};

pub trait JsonQueryable: Downcast + Debug + 'static {
    fn eval_pointer<'x>(
        &'x self,
        pointer: Iter<JsonPointerItem>,
        results: &mut Vec<&'x dyn JsonQueryable>,
    );
}

impl_downcast!(JsonQueryable);

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct JsonPointer(pub Vec<JsonPointerItem>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum JsonPointerItem {
    Root,
    Wildcard,
    String(String),
    Number(u64),
}
