/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

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
