/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{JsonPointerItem, JsonQueryable};
use std::hash::BuildHasher;
use std::{collections::HashMap, slice::Iter};

impl<T: JsonQueryable> JsonQueryable for Vec<T> {
    fn eval_pointer<'x>(
        &'x self,
        mut pointer: Iter<JsonPointerItem>,
        results: &mut Vec<&'x dyn JsonQueryable>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::Number(n)) => {
                if let Some(v) = self.get(*n as usize) {
                    v.eval_pointer(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard) => {
                for v in self {
                    v.eval_pointer(pointer.clone(), results);
                }
            }
            Some(JsonPointerItem::Root) | None => {
                results.push(self);
            }
            _ => {}
        }
    }
}

impl<V: JsonQueryable, S: BuildHasher + Default + 'static> JsonQueryable for HashMap<String, V, S> {
    fn eval_pointer<'x>(
        &'x self,
        mut pointer: Iter<JsonPointerItem>,
        results: &mut Vec<&'x dyn JsonQueryable>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::String(n)) => {
                if let Some(v) = self.get(n) {
                    v.eval_pointer(pointer, results);
                }
            }
            Some(JsonPointerItem::Number(n)) => {
                let n = n.to_string();
                if let Some(v) = self.get(&n) {
                    v.eval_pointer(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard) => {
                for v in self.values() {
                    v.eval_pointer(pointer.clone(), results);
                }
            }
            Some(JsonPointerItem::Root) | None => {
                results.push(self);
            }
        }
    }
}

impl JsonQueryable for serde_json::Value {
    fn eval_pointer<'x>(
        &'x self,
        mut pointer: Iter<JsonPointerItem>,
        results: &mut Vec<&'x dyn JsonQueryable>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::String(n)) => {
                if let serde_json::Value::Object(map) = self {
                    if let Some(v) = map.get(n) {
                        v.eval_pointer(pointer, results);
                    }
                }
            }
            Some(JsonPointerItem::Number(n)) => match self {
                serde_json::Value::Array(values) => {
                    if let Some(v) = values.get(*n as usize) {
                        v.eval_pointer(pointer, results);
                    }
                }
                serde_json::Value::Object(map) => {
                    let n = n.to_string();
                    if let Some(v) = map.get(&n) {
                        v.eval_pointer(pointer, results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Wildcard) => match self {
                serde_json::Value::Array(values) => {
                    for v in values {
                        v.eval_pointer(pointer.clone(), results);
                    }
                }
                serde_json::Value::Object(map) => {
                    for v in map.values() {
                        v.eval_pointer(pointer.clone(), results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Root) | None => {
                results.push(self);
            }
        }
    }
}
