/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::HashSet};

use store::{
    write::{
        assert::HashedValue, BatchBuilder, BitmapClass, BitmapHash, IntoOperations, Operation,
        TokenizeText, ValueClass, ValueOp,
    },
    Serialize,
};

use crate::{
    error::set::SetError,
    types::{id::Id, property::Property, value::Value},
};

use super::Object;

#[derive(Debug, Clone, Default)]
pub struct ObjectIndexBuilder {
    index: &'static [IndexProperty],
    current: Option<HashedValue<Object<Value>>>,
    changes: Option<Object<Value>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum IndexAs {
    Text {
        tokenize: bool,
        index: bool,
    },
    TextList {
        tokenize: bool,
        index: bool,
    },
    Integer,
    IntegerList,
    LongInteger,
    HasProperty,
    Acl,
    #[default]
    None,
}

#[derive(Debug, Clone)]
pub struct IndexProperty {
    property: Property,
    index_as: IndexAs,
    required: bool,
    max_size: usize,
}

impl ObjectIndexBuilder {
    pub fn new(index: &'static [IndexProperty]) -> Self {
        Self {
            index,
            current: None,
            changes: None,
        }
    }

    pub fn with_current(mut self, current: HashedValue<Object<Value>>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: Object<Value>) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<HashedValue<Object<Value>>>) -> Self {
        self.current = current;
        self
    }

    pub fn get(&self, property: &Property) -> &Value {
        self.changes
            .as_ref()
            .and_then(|c| c.properties.get(property))
            .or_else(|| {
                self.current
                    .as_ref()
                    .and_then(|c| c.inner.properties.get(property))
            })
            .unwrap_or(&Value::Null)
    }

    pub fn set(&mut self, property: Property, value: Value) {
        if let Some(changes) = &mut self.changes {
            changes.properties.set(property, value);
        }
    }

    pub fn validate(self) -> Result<Self, SetError> {
        for item in self.index {
            if item.required || item.max_size > 0 {
                let error: Cow<str> = match self.get(&item.property) {
                    Value::Null if item.required => "Property cannot be empty.".into(),
                    Value::Text(text) => {
                        if item.required && text.trim().is_empty() {
                            "Property cannot be empty.".into()
                        } else if item.max_size > 0 && text.len() > item.max_size {
                            format!("Property cannot be longer than {} bytes.", item.max_size)
                                .into()
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };
                return Err(SetError::invalid_properties()
                    .with_property(item.property.clone())
                    .with_description(error));
            }
        }

        Ok(self)
    }

    pub fn changes(&self) -> Option<&Object<Value>> {
        self.changes.as_ref()
    }

    pub fn changes_mut(&mut self) -> Option<&mut Object<Value>> {
        self.changes.as_mut()
    }

    pub fn current(&self) -> Option<&HashedValue<Object<Value>>> {
        self.current.as_ref()
    }
}

impl IntoOperations for ObjectIndexBuilder {
    fn build(self, batch: &mut BatchBuilder) {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                build_batch(batch, self.index, &changes, true);
                batch.set(Property::Value, changes.serialize());
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Property::Value, &current);
                merge_batch(batch, self.index, current.inner, changes);
            }
            (Some(current), None) => {
                // Deletion
                batch.assert_value(Property::Value, &current);
                build_batch(batch, self.index, &current.inner, false);
                batch.clear(Property::Value);
            }
            (None, None) => unreachable!(),
        }
    }
}

fn merge_batch(
    batch: &mut BatchBuilder,
    index: &'static [IndexProperty],
    mut current: Object<Value>,
    changes: Object<Value>,
) {
    let mut has_changes = false;

    for (property, value) in changes.properties {
        let current_value = current.get(&property);
        if current_value == &value {
            continue;
        }

        for index_property in index {
            if index_property.property != property {
                continue;
            }
            match index_property.index_as {
                IndexAs::Text { tokenize, index } => {
                    // Remove current text from index
                    let mut add_tokens = HashSet::new();
                    let mut remove_tokens = HashSet::new();
                    if let Some(text) = current_value.as_string() {
                        if index {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: text.serialize(),
                                set: false,
                            });
                        }
                        if tokenize {
                            text.tokenize_into(&mut remove_tokens);
                        }
                    }

                    // Add new text to index
                    if let Some(text) = value.as_string() {
                        if index {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: text.serialize(),
                                set: true,
                            });
                        }
                        if tokenize {
                            for token in text.to_tokens() {
                                if !remove_tokens.remove(&token) {
                                    add_tokens.insert(token);
                                }
                            }
                        }
                    }

                    // Update tokens
                    let field: u8 = property.clone().into();
                    for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                        for token in token {
                            batch.ops.push(Operation::Bitmap {
                                class: BitmapClass::Text {
                                    field,
                                    token: BitmapHash::new(token),
                                },
                                set,
                            });
                        }
                    }
                }
                IndexAs::TextList { tokenize, index } => {
                    let mut add_tokens = HashSet::new();
                    let mut remove_tokens = HashSet::new();
                    let mut add_values = HashSet::new();
                    let mut remove_values = HashSet::new();

                    // Remove current text from index
                    if let Some(current_values) = current_value.as_list() {
                        for current_value in current_values {
                            if let Some(text) = current_value.as_string() {
                                if index {
                                    remove_values.insert(text);
                                }
                                if tokenize {
                                    text.tokenize_into(&mut remove_tokens);
                                }
                            }
                        }
                    }

                    // Add new text to index
                    if let Some(values) = value.as_list() {
                        for value in values {
                            if let Some(text) = value.as_string() {
                                if index && !remove_values.remove(text) {
                                    add_values.insert(text);
                                }
                                if tokenize {
                                    for token in text.to_tokens() {
                                        if !remove_tokens.remove(&token) {
                                            add_tokens.insert(token);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Update index
                    for (values, set) in [(add_values, true), (remove_values, false)] {
                        for value in values {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: value.serialize(),
                                set,
                            });
                        }
                    }

                    // Update tokens
                    let field: u8 = property.clone().into();
                    for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                        for token in token {
                            batch.ops.push(Operation::Bitmap {
                                class: BitmapClass::Text {
                                    field,
                                    token: BitmapHash::new(token),
                                },
                                set,
                            });
                        }
                    }
                }
                index_as @ (IndexAs::Integer | IndexAs::LongInteger) => {
                    if let Some(current_value) = current_value.try_cast_uint() {
                        batch.ops.push(Operation::Index {
                            field: property.clone().into(),
                            key: current_value.into_index(index_as),
                            set: false,
                        });
                    }
                    if let Some(value) = value.try_cast_uint() {
                        batch.ops.push(Operation::Index {
                            field: property.clone().into(),
                            key: value.into_index(index_as),
                            set: true,
                        });
                    }
                }
                IndexAs::IntegerList => {
                    let mut add_values = HashSet::new();
                    let mut remove_values = HashSet::new();

                    if let Some(current_values) = current_value.as_list() {
                        for current_value in current_values {
                            if let Some(current_value) = current_value.try_cast_uint() {
                                remove_values.insert(current_value);
                            }
                        }
                    }
                    if let Some(values) = value.as_list() {
                        for value in values {
                            if let Some(value) = value.try_cast_uint() {
                                if !remove_values.remove(&value) {
                                    add_values.insert(value);
                                }
                            }
                        }
                    }

                    for (values, set) in [(add_values, true), (remove_values, false)] {
                        for value in values {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: (value as u32).serialize(),
                                set,
                            });
                        }
                    }
                }
                IndexAs::HasProperty => {
                    if current_value == &Value::Null {
                        batch.ops.push(Operation::Bitmap {
                            class: BitmapClass::Tag {
                                field: property.clone().into(),
                                value: ().into(),
                            },
                            set: true,
                        });
                    } else if value == Value::Null {
                        batch.ops.push(Operation::Bitmap {
                            class: BitmapClass::Tag {
                                field: property.clone().into(),
                                value: ().into(),
                            },
                            set: false,
                        });
                    }
                }
                IndexAs::Acl => {
                    match (current_value, &value) {
                        (Value::Acl(current_value), Value::Acl(value)) => {
                            // Remove deleted ACLs
                            for current_item in current_value {
                                if !value
                                    .iter()
                                    .any(|item| item.account_id == current_item.account_id)
                                {
                                    batch
                                        .ops
                                        .push(Operation::acl(current_item.account_id, None));
                                }
                            }

                            // Update ACLs
                            for item in value {
                                let mut add_item = true;
                                for current_item in current_value {
                                    if item.account_id == current_item.account_id {
                                        if item.grants == current_item.grants {
                                            add_item = false;
                                        }
                                        break;
                                    }
                                }
                                if add_item {
                                    batch.ops.push(Operation::acl(
                                        item.account_id,
                                        item.grants.bitmap.serialize().into(),
                                    ));
                                }
                            }
                        }
                        (Value::Null, Value::Acl(values)) => {
                            // Add all ACLs
                            for item in values {
                                batch.ops.push(Operation::acl(
                                    item.account_id,
                                    item.grants.bitmap.serialize().into(),
                                ));
                            }
                        }
                        (Value::Acl(current_values), Value::Null) => {
                            // Remove all ACLs
                            for item in current_values {
                                batch.ops.push(Operation::acl(item.account_id, None));
                            }
                        }
                        _ => {}
                    }
                }
                IndexAs::None => (),
            }
        }
        if value != Value::Null {
            current.set(property, value);
        } else {
            current.remove(&property);
        }
        has_changes = true;
    }

    if has_changes {
        batch.ops.push(Operation::Value {
            class: Property::Value.into(),
            op: ValueOp::Set(current.serialize().into()),
        });
    }
}

fn build_batch(
    batch: &mut BatchBuilder,
    index: &'static [IndexProperty],
    object: &Object<Value>,
    set: bool,
) {
    for item in index {
        match (object.get(&item.property), item.index_as) {
            (Value::Text(text), IndexAs::Text { tokenize, index }) => {
                if index {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: text.serialize(),
                        set,
                    });
                }
                if tokenize {
                    let field: u8 = (&item.property).into();
                    for token in text.as_str().to_tokens() {
                        batch.ops.push(Operation::Bitmap {
                            class: BitmapClass::Text {
                                field,
                                token: BitmapHash::new(token),
                            },
                            set,
                        });
                    }
                }
            }
            (Value::List(values), IndexAs::TextList { tokenize, index }) => {
                let mut tokens = HashSet::new();
                let mut indexes = HashSet::new();
                for value in values {
                    if let Some(text) = value.as_string() {
                        if index {
                            indexes.insert(text);
                        }
                        if tokenize {
                            tokens.extend(text.to_tokens());
                        }
                    }
                }
                let field: u8 = (&item.property).into();
                for text in indexes {
                    batch.ops.push(Operation::Index {
                        field,
                        key: text.serialize(),
                        set,
                    });
                }
                for token in tokens {
                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Text {
                            field,
                            token: BitmapHash::new(token),
                        },
                        set,
                    });
                }
            }
            (Value::UnsignedInt(integer), IndexAs::Integer | IndexAs::LongInteger) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: integer.into_index(item.index_as),
                    set,
                });
            }
            (Value::Bool(boolean), IndexAs::Integer) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: (*boolean as u32).serialize(),
                    set,
                });
            }
            (Value::Id(id), IndexAs::Integer | IndexAs::LongInteger) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: id.into_index(item.index_as),
                    set,
                });
            }
            (Value::List(values), IndexAs::IntegerList) => {
                for value in values
                    .iter()
                    .map(|value| match value {
                        Value::UnsignedInt(integer) => *integer as u32,
                        Value::Id(id) => id.document_id(),
                        _ => unreachable!(),
                    })
                    .collect::<HashSet<_>>()
                {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: value.into_index(item.index_as),
                        set,
                    });
                }
            }
            (Value::Acl(values), IndexAs::Acl) => {
                for item in values {
                    batch.ops.push(Operation::acl(
                        item.account_id,
                        if set {
                            item.grants.bitmap.serialize().into()
                        } else {
                            None
                        },
                    ));
                }
            }
            (value, IndexAs::HasProperty) if value != &Value::Null => {
                batch.ops.push(Operation::Bitmap {
                    class: BitmapClass::Tag {
                        field: (&item.property).into(),
                        value: ().into(),
                    },
                    set,
                });
            }

            _ => (),
        }
    }
}

impl IndexProperty {
    pub const fn new(property: Property) -> Self {
        Self {
            property,
            required: false,
            max_size: 0,
            index_as: IndexAs::None,
        }
    }

    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub const fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    pub const fn index_as(mut self, index_as: IndexAs) -> Self {
        self.index_as = index_as;
        self
    }
}

trait IntoIndex {
    fn into_index(self, index_as: IndexAs) -> Vec<u8>;
}

impl IntoIndex for &u64 {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer => (*self as u32).serialize(),
            IndexAs::LongInteger => self.serialize(),
            _ => unreachable!(),
        }
    }
}

impl IntoIndex for &u32 {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer | IndexAs::IntegerList => self.serialize(),
            _ => unreachable!("index as {index_as:?} not supported for u32"),
        }
    }
}

impl IntoIndex for &Id {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer => self.document_id().serialize(),
            IndexAs::LongInteger => self.id().serialize(),
            _ => unreachable!("index as {index_as:?} not supported for Id"),
        }
    }
}

impl<T> From<Property> for ValueClass<T> {
    fn from(value: Property) -> Self {
        ValueClass::Property(value.into())
    }
}
