use std::{borrow::Cow, collections::HashSet};

use store::{
    fts::builder::ToTokens,
    write::{BatchBuilder, IntoOperations, Operation},
    Serialize, BM_TAG, HASH_EXACT,
};

use crate::{
    error::set::SetError,
    types::{id::Id, property::Property, value::Value},
};

use super::Object;

#[derive(Debug, Clone, Default)]
pub struct ObjectIndexBuilder {
    index: &'static [IndexProperty],
    current: Option<Object<Value>>,
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

    pub fn with_current(mut self, current: Object<Value>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: Object<Value>) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<Object<Value>>) -> Self {
        self.current = current;
        self
    }

    pub fn validate(self) -> Result<Self, SetError> {
        for item in self.index {
            if item.required || item.max_size > 0 {
                let value = self
                    .changes
                    .as_ref()
                    .and_then(|c| c.properties.get(&item.property))
                    .or_else(|| {
                        self.current
                            .as_ref()
                            .and_then(|c| c.properties.get(&item.property))
                    });
                let error: Cow<str> = match value {
                    None if item.required => "Property cannot be empty.".into(),
                    Some(Value::Text(text)) => {
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
}

impl IntoOperations for ObjectIndexBuilder {
    fn build(self, batch: &mut BatchBuilder) {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                build_batch(batch, self.index, &changes, true);
                batch.ops.push(Operation::Value {
                    field: Property::Value.into(),
                    family: 0,
                    set: changes.serialize().into(),
                });
            }
            (Some(current), Some(changes)) => {
                // Update
                merge_batch(batch, self.index, current, changes);
            }
            (Some(current), None) => {
                // Deletion
                build_batch(batch, self.index, &current, true);
                batch.ops.push(Operation::Value {
                    field: Property::Value.into(),
                    family: 0,
                    set: None,
                });
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
        match index
            .iter()
            .find_map(|i| {
                if i.property == property {
                    Some(i.index_as)
                } else {
                    None
                }
            })
            .unwrap_or_default()
        {
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
                        remove_tokens = text.to_tokens();
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
                for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                    for token in token {
                        batch.ops.push(Operation::hash(
                            &token,
                            HASH_EXACT,
                            property.clone().into(),
                            set,
                        ));
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
                                remove_tokens.extend(text.to_tokens());
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
                for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                    for token in token {
                        batch.ops.push(Operation::hash(
                            &token,
                            HASH_EXACT,
                            property.clone().into(),
                            set,
                        ));
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
                        set: false,
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
                        family: BM_TAG,
                        field: property.clone().into(),
                        key: vec![],
                        set: true,
                    });
                } else if value == Value::Null {
                    batch.ops.push(Operation::Bitmap {
                        family: BM_TAG,
                        field: property.clone().into(),
                        key: vec![],
                        set: false,
                    });
                }
            }
            IndexAs::None => (),
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
            field: Property::Value.into(),
            family: 0,
            set: current.serialize().into(),
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
                    for token in text.to_tokens() {
                        batch.ops.push(Operation::hash(
                            &token,
                            HASH_EXACT,
                            (&item.property).into(),
                            true,
                        ));
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
                for text in indexes {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: text.serialize(),
                        set,
                    });
                }
                for token in tokens {
                    batch.ops.push(Operation::hash(
                        &token,
                        HASH_EXACT,
                        (&item.property).into(),
                        true,
                    ));
                }
            }
            (Value::UnsignedInt(integer), IndexAs::Integer | IndexAs::LongInteger) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: integer.into_index(item.index_as),
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
            (value, IndexAs::HasProperty) if value != &Value::Null => {
                batch.ops.push(Operation::Bitmap {
                    family: BM_TAG,
                    field: (&item.property).into(),
                    key: vec![],
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
            IndexAs::Integer => self.serialize(),
            _ => unreachable!(),
        }
    }
}

impl IntoIndex for &Id {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer => self.document_id().serialize(),
            IndexAs::LongInteger => self.id().serialize(),
            _ => unreachable!(),
        }
    }
}
