/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::hash_map::Entry, str::FromStr};

use serde::{ser::SerializeMap, Serializer};
use store::U64_LEN;

use crate::{
    backend::internal::{PrincipalField, PrincipalValue},
    Principal, Type, ROLE_ADMIN,
};

impl Principal {
    pub fn new(id: u32, typ: Type) -> Self {
        Self {
            id,
            typ,
            ..Default::default()
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn typ(&self) -> Type {
        self.typ
    }

    pub fn name(&self) -> &str {
        self.get_str(PrincipalField::Name).unwrap_or_default()
    }

    pub fn has_name(&self) -> bool {
        self.fields.contains_key(&PrincipalField::Name)
    }

    pub fn quota(&self) -> u64 {
        self.get_int(PrincipalField::Quota).unwrap_or_default()
    }

    pub fn tenant(&self) -> Option<u32> {
        self.get_int(PrincipalField::Tenant).map(|v| v as u32)
    }

    pub fn description(&self) -> Option<&str> {
        self.get_str(PrincipalField::Description)
    }

    pub fn get_str(&self, key: PrincipalField) -> Option<&str> {
        self.fields.get(&key).and_then(|v| v.as_str())
    }

    pub fn get_int(&self, key: PrincipalField) -> Option<u64> {
        self.fields.get(&key).and_then(|v| v.as_int())
    }

    pub fn take(&mut self, key: PrincipalField) -> Option<PrincipalValue> {
        self.fields.remove(&key)
    }

    pub fn take_str(&mut self, key: PrincipalField) -> Option<String> {
        self.take(key).and_then(|v| match v {
            PrincipalValue::String(s) => Some(s),
            PrincipalValue::StringList(l) => l.into_iter().next(),
            PrincipalValue::Integer(i) => Some(i.to_string()),
            PrincipalValue::IntegerList(l) => l.into_iter().next().map(|i| i.to_string()),
        })
    }

    pub fn take_str_array(&mut self, key: PrincipalField) -> Option<Vec<String>> {
        self.take(key).map(|v| v.into_str_array())
    }

    pub fn take_int_array(&mut self, key: PrincipalField) -> Option<Vec<u64>> {
        self.take(key).map(|v| v.into_int_array())
    }

    pub fn iter_str(
        &self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &String> + Sync + Send + '_> {
        self.fields
            .get(&key)
            .map(|v| v.iter_str())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_mut_str(
        &mut self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &mut String> + Sync + Send + '_> {
        self.fields
            .get_mut(&key)
            .map(|v| v.iter_mut_str())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_int(
        &self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = u64> + Sync + Send + '_> {
        self.fields
            .get(&key)
            .map(|v| v.iter_int())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_mut_int(
        &mut self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &mut u64> + Sync + Send + '_> {
        self.fields
            .get_mut(&key)
            .map(|v| v.iter_mut_int())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn append_int(&mut self, key: PrincipalField, value: impl Into<u64>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::IntegerList(v) => {
                        v.push(value);
                    }
                    PrincipalValue::Integer(i) => {
                        *v = PrincipalValue::IntegerList(vec![*i, value]);
                    }
                    PrincipalValue::String(s) => {
                        *v =
                            PrincipalValue::IntegerList(vec![s.parse().unwrap_or_default(), value]);
                    }
                    PrincipalValue::StringList(l) => {
                        *v = PrincipalValue::IntegerList(
                            l.iter()
                                .map(|s| s.parse().unwrap_or_default())
                                .chain(std::iter::once(value))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::IntegerList(vec![value]));
            }
        }

        self
    }

    pub fn append_str(&mut self, key: PrincipalField, value: impl Into<String>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::StringList(v) => {
                        v.push(value);
                    }
                    PrincipalValue::String(s) => {
                        *v = PrincipalValue::StringList(vec![std::mem::take(s), value]);
                    }
                    PrincipalValue::Integer(i) => {
                        *v = PrincipalValue::StringList(vec![i.to_string(), value]);
                    }
                    PrincipalValue::IntegerList(l) => {
                        *v = PrincipalValue::StringList(
                            l.iter()
                                .map(|i| i.to_string())
                                .chain(std::iter::once(value))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::StringList(vec![value]));
            }
        }
        self
    }

    pub fn prepend_str(&mut self, key: PrincipalField, value: impl Into<String>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::StringList(v) => {
                        v.insert(0, value);
                    }
                    PrincipalValue::String(s) => {
                        *v = PrincipalValue::StringList(vec![value, std::mem::take(s)]);
                    }
                    PrincipalValue::Integer(i) => {
                        *v = PrincipalValue::StringList(vec![value, i.to_string()]);
                    }
                    PrincipalValue::IntegerList(l) => {
                        *v = PrincipalValue::StringList(
                            std::iter::once(value)
                                .chain(l.iter().map(|i| i.to_string()))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::StringList(vec![value]));
            }
        }
        self
    }

    pub fn set(&mut self, key: PrincipalField, value: impl Into<PrincipalValue>) -> &mut Self {
        self.fields.insert(key, value.into());
        self
    }

    pub fn with_field(mut self, key: PrincipalField, value: impl Into<PrincipalValue>) -> Self {
        self.set(key, value);
        self
    }

    pub fn with_opt_field(
        mut self,
        key: PrincipalField,
        value: Option<impl Into<PrincipalValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.set(key, value);
        }
        self
    }

    pub fn has_field(&self, key: PrincipalField) -> bool {
        self.fields.contains_key(&key)
    }

    pub fn has_str_value(&self, key: PrincipalField, value: &str) -> bool {
        self.fields.get(&key).map_or(false, |v| match v {
            PrincipalValue::String(v) => v == value,
            PrincipalValue::StringList(l) => l.iter().any(|v| v == value),
            PrincipalValue::Integer(_) | PrincipalValue::IntegerList(_) => false,
        })
    }

    pub fn has_int_value(&self, key: PrincipalField, value: u64) -> bool {
        self.fields.get(&key).map_or(false, |v| match v {
            PrincipalValue::Integer(v) => *v == value,
            PrincipalValue::IntegerList(l) => l.iter().any(|v| *v == value),
            PrincipalValue::String(_) | PrincipalValue::StringList(_) => false,
        })
    }

    pub fn find_str(&self, value: &str) -> bool {
        self.fields.values().any(|v| v.find_str(value))
    }

    pub fn field_len(&self, key: PrincipalField) -> usize {
        self.fields.get(&key).map_or(0, |v| match v {
            PrincipalValue::String(_) => 1,
            PrincipalValue::StringList(l) => l.len(),
            PrincipalValue::Integer(_) => 1,
            PrincipalValue::IntegerList(l) => l.len(),
        })
    }

    pub fn remove(&mut self, key: PrincipalField) -> Option<PrincipalValue> {
        self.fields.remove(&key)
    }

    pub fn retain_str<F>(&mut self, key: PrincipalField, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        if let Some(value) = self.fields.get_mut(&key) {
            match value {
                PrincipalValue::String(s) => {
                    if !f(s) {
                        self.fields.remove(&key);
                    }
                }
                PrincipalValue::StringList(l) => {
                    l.retain(f);
                    if l.is_empty() {
                        self.fields.remove(&key);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn retain_int<F>(&mut self, key: PrincipalField, mut f: F)
    where
        F: FnMut(&u64) -> bool,
    {
        if let Some(value) = self.fields.get_mut(&key) {
            match value {
                PrincipalValue::Integer(i) => {
                    if !f(i) {
                        self.fields.remove(&key);
                    }
                }
                PrincipalValue::IntegerList(l) => {
                    l.retain(f);
                    if l.is_empty() {
                        self.fields.remove(&key);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn fallback_admin(fallback_pass: impl Into<String>) -> Self {
        Principal {
            id: u32::MAX,
            typ: Type::Individual,
            ..Default::default()
        }
        .with_field(PrincipalField::Name, "Fallback Administrator")
        .with_field(
            PrincipalField::Secrets,
            PrincipalValue::String(fallback_pass.into()),
        )
        .with_field(PrincipalField::Roles, ROLE_ADMIN)
    }
}

impl PrincipalValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PrincipalValue::String(v) => Some(v.as_str()),
            PrincipalValue::StringList(v) => v.first().map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<u64> {
        match self {
            PrincipalValue::Integer(v) => Some(*v),
            PrincipalValue::IntegerList(v) => v.first().copied(),
            _ => None,
        }
    }

    pub fn iter_str(&self) -> Box<dyn Iterator<Item = &String> + Sync + Send + '_> {
        match self {
            PrincipalValue::String(v) => Box::new(std::iter::once(v)),
            PrincipalValue::StringList(v) => Box::new(v.iter()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_mut_str(&mut self) -> Box<dyn Iterator<Item = &mut String> + Sync + Send + '_> {
        match self {
            PrincipalValue::String(v) => Box::new(std::iter::once(v)),
            PrincipalValue::StringList(v) => Box::new(v.iter_mut()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_int(&self) -> Box<dyn Iterator<Item = u64> + Sync + Send + '_> {
        match self {
            PrincipalValue::Integer(v) => Box::new(std::iter::once(*v)),
            PrincipalValue::IntegerList(v) => Box::new(v.iter().copied()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_mut_int(&mut self) -> Box<dyn Iterator<Item = &mut u64> + Sync + Send + '_> {
        match self {
            PrincipalValue::Integer(v) => Box::new(std::iter::once(v)),
            PrincipalValue::IntegerList(v) => Box::new(v.iter_mut()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn into_array(self) -> Self {
        match self {
            PrincipalValue::String(v) => PrincipalValue::StringList(vec![v]),
            PrincipalValue::Integer(v) => PrincipalValue::IntegerList(vec![v]),
            v => v,
        }
    }

    pub fn into_str_array(self) -> Vec<String> {
        match self {
            PrincipalValue::StringList(v) => v,
            PrincipalValue::String(v) => vec![v],
            PrincipalValue::Integer(v) => vec![v.to_string()],
            PrincipalValue::IntegerList(v) => v.into_iter().map(|v| v.to_string()).collect(),
        }
    }

    pub fn into_int_array(self) -> Vec<u64> {
        match self {
            PrincipalValue::IntegerList(v) => v,
            PrincipalValue::Integer(v) => vec![v],
            PrincipalValue::String(v) => vec![v.parse().unwrap_or_default()],
            PrincipalValue::StringList(v) => v
                .into_iter()
                .map(|v| v.parse().unwrap_or_default())
                .collect(),
        }
    }

    pub fn serialized_size(&self) -> usize {
        match self {
            PrincipalValue::String(s) => s.len() + 2,
            PrincipalValue::StringList(s) => s.iter().map(|s| s.len() + 2).sum(),
            PrincipalValue::Integer(_) => U64_LEN,
            PrincipalValue::IntegerList(l) => l.len() * U64_LEN,
        }
    }

    pub fn find_str(&self, value: &str) -> bool {
        match self {
            PrincipalValue::String(s) => s.to_lowercase().contains(value),
            PrincipalValue::StringList(l) => l.iter().any(|s| s.to_lowercase().contains(value)),
            _ => false,
        }
    }
}

impl From<u64> for PrincipalValue {
    fn from(v: u64) -> Self {
        Self::Integer(v)
    }
}

impl From<String> for PrincipalValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for PrincipalValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}

impl From<Vec<String>> for PrincipalValue {
    fn from(v: Vec<String>) -> Self {
        Self::StringList(v)
    }
}

impl From<Vec<u64>> for PrincipalValue {
    fn from(v: Vec<u64>) -> Self {
        Self::IntegerList(v)
    }
}

impl From<u32> for PrincipalValue {
    fn from(v: u32) -> Self {
        Self::Integer(v as u64)
    }
}

impl From<Vec<u32>> for PrincipalValue {
    fn from(v: Vec<u32>) -> Self {
        Self::IntegerList(v.into_iter().map(|v| v as u64).collect())
    }
}

impl Type {
    pub fn to_jmap(&self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Group => "group",
            Self::Resource => "resource",
            Self::Location => "location",
            Self::Other => "other",
            Self::List => "list",
            Self::Tenant => "tenant",
            Self::Role => "role",
            Self::Domain => "domain",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Individual => "Individual",
            Self::Group => "Group",
            Self::Resource => "Resource",
            Self::Location => "Location",
            Self::Tenant => "Tenant",
            Self::List => "List",
            Self::Other => "Other",
            Self::Role => "Role",
            Self::Domain => "Domain",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "individual" => Some(Type::Individual),
            "group" => Some(Type::Group),
            "resource" => Some(Type::Resource),
            "location" => Some(Type::Location),
            "list" => Some(Type::List),
            "tenant" => Some(Type::Tenant),
            "superuser" => Some(Type::Individual), // legacy
            "role" => Some(Type::Role),
            "domain" => Some(Type::Domain),
            _ => None,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Type::Individual,
            1 => Type::Group,
            2 => Type::Resource,
            3 => Type::Location,
            4 => Type::Individual, // legacy
            5 => Type::List,
            6 => Type::Other,
            7 => Type::Domain,
            8 => Type::Tenant,
            9 => Type::Role,
            _ => Type::Other,
        }
    }
}

impl FromStr for Type {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Type::parse(s).ok_or(())
    }
}

impl serde::Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("type", &self.typ.to_jmap())?;

        for (key, value) in &self.fields {
            match value {
                PrincipalValue::String(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::StringList(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::Integer(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::IntegerList(v) => map.serialize_entry(key.as_str(), v)?,
            };
        }

        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrincipalVisitor;

        // Deserialize the principal
        impl<'de> serde::de::Visitor<'de> for PrincipalVisitor {
            type Value = Principal;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid principal")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut principal = Principal::default();

                while let Some(key) = map.next_key::<&str>()? {
                    let key = PrincipalField::try_parse(key).ok_or_else(|| {
                        serde::de::Error::custom(format!("invalid principal field: {}", key))
                    })?;
                    let value = match key {
                        PrincipalField::Name => PrincipalValue::String(map.next_value()?),
                        PrincipalField::Description | PrincipalField::Tenant => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                PrincipalValue::String(v)
                            } else {
                                continue;
                            }
                        }

                        PrincipalField::Type => {
                            principal.typ = Type::parse(map.next_value()?).ok_or_else(|| {
                                serde::de::Error::custom("invalid principal type")
                            })?;
                            continue;
                        }
                        PrincipalField::Quota => PrincipalValue::Integer(
                            map.next_value::<Option<u64>>()?.unwrap_or_default(),
                        ),

                        PrincipalField::Secrets
                        | PrincipalField::Emails
                        | PrincipalField::MemberOf
                        | PrincipalField::Members
                        | PrincipalField::Roles
                        | PrincipalField::Lists
                        | PrincipalField::EnabledPermissions
                        | PrincipalField::DisabledPermissions => {
                            PrincipalValue::StringList(map.next_value()?)
                        }
                        PrincipalField::UsedQuota => {
                            // consume and ignore
                            let _ = map.next_value::<Option<u64>>()?;
                            continue;
                        }
                    };

                    principal.set(key, value);
                }

                Ok(principal)
            }
        }

        deserializer.deserialize_map(PrincipalVisitor)
    }
}
