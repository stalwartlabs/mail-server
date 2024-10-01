/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::hash_map::Entry, fmt, str::FromStr};

use serde::{
    de::{self, IgnoredAny, Visitor},
    ser::SerializeMap,
    Deserializer, Serializer,
};
use store::U64_LEN;

use crate::{
    backend::internal::{PrincipalField, PrincipalUpdate, PrincipalValue},
    Permission, Principal, Type, ROLE_ADMIN,
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

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    pub fn tenant(&self) -> Option<u32> {
        self.get_int(PrincipalField::Tenant).map(|v| v as u32)
    }
    // SPDX-SnippetEnd

    pub fn description(&self) -> Option<&str> {
        self.get_str(PrincipalField::Description)
    }

    pub fn get_str(&self, key: PrincipalField) -> Option<&str> {
        self.fields.get(&key).and_then(|v| v.as_str())
    }

    pub fn get_int(&self, key: PrincipalField) -> Option<u64> {
        self.fields.get(&key).and_then(|v| v.as_int())
    }

    pub fn get_str_array(&self, key: PrincipalField) -> Option<&[String]> {
        self.fields.get(&key).and_then(|v| match v {
            PrincipalValue::StringList(v) => Some(v.as_slice()),
            PrincipalValue::String(v) => Some(std::slice::from_ref(v)),
            PrincipalValue::Integer(_) | PrincipalValue::IntegerList(_) => None,
        })
    }

    pub fn get_int_array(&self, key: PrincipalField) -> Option<&[u64]> {
        self.fields.get(&key).and_then(|v| match v {
            PrincipalValue::IntegerList(v) => Some(v.as_slice()),
            PrincipalValue::Integer(v) => Some(std::slice::from_ref(v)),
            PrincipalValue::String(_) | PrincipalValue::StringList(_) => None,
        })
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

    pub fn take_int(&mut self, key: PrincipalField) -> Option<u64> {
        self.take(key).and_then(|v| match v {
            PrincipalValue::Integer(i) => Some(i),
            PrincipalValue::IntegerList(l) => l.into_iter().next(),
            PrincipalValue::String(s) => s.parse().ok(),
            PrincipalValue::StringList(l) => l.into_iter().next().and_then(|s| s.parse().ok()),
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
                        if !v.contains(&value) {
                            v.push(value);
                        }
                    }
                    PrincipalValue::Integer(i) => {
                        if value != *i {
                            *v = PrincipalValue::IntegerList(vec![*i, value]);
                        }
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
                        if !v.contains(&value) {
                            v.push(value);
                        }
                    }
                    PrincipalValue::String(s) => {
                        if s != &value {
                            *v = PrincipalValue::StringList(vec![std::mem::take(s), value]);
                        }
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
                        if !v.contains(&value) {
                            v.insert(0, value);
                        }
                    }
                    PrincipalValue::String(s) => {
                        if s != &value {
                            *v = PrincipalValue::StringList(vec![value, std::mem::take(s)]);
                        }
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

    pub fn update_external(&mut self, mut external: Principal) -> Vec<PrincipalUpdate> {
        let mut updates = Vec::new();
        if let Some(name) = external.take_str(PrincipalField::Description) {
            if self.get_str(PrincipalField::Description) != Some(name.as_str()) {
                updates.push(PrincipalUpdate::set(
                    PrincipalField::Description,
                    PrincipalValue::String(name.clone()),
                ));
                self.set(PrincipalField::Description, name);
            }
        }

        for field in [PrincipalField::Secrets, PrincipalField::Emails] {
            if let Some(secrets) = external.take_str_array(field).filter(|s| !s.is_empty()) {
                if self.get_str_array(field) != Some(secrets.as_ref()) {
                    updates.push(PrincipalUpdate::set(
                        field,
                        PrincipalValue::StringList(secrets.clone()),
                    ));
                    self.set(field, secrets);
                }
            }
        }

        if let Some(quota) = external.take_int(PrincipalField::Quota) {
            if self.get_int(PrincipalField::Quota) != Some(quota) {
                updates.push(PrincipalUpdate::set(
                    PrincipalField::Quota,
                    PrincipalValue::Integer(quota),
                ));
                self.set(PrincipalField::Quota, quota);
            }
        }

        // Add external members
        if let Some(member_of) = external
            .take_int_array(PrincipalField::MemberOf)
            .filter(|s| !s.is_empty())
        {
            self.set(PrincipalField::MemberOf, member_of);
        }

        // If the principal has no roles, take the ones from the external principal
        if let Some(member_of) = external
            .take_int_array(PrincipalField::Roles)
            .filter(|s| !s.is_empty())
        {
            if self
                .get_int_array(PrincipalField::Roles)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                self.set(PrincipalField::Roles, member_of);
            }
        }

        updates
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
            Self::ApiKey => "apiKey",
            Self::OauthClient => "oauthClient",
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
            Self::ApiKey => "API Key",
            Self::OauthClient => "OAuth Client",
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
            "apiKey" => Some(Type::ApiKey),
            "oauthClient" => Some(Type::OauthClient),
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
            10 => Type::ApiKey,
            11 => Type::OauthClient,
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

const MAX_STRING_LEN: usize = 512;

impl<'de> serde::Deserialize<'de> for PrincipalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrincipalValueVisitor;

        impl<'de> Visitor<'de> for PrincipalValueVisitor {
            type Value = PrincipalValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an optional values or a sequence of values")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PrincipalValue::String(String::new()))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PrincipalValue::Integer(value))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(PrincipalValue::String(value))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(PrincipalValue::String(value.to_string()))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec_u64 = Vec::new();
                let mut vec_string = Vec::new();

                while let Some(value) = seq.next_element::<StringOrU64>()? {
                    match value {
                        StringOrU64::String(s) => {
                            if s.len() <= MAX_STRING_LEN {
                                vec_string.push(s);
                            } else {
                                return Err(serde::de::Error::custom("string too long"));
                            }
                        }
                        StringOrU64::U64(u) => vec_u64.push(u),
                    }
                }

                match (vec_u64.is_empty(), vec_string.is_empty()) {
                    (true, false) => Ok(PrincipalValue::StringList(vec_string)),
                    (false, true) => Ok(PrincipalValue::IntegerList(vec_u64)),
                    (true, true) => Ok(PrincipalValue::StringList(vec_string)),
                    _ => Err(serde::de::Error::custom("invalid principal value")),
                }
            }
        }

        deserializer.deserialize_any(PrincipalValueVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrincipalVisitor;

        // Deserialize the principal
        impl<'de> Visitor<'de> for PrincipalVisitor {
            type Value = Principal;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid principal")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut principal = Principal::default();

                while let Some(key) = map.next_key::<&str>()? {
                    let key = PrincipalField::try_parse(key)
                        .or_else(|| {
                            if key == "id" {
                                // Ignored
                                Some(PrincipalField::UsedQuota)
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            serde::de::Error::custom(format!("invalid principal field: {}", key))
                        })?;

                    let value = match key {
                        PrincipalField::Name => {
                            PrincipalValue::String(map.next_value::<String>().and_then(|v| {
                                if v.len() <= MAX_STRING_LEN {
                                    Ok(v)
                                } else {
                                    Err(serde::de::Error::custom("string too long"))
                                }
                            })?)
                        }
                        PrincipalField::Description
                        | PrincipalField::Tenant
                        | PrincipalField::Picture => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                if v.len() <= MAX_STRING_LEN {
                                    PrincipalValue::String(v)
                                } else {
                                    return Err(serde::de::Error::custom("string too long"));
                                }
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
                        PrincipalField::Quota => map.next_value::<PrincipalValue>()?,
                        PrincipalField::Secrets
                        | PrincipalField::Emails
                        | PrincipalField::MemberOf
                        | PrincipalField::Members
                        | PrincipalField::Roles
                        | PrincipalField::Lists
                        | PrincipalField::EnabledPermissions
                        | PrincipalField::DisabledPermissions
                        | PrincipalField::Urls => match map.next_value::<StringOrMany>()? {
                            StringOrMany::One(v) => PrincipalValue::StringList(vec![v]),
                            StringOrMany::Many(v) => {
                                if !v.is_empty() {
                                    PrincipalValue::StringList(v)
                                } else {
                                    continue;
                                }
                            }
                        },
                        PrincipalField::UsedQuota => {
                            // consume and ignore
                            map.next_value::<IgnoredAny>()?;
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

#[derive(Debug)]
enum StringOrU64 {
    String(String),
    U64(u64),
}

impl<'de> serde::Deserialize<'de> for StringOrU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrU64Visitor;

        impl<'de> Visitor<'de> for StringOrU64Visitor {
            type Value = StringOrU64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or u64")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(StringOrU64::String(value.to_string()))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() <= MAX_STRING_LEN {
                    Ok(StringOrU64::String(v))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrU64::U64(value))
            }
        }

        deserializer.deserialize_any(StringOrU64Visitor)
    }
}

#[derive(Debug)]
enum StringOrMany {
    One(String),
    Many(Vec<String>),
}

impl<'de> serde::Deserialize<'de> for StringOrMany {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrManyVisitor;

        impl<'de> Visitor<'de> for StringOrManyVisitor {
            type Value = StringOrMany;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a sequence of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(StringOrMany::One(value.to_string()))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() <= MAX_STRING_LEN {
                    Ok(StringOrMany::One(v))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();

                while let Some(value) = seq.next_element::<String>()? {
                    vec.push(value);
                }

                Ok(StringOrMany::Many(vec))
            }
        }

        deserializer.deserialize_any(StringOrManyVisitor)
    }
}

impl Permission {
    pub fn all() -> impl Iterator<Item = Permission> {
        (0..Permission::COUNT).filter_map(Permission::from_id)
    }

    pub const fn is_user_permission(&self) -> bool {
        matches!(
            self,
            Permission::Authenticate
                | Permission::AuthenticateOauth
                | Permission::EmailSend
                | Permission::EmailReceive
                | Permission::ManageEncryption
                | Permission::ManagePasswords
                | Permission::JmapEmailGet
                | Permission::JmapMailboxGet
                | Permission::JmapThreadGet
                | Permission::JmapIdentityGet
                | Permission::JmapEmailSubmissionGet
                | Permission::JmapPushSubscriptionGet
                | Permission::JmapSieveScriptGet
                | Permission::JmapVacationResponseGet
                | Permission::JmapQuotaGet
                | Permission::JmapBlobGet
                | Permission::JmapEmailSet
                | Permission::JmapMailboxSet
                | Permission::JmapIdentitySet
                | Permission::JmapEmailSubmissionSet
                | Permission::JmapPushSubscriptionSet
                | Permission::JmapSieveScriptSet
                | Permission::JmapVacationResponseSet
                | Permission::JmapEmailChanges
                | Permission::JmapMailboxChanges
                | Permission::JmapThreadChanges
                | Permission::JmapIdentityChanges
                | Permission::JmapEmailSubmissionChanges
                | Permission::JmapQuotaChanges
                | Permission::JmapEmailCopy
                | Permission::JmapBlobCopy
                | Permission::JmapEmailImport
                | Permission::JmapEmailParse
                | Permission::JmapEmailQueryChanges
                | Permission::JmapMailboxQueryChanges
                | Permission::JmapEmailSubmissionQueryChanges
                | Permission::JmapSieveScriptQueryChanges
                | Permission::JmapQuotaQueryChanges
                | Permission::JmapEmailQuery
                | Permission::JmapMailboxQuery
                | Permission::JmapEmailSubmissionQuery
                | Permission::JmapSieveScriptQuery
                | Permission::JmapQuotaQuery
                | Permission::JmapSearchSnippet
                | Permission::JmapSieveScriptValidate
                | Permission::JmapBlobLookup
                | Permission::JmapBlobUpload
                | Permission::JmapEcho
                | Permission::ImapAuthenticate
                | Permission::ImapAclGet
                | Permission::ImapAclSet
                | Permission::ImapMyRights
                | Permission::ImapListRights
                | Permission::ImapAppend
                | Permission::ImapCapability
                | Permission::ImapId
                | Permission::ImapCopy
                | Permission::ImapMove
                | Permission::ImapCreate
                | Permission::ImapDelete
                | Permission::ImapEnable
                | Permission::ImapExpunge
                | Permission::ImapFetch
                | Permission::ImapIdle
                | Permission::ImapList
                | Permission::ImapLsub
                | Permission::ImapNamespace
                | Permission::ImapRename
                | Permission::ImapSearch
                | Permission::ImapSort
                | Permission::ImapSelect
                | Permission::ImapExamine
                | Permission::ImapStatus
                | Permission::ImapStore
                | Permission::ImapSubscribe
                | Permission::ImapThread
                | Permission::Pop3Authenticate
                | Permission::Pop3List
                | Permission::Pop3Uidl
                | Permission::Pop3Stat
                | Permission::Pop3Retr
                | Permission::Pop3Dele
                | Permission::SieveAuthenticate
                | Permission::SieveListScripts
                | Permission::SieveSetActive
                | Permission::SieveGetScript
                | Permission::SievePutScript
                | Permission::SieveDeleteScript
                | Permission::SieveRenameScript
                | Permission::SieveCheckScript
                | Permission::SieveHaveSpace
        )
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    pub const fn is_tenant_admin_permission(&self) -> bool {
        matches!(
            self,
            Permission::MessageQueueList
                | Permission::MessageQueueGet
                | Permission::MessageQueueUpdate
                | Permission::MessageQueueDelete
                | Permission::OutgoingReportList
                | Permission::OutgoingReportGet
                | Permission::OutgoingReportDelete
                | Permission::IncomingReportList
                | Permission::IncomingReportGet
                | Permission::IncomingReportDelete
                | Permission::IndividualList
                | Permission::IndividualGet
                | Permission::IndividualUpdate
                | Permission::IndividualDelete
                | Permission::IndividualCreate
                | Permission::GroupList
                | Permission::GroupGet
                | Permission::GroupUpdate
                | Permission::GroupDelete
                | Permission::GroupCreate
                | Permission::DomainList
                | Permission::DomainGet
                | Permission::DomainCreate
                | Permission::DomainUpdate
                | Permission::DomainDelete
                | Permission::MailingListList
                | Permission::MailingListGet
                | Permission::MailingListCreate
                | Permission::MailingListUpdate
                | Permission::MailingListDelete
                | Permission::RoleList
                | Permission::RoleGet
                | Permission::RoleCreate
                | Permission::RoleUpdate
                | Permission::RoleDelete
                | Permission::PrincipalList
                | Permission::PrincipalGet
                | Permission::PrincipalCreate
                | Permission::PrincipalUpdate
                | Permission::PrincipalDelete
                | Permission::Undelete
                | Permission::DkimSignatureCreate
                | Permission::DkimSignatureGet
                | Permission::JmapPrincipalGet
                | Permission::JmapPrincipalQueryChanges
                | Permission::JmapPrincipalQuery
                | Permission::ApiKeyList
                | Permission::ApiKeyGet
                | Permission::ApiKeyCreate
                | Permission::ApiKeyUpdate
                | Permission::ApiKeyDelete
        ) || self.is_user_permission()
    }

    // SPDX-SnippetEnd
}
