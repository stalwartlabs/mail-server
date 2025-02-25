/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashSet;

use serde::ser::SerializeSeq;
use store::{Serialize, ahash::RandomState, write::now};

use super::{SeenIdHash, SeenIds, SieveScript};

impl Serialize for SieveScript {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|r| r.into_vec())
            .map_err(Into::into)
    }
}

// SeenIds serializer
impl serde::Serialize for SeenIds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq((self.ids.len() * 2).into())?;
        for id in &self.ids {
            seq.serialize_element(&id.expiry)?;
            seq.serialize_element(&id.hash)?;
        }

        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for SeenIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(SeenIdsVisitor)
    }
}

struct SeenIdsVisitor;

impl<'de> serde::de::Visitor<'de> for SeenIdsVisitor {
    type Value = SeenIds;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("invalid SeenIds")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let num_entries = seq.size_hint().unwrap_or(0) / 2;
        let mut seen_ids = SeenIds {
            ids: HashSet::with_capacity_and_hasher(num_entries, RandomState::new()),
            has_changes: false,
        };
        let now = now();

        for _ in 0..num_entries {
            let expiry = seq
                .next_element::<u64>()?
                .ok_or_else(|| serde::de::Error::custom("Expected expiry."))?;
            if expiry > now {
                seen_ids.ids.insert(SeenIdHash {
                    hash: seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("Expected hash."))?,
                    expiry,
                });
            } else {
                seq.next_element::<[u8; 32]>()?
                    .ok_or_else(|| serde::de::Error::custom("Expected hash."))?;
                seen_ids.has_changes = true;
            }
        }

        Ok(seen_ids)
    }
}
