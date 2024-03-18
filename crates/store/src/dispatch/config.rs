/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use utils::config::ConfigKey;

use crate::{
    write::{BatchBuilder, ValueClass},
    Deserialize, IterateParams, Store, ValueKey,
};

impl Store {
    pub async fn config_get(&self, key: impl Into<String>) -> crate::Result<Option<String>> {
        self.get_value(ValueKey::from(ValueClass::Config(key.into().into_bytes())))
            .await
    }

    pub async fn config_list(
        &self,
        prefix: &str,
        strip_prefix: bool,
    ) -> crate::Result<Vec<(String, String)>> {
        let key = prefix.as_bytes();
        let from_key = ValueKey::from(ValueClass::Config(key.to_vec()));
        let to_key = ValueKey::from(ValueClass::Config(
            key.iter()
                .copied()
                .chain([u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX])
                .collect::<Vec<_>>(),
        ));
        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let mut key =
                    std::str::from_utf8(key.get(1..).unwrap_or_default()).map_err(|_| {
                        crate::Error::InternalError("Failed to deserialize config key".to_string())
                    })?;
                if strip_prefix && !prefix.is_empty() {
                    key = key.strip_prefix(prefix).unwrap_or(key);
                }

                results.push((key.to_string(), String::deserialize(value)?));

                Ok(true)
            },
        )
        .await?;

        Ok(results)
    }

    pub async fn config_set(&self, keys: impl Iterator<Item = ConfigKey>) -> crate::Result<()> {
        let mut batch = BatchBuilder::new();
        for key in keys {
            batch.set(ValueClass::Config(key.key.into_bytes()), key.value);
        }
        self.write(batch.build()).await.map(|_| ())
    }

    pub async fn config_clear(&self, key: impl Into<String>) -> crate::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Config(key.into().into_bytes()));
        self.write(batch.build()).await.map(|_| ())
    }

    pub async fn config_clear_prefix(&self, key: impl AsRef<str>) -> crate::Result<()> {
        self.delete_range(
            ValueKey::from(ValueClass::Config(key.as_ref().as_bytes().to_vec())),
            ValueKey::from(ValueClass::Config(
                key.as_ref()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain([u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX])
                    .collect::<Vec<_>>(),
            )),
        )
        .await
    }
}
