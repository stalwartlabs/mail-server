/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
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

use store::{config::ConfigStore, LookupKey, LookupStore, LookupValue};
use utils::config::Config;

use crate::store::{TempDir, CONFIG};

#[tokio::test]
pub async fn lookup_tests() {
    let temp_dir = TempDir::new("lookup_tests", true);
    let config =
        Config::new(&CONFIG.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap())).unwrap();
    let stores = config.parse_stores().await.unwrap();

    for (store_id, store) in stores.lookup_stores {
        println!("Testing lookup store {}...", store_id);
        if let LookupStore::Store(store) = &store {
            store.destroy().await;
        }

        // Test value expiry
        let key = "xyz".as_bytes().to_vec();
        assert_eq!(
            LookupValue::None,
            store
                .key_get::<String>(LookupKey::Key(key.clone()))
                .await
                .unwrap()
        );
        store
            .key_set(
                key.clone(),
                LookupValue::Value {
                    value: "hello".to_string().into_bytes(),
                    expires: 1,
                },
            )
            .await
            .unwrap();
        assert!(matches!(store
            .key_get::<String>(LookupKey::Key(key.clone()))
            .await
            .unwrap(), LookupValue::Value { value,.. } if value == "hello"));
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert_eq!(
            LookupValue::None,
            store
                .key_get::<String>(LookupKey::Key(key.clone()))
                .await
                .unwrap()
        );

        store.purge_expired().await.unwrap();
        if let LookupStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }

        // Test key
        store
            .key_set(
                key.clone(),
                LookupValue::Value {
                    value: "world".to_string().into_bytes(),
                    expires: 0,
                },
            )
            .await
            .unwrap();
        store.purge_expired().await.unwrap();
        assert!(matches!(store
        .key_get::<String>(LookupKey::Key(key.clone()))
        .await
        .unwrap(), LookupValue::Value { value,.. } if value == "world"));

        // Test counter
        let key = "abc".as_bytes().to_vec();
        store
            .key_set(key.clone(), LookupValue::Counter { num: 1 })
            .await
            .unwrap();
        assert_eq!(
            LookupValue::Counter { num: 1 },
            store
                .key_get::<String>(LookupKey::Counter(key.clone()))
                .await
                .unwrap()
        );
        store
            .key_set(key.clone(), LookupValue::Counter { num: 2 })
            .await
            .unwrap();
        assert_eq!(
            LookupValue::Counter { num: 3 },
            store
                .key_get::<String>(LookupKey::Counter(key.clone()))
                .await
                .unwrap()
        );
    }
}
