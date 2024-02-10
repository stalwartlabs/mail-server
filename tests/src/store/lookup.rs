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

use store::{config::ConfigStore, LookupStore};
use utils::config::Config;

use crate::store::{TempDir, CONFIG};

#[tokio::test]
pub async fn lookup_tests() {
    let temp_dir = TempDir::new("lookup_tests", true);
    let config =
        Config::new(&CONFIG.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap())).unwrap();
    let stores = config.parse_stores().await.unwrap();

    let todo = "test expiry counter + ratelimit";
    let todo = "use lookup ratelimit everywhere";

    for (store_id, store) in stores.lookup_stores {
        println!("Testing lookup store {}...", store_id);
        if let LookupStore::Store(store) = &store {
            store.destroy().await;
        } else {
            // Reset redis counter
            store
                .key_set("abc".as_bytes().to_vec(), "0".as_bytes().to_vec(), None)
                .await
                .unwrap();
        }

        // Test key
        let key = "xyz".as_bytes().to_vec();
        store
            .key_set(key.clone(), "world".to_string().into_bytes(), None)
            .await
            .unwrap();
        store.purge_expired().await.unwrap();
        assert_eq!(
            store.key_get::<String>(key.clone()).await.unwrap(),
            Some("world".to_string())
        );

        // Test value expiry
        store
            .key_set(key.clone(), "hello".to_string().into_bytes(), 1.into())
            .await
            .unwrap();
        assert_eq!(
            store.key_get::<String>(key.clone()).await.unwrap(),
            Some("hello".to_string())
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert_eq!(None, store.key_get::<String>(key.clone()).await.unwrap());

        store.purge_expired().await.unwrap();
        if let LookupStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }

        // Test counter
        let key = "abc".as_bytes().to_vec();
        store.counter_incr(key.clone(), 1, None).await.unwrap();
        assert_eq!(1, store.counter_get(key.clone()).await.unwrap());
        store.counter_incr(key.clone(), 2, None).await.unwrap();
        assert_eq!(3, store.counter_get(key.clone()).await.unwrap());
    }
}
