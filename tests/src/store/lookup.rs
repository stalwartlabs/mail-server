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

use std::time::Duration;

use store::{LookupStore, Stores};
use utils::config::{Config, Rate};

use crate::{
    store::{TempDir, CONFIG},
    AssertConfig,
};

#[tokio::test]
pub async fn lookup_tests() {
    let temp_dir = TempDir::new("lookup_tests", true);
    let mut config =
        Config::new(CONFIG.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap()))
            .unwrap()
            .assert_no_errors();
    let stores = Stores::parse(&mut config).await;
    let rate = Rate {
        requests: 1,
        period: Duration::from_secs(1),
    };

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
        store.purge_lookup_store().await.unwrap();
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

        store.purge_lookup_store().await.unwrap();
        if let LookupStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }

        // Test counter
        let key = "abc".as_bytes().to_vec();
        store
            .counter_incr(key.clone(), 1, None, false)
            .await
            .unwrap();
        assert_eq!(1, store.counter_get(key.clone()).await.unwrap());
        store
            .counter_incr(key.clone(), 2, None, false)
            .await
            .unwrap();
        assert_eq!(3, store.counter_get(key.clone()).await.unwrap());
        store
            .counter_incr(key.clone(), -3, None, false)
            .await
            .unwrap();
        assert_eq!(0, store.counter_get(key.clone()).await.unwrap());

        // Test counter expiry
        let key = "fgh".as_bytes().to_vec();
        store
            .counter_incr(key.clone(), 1, 1.into(), false)
            .await
            .unwrap();
        assert_eq!(1, store.counter_get(key.clone()).await.unwrap());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        store.purge_lookup_store().await.unwrap();
        assert_eq!(0, store.counter_get(key.clone()).await.unwrap());

        // Test rate limiter
        assert!(store
            .is_rate_allowed("rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .is_rate_allowed("rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_some());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        assert!(store
            .is_rate_allowed("rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_none());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        store.purge_lookup_store().await.unwrap();
        if let LookupStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }
    }
}
