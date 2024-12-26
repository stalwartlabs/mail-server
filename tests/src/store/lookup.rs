/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use store::{dispatch::lookup::KeyValue, InMemoryStore, Stores};
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
    let stores = Stores::parse_all(&mut config).await;
    let rate = Rate {
        requests: 1,
        period: Duration::from_secs(1),
    };

    for (store_id, store) in stores.in_memory_stores {
        let is_mysql = store_id == "mysql";
        println!("Testing lookup store {}...", store_id);
        if let InMemoryStore::Store(store) = &store {
            store.destroy().await;
        } else {
            // Reset redis counter
            store
                .key_set(KeyValue::new("abc", "0".as_bytes().to_vec()))
                .await
                .unwrap();
        }

        // Test key
        let key = "xyz".as_bytes().to_vec();
        store
            .key_set(KeyValue::new(key.clone(), "world".to_string().into_bytes()))
            .await
            .unwrap();
        store.purge_in_memory_store().await.unwrap();
        assert_eq!(
            store.key_get::<String>(key.clone()).await.unwrap(),
            Some("world".to_string())
        );

        // Test value expiry
        store
            .key_set(KeyValue::new(key.clone(), "hello".to_string().into_bytes()).expires(1))
            .await
            .unwrap();
        assert_eq!(
            store.key_get::<String>(key.clone()).await.unwrap(),
            Some("hello".to_string())
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert_eq!(None, store.key_get::<String>(key.clone()).await.unwrap());

        store.purge_in_memory_store().await.unwrap();
        if let InMemoryStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }

        // Test counter
        let key = "abc".as_bytes().to_vec();
        store
            .counter_incr(KeyValue::new(key.clone(), 1))
            .await
            .unwrap();
        assert_eq!(1, store.counter_get(key.clone()).await.unwrap());
        store
            .counter_incr(KeyValue::new(key.clone(), 2))
            .await
            .unwrap();
        assert_eq!(3, store.counter_get(key.clone()).await.unwrap());
        if !is_mysql {
            store
                .counter_incr(KeyValue::new(key.clone(), -3))
                .await
                .unwrap();
        } else {
            // TODO: Detect mySQL version and use RETURNING
            store.counter_delete(key.clone()).await.unwrap();
        }
        assert_eq!(0, store.counter_get(key.clone()).await.unwrap());

        // Test counter expiry
        let key = "fgh".as_bytes().to_vec();
        store
            .counter_incr(KeyValue::new(key.clone(), 1).expires(1))
            .await
            .unwrap();
        assert_eq!(1, store.counter_get(key.clone()).await.unwrap());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        store.purge_in_memory_store().await.unwrap();
        assert_eq!(0, store.counter_get(key.clone()).await.unwrap());

        // Test rate limiter
        assert!(store
            .is_rate_allowed(0, "rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .is_rate_allowed(0, "rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_some());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        assert!(store
            .is_rate_allowed(0, "rate".as_bytes(), &rate, false)
            .await
            .unwrap()
            .is_none());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        store.purge_in_memory_store().await.unwrap();
        if let InMemoryStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }

        // Test prefix delete
        store
            .key_set(KeyValue::with_prefix(
                1,
                [0],
                "hello".to_string().into_bytes(),
            ))
            .await
            .unwrap();
        for v in 0u32..2020u32 {
            store
                .key_set(KeyValue::with_prefix(
                    0,
                    pack_u32(0, v),
                    "world".to_string().into_bytes(),
                ))
                .await
                .unwrap();
            store
                .counter_incr(KeyValue::with_prefix(0, pack_u32(1, v), 123).expires(3600))
                .await
                .unwrap();
        }

        // Make sure the keys are there
        assert_eq!(
            Some("hello"),
            store
                .key_get::<String>(KeyValue::<()>::build_key(1, [0]))
                .await
                .unwrap()
                .as_deref()
        );
        for v in [0, 1000, 1001, 2000, 2001] {
            assert_eq!(
                Some("world"),
                store
                    .key_get::<String>(KeyValue::<()>::build_key(0, pack_u32(0, v)))
                    .await
                    .unwrap()
                    .as_deref()
            );
        }
        for v in [0, 1000, 1001, 2000, 2001] {
            assert_ne!(
                0,
                store
                    .counter_get(KeyValue::<()>::build_key(0, pack_u32(1, v)))
                    .await
                    .unwrap()
            );
        }

        // Delete [0, 0, 0, 0, 1] prefix and make sure only the keys with that prefix are gone
        store
            .key_delete_prefix(&KeyValue::<()>::build_key(0, 1u32.to_be_bytes()))
            .await
            .unwrap();

        assert_eq!(
            Some("hello"),
            store
                .key_get::<String>(KeyValue::<()>::build_key(1, [0]))
                .await
                .unwrap()
                .as_deref()
        );
        for v in [0, 1000, 1001, 2000, 2001] {
            assert_eq!(
                Some("world"),
                store
                    .key_get::<String>(KeyValue::<()>::build_key(0, pack_u32(0, v)))
                    .await
                    .unwrap()
                    .as_deref()
            );
        }

        for v in [0, 1000, 1001, 2000, 2001] {
            assert_eq!(
                0,
                store
                    .counter_get(KeyValue::<()>::build_key(0, pack_u32(1, v)))
                    .await
                    .unwrap()
            );
        }

        // Delete [0, 0, 0, 0, 0] prefix and make sure only the keys with that prefix are gone
        store
            .key_delete_prefix(&KeyValue::<()>::build_key(0, 0u32.to_be_bytes()))
            .await
            .unwrap();

        assert_eq!(
            Some("hello"),
            store
                .key_get::<String>(KeyValue::<()>::build_key(1, [0]))
                .await
                .unwrap()
                .as_deref()
        );
        for v in [0, 1000, 1001, 2000, 2001] {
            assert_eq!(
                None,
                store
                    .key_get::<String>(KeyValue::<()>::build_key(0, pack_u32(0, v)))
                    .await
                    .unwrap()
                    .as_deref()
            );
        }

        // Delete [1, ...] prefix and make sure it's all gone
        store.key_delete_prefix(&[1u8]).await.unwrap();

        assert_eq!(
            None,
            store
                .key_get::<String>(KeyValue::<()>::build_key(1, [0]))
                .await
                .unwrap()
                .as_deref()
        );

        if let InMemoryStore::Store(store) = &store {
            store.assert_is_empty(store.clone().into()).await;
        }
    }
}

fn pack_u32(a: u32, b: u32) -> Vec<u8> {
    ((a as u64) << 32 | b as u64).to_be_bytes().to_vec()
}
