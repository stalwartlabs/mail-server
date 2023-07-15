/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use store::{write::now, BlobKind, Store};
use utils::config::Config;

use crate::store::TempDir;

const CONFIG_S3: &str = r#"
[store.db]
path = "{TMP}/_blob_s3_test_delete.db?mode=rwc"

[store.blob]
type = "s3"

[store.blob.s3]
access-key = "minioadmin"
secret-key = "minioadmin"
region = "eu-central-1"
endpoint = "http://localhost:9000"
bucket = "tmp"

"#;

const CONFIG_LOCAL: &str = r#"
[store.db]
path = "{TMP}/_blob_s3_test_delete.db?mode=rwc"

[store.blob]
type = "local"

[store.blob.local]
path = "{TMP}"

"#;

const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce erat nisl, dignissim a porttitor id, varius nec arcu. Sed mauris.";

#[tokio::test]
pub async fn blob_tests() {
    let temp_dir = TempDir::new("blob_tests", true);
    test_blob(
        Store::open(
            &Config::parse(
                &CONFIG_LOCAL.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap()),
            )
            .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    test_blob(
        Store::open(
            &Config::parse(&CONFIG_S3.replace("{TMP}", temp_dir.path.as_path().to_str().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    temp_dir.delete();
}

async fn test_blob(store: Store) {
    // Obtain temp quota
    let (quota_items, quota_bytes) = store.get_tmp_blob_usage(2, 100).await.unwrap();
    assert_eq!(quota_items, 0);
    assert_eq!(quota_bytes, 0);
    store.purge_tmp_blobs(0).await.unwrap();

    // Store and fetch
    let kind = BlobKind::LinkedMaildir {
        account_id: 0,
        document_id: 0,
    };
    store.put_blob(&kind, DATA).await.unwrap();
    assert_eq!(
        String::from_utf8(store.get_blob(&kind, 0..u32::MAX).await.unwrap().unwrap()).unwrap(),
        std::str::from_utf8(DATA).unwrap()
    );
    assert_eq!(
        String::from_utf8(store.get_blob(&kind, 11..57).await.unwrap().unwrap()).unwrap(),
        std::str::from_utf8(&DATA[11..57]).unwrap()
    );
    assert!(store.delete_blob(&kind).await.unwrap());
    assert!(store.get_blob(&kind, 0..u32::MAX).await.unwrap().is_none());

    // Copy
    let src_kind = BlobKind::LinkedMaildir {
        account_id: 0,
        document_id: 1,
    };
    store.put_blob(&src_kind, DATA).await.unwrap();
    for id in 0..4 {
        let dest_kind = BlobKind::LinkedMaildir {
            account_id: 1,
            document_id: id,
        };
        assert!(store.copy_blob(&src_kind, &dest_kind, None).await.unwrap());

        assert_eq!(
            String::from_utf8(
                store
                    .get_blob(&dest_kind, 0..u32::MAX)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            std::str::from_utf8(DATA).unwrap()
        );
    }

    // Copy partial
    let now = now();
    let mut tmp_kinds = Vec::new();
    for i in 1..=3 {
        let tmp_kind = BlobKind::Temporary {
            account_id: 2,
            timestamp: now - (i * 5),
            seq: 0,
        };
        assert!(store
            .copy_blob(&src_kind, &tmp_kind, (0..11).into())
            .await
            .unwrap());
        tmp_kinds.push(tmp_kind);
    }

    assert_eq!(
        String::from_utf8(
            store
                .get_blob(&tmp_kinds[0], 0..u32::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[0..11]).unwrap()
    );

    // Obtain temp quota
    let (quota_items, quota_bytes) = store.get_tmp_blob_usage(2, 100).await.unwrap();
    assert_eq!(quota_items, 3);
    assert_eq!(quota_bytes, 33);
    let (quota_items, quota_bytes) = store.get_tmp_blob_usage(2, 12).await.unwrap();
    assert_eq!(quota_items, 2);
    assert_eq!(quota_bytes, 22);

    // Delete range
    store.delete_account_blobs(1).await.unwrap();
    store.purge_tmp_blobs(7).await.unwrap();

    // Make sure the blobs are deleted
    for id in 0..4 {
        assert!(store
            .get_blob(
                &BlobKind::LinkedMaildir {
                    account_id: 1,
                    document_id: id,
                },
                0..u32::MAX
            )
            .await
            .unwrap()
            .is_none());
    }
    for i in [1, 2] {
        assert!(store
            .get_blob(&tmp_kinds[i], 0..u32::MAX)
            .await
            .unwrap()
            .is_none());
    }

    // Make sure other blobs were not deleted
    assert!(store
        .get_blob(&src_kind, 0..u32::MAX)
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_blob(&tmp_kinds[0], 0..u32::MAX)
        .await
        .unwrap()
        .is_some());

    // Copying a non-existing blob should fail
    assert!(!store
        .copy_blob(&tmp_kinds[1], &src_kind, None)
        .await
        .unwrap());

    // Copy blob between buckets
    assert!(store
        .copy_blob(&src_kind, &tmp_kinds[0], (10..20).into())
        .await
        .unwrap());
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(&tmp_kinds[0], 0..u32::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[10..20]).unwrap()
    );

    // Delete blobs
    for blob_kind in [src_kind, tmp_kinds[0]] {
        assert!(store.delete_blob(&blob_kind).await.unwrap());
        assert!(store
            .get_blob(&blob_kind, 0..u32::MAX)
            .await
            .unwrap()
            .is_none());
    }
}
