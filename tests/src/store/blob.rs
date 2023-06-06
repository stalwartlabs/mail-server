use store::{BlobKind, Store};
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
pub async fn blob_s3_test() {
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
    let tmp_kind = BlobKind::Temporary {
        account_id: 1,
        creation_year: 2020,
        creation_month: 12,
        creation_day: 31,
        seq: 0,
    };
    let tmp_kind2 = BlobKind::Temporary {
        account_id: 1,
        creation_year: 2021,
        creation_month: 1,
        creation_day: 1,
        seq: 0,
    };
    assert!(store
        .copy_blob(&src_kind, &tmp_kind, (0..11).into())
        .await
        .unwrap());
    assert!(store
        .copy_blob(&src_kind, &tmp_kind2, (0..11).into())
        .await
        .unwrap());
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(&tmp_kind, 0..u32::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[0..11]).unwrap()
    );

    // Delete range
    store
        .bulk_delete_blob(&BlobKind::LinkedMaildir {
            account_id: 1,
            document_id: 0,
        })
        .await
        .unwrap();
    store.bulk_delete_blob(&tmp_kind).await.unwrap();

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
    assert!(store
        .get_blob(&tmp_kind, 0..u32::MAX)
        .await
        .unwrap()
        .is_none());

    // Make sure other blobs were not deleted
    assert!(store
        .get_blob(&src_kind, 0..u32::MAX)
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_blob(&tmp_kind2, 0..u32::MAX)
        .await
        .unwrap()
        .is_some());

    // Copying a non-existing blob should fail
    assert!(!store.copy_blob(&tmp_kind, &src_kind, None).await.unwrap());

    // Copy blob between buckets
    assert!(store
        .copy_blob(&src_kind, &tmp_kind, (10..20).into())
        .await
        .unwrap());
    assert_eq!(
        String::from_utf8(
            store
                .get_blob(&tmp_kind, 0..u32::MAX)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        std::str::from_utf8(&DATA[10..20]).unwrap()
    );

    // Delete blobs
    for blob_kind in [src_kind, tmp_kind, tmp_kind2] {
        assert!(store.delete_blob(&blob_kind).await.unwrap());
        assert!(store
            .get_blob(&blob_kind, 0..u32::MAX)
            .await
            .unwrap()
            .is_none());
    }
}
