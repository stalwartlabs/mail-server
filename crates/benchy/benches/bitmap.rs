use criterion::{criterion_group, criterion_main, Criterion};
use roaring::RoaringBitmap;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::path::PathBuf;

// Functions to setup the database with the different layouts
// ...

// Functions to insert data into each layout
#[inline(always)]
fn insert_into_layout1(conn: &mut Connection) {
    conn.prepare_cached("DELETE FROM l1")
        .unwrap()
        .execute([])
        .unwrap();

    let mut bitmap_block_num;
    let mut bitmap_col_num;
    let mut bitmap_value_set;
    let trx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    for document_id in 0u32..100_000u32 {
        bitmap_block_num = document_id / BITS_PER_BLOCK;
        let index = document_id & BITS_MASK;
        bitmap_col_num = (index / 64) as usize;
        bitmap_value_set = (1u64 << (index as u64 & 63)) as i64;

        for key in [b"key1", b"key2"] {
            if key == b"key2" && document_id % 2 == 0 {
                continue;
            }
            let mut key = key.to_vec();
            key.extend_from_slice(bitmap_block_num.to_be_bytes().as_ref());

            trx.prepare_cached(SET_QUERIES[bitmap_col_num])
                .unwrap()
                .execute(params![bitmap_value_set, &key])
                .unwrap();
            if trx.changes() == 0 {
                trx.prepare_cached(INSERT_QUERIES[bitmap_col_num])
                    .unwrap()
                    .execute(params![&key, bitmap_value_set])
                    .unwrap();
            }
        }
    }

    trx.commit().unwrap();
}

#[inline(always)]
fn insert_into_layout1a(conn: &mut Connection) {
    conn.prepare_cached("DELETE FROM l1a")
        .unwrap()
        .execute([])
        .unwrap();

    let mut bitmap_block_num;
    let mut bitmap_col_num;
    let mut bitmap_value_set;
    let trx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    for document_id in 0u32..100_000u32 {
        bitmap_block_num = document_id / BITS_PER_BLOCK;
        let index = document_id & BITS_MASK;
        bitmap_col_num = (index / 64) as usize;
        bitmap_value_set = (1u64 << (index as u64 & 63)) as i64;

        for key in [b"key1", b"key2"] {
            if key == b"key2" && document_id % 2 == 0 {
                continue;
            }
            let mut block = Vec::new();
            block.extend_from_slice(bitmap_block_num.to_be_bytes().as_ref());

            trx.prepare_cached(SET_QUERIES2[bitmap_col_num])
                .unwrap()
                .execute(params![bitmap_value_set, &key, &block])
                .unwrap();
            if trx.changes() == 0 {
                trx.prepare_cached(INSERT_QUERIES2[bitmap_col_num])
                    .unwrap()
                    .execute(params![&key, &block, bitmap_value_set])
                    .unwrap();
            }
        }
    }

    trx.commit().unwrap();
}

#[inline(always)]
fn insert_into_layout2(conn: &mut Connection) {
    conn.prepare_cached("DELETE FROM l2")
        .unwrap()
        .execute([])
        .unwrap();

    let trx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    for document_id in 0u32..100_000u32 {
        for key in [b"key1", b"key2"] {
            if key == b"key2" && document_id % 2 == 0 {
                continue;
            }

            let bm = trx
                .prepare_cached("SELECT v FROM l2 WHERE k = ?")
                .unwrap()
                .query_row([&key], |row| {
                    Ok(
                        RoaringBitmap::deserialize_unchecked_from(row.get_ref(0)?.as_bytes()?)
                            .unwrap(),
                    )
                })
                .optional()
                .unwrap();

            if let Some(mut bm) = bm {
                bm.insert(document_id);
                let mut buf = Vec::with_capacity(bm.serialized_size());
                bm.serialize_into(&mut buf).unwrap();

                trx.prepare_cached("UPDATE l2 SET v = ? WHERE k = ?")
                    .unwrap()
                    .execute(params![&buf, key])
                    .unwrap();
            } else {
                let mut bm = RoaringBitmap::new();
                bm.insert(document_id);
                let mut buf = Vec::with_capacity(bm.serialized_size());
                bm.serialize_into(&mut buf).unwrap();
                trx.prepare_cached("INSERT INTO l2 (k, v) VALUES (?, ?)")
                    .unwrap()
                    .execute(params![&key, buf])
                    .unwrap();
            }
        }
    }

    trx.commit().unwrap();
}

#[inline(always)]
fn insert_into_layout3(conn: &mut Connection) {
    conn.prepare_cached("DELETE FROM l3")
        .unwrap()
        .execute([])
        .unwrap();
    let trx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    for document_id in 0u32..100_000u32 {
        for key in [b"key1", b"key2"] {
            if key == b"key2" && document_id % 2 == 0 {
                continue;
            }
            let mut key = key.to_vec();
            key.extend_from_slice(document_id.to_be_bytes().as_ref());

            trx.prepare_cached("INSERT INTO l3 (k) VALUES (?)")
                .unwrap()
                .execute(params![key])
                .unwrap();
        }
    }

    trx.commit().unwrap();
}

// Functions to query each layout
#[inline(always)]
fn query_layout1(conn: &Connection) {
    for (pos, key) in [b"key1", b"key2"].into_iter().enumerate() {
        let mut begin = key.to_vec();
        begin.extend_from_slice(0u32.to_be_bytes().as_ref());
        let key_len = begin.len();
        let mut end = key.to_vec();
        end.extend_from_slice(u32::MAX.to_be_bytes().as_ref());
        let mut query = conn
            .prepare_cached("SELECT z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p FROM l1 WHERE z >= ? AND z <= ?").unwrap();
        let mut rows = query.query([&begin, &end]).unwrap();

        let mut bm = roaring::RoaringBitmap::new();
        while let Some(row) = rows.next().unwrap() {
            let key = row.get_ref(0).unwrap().as_bytes().unwrap();
            if key.len() == key_len {
                let block_num = deserialize_be_u32(key, key.len() - std::mem::size_of::<u32>());

                for word_num in 0..WORDS_PER_BLOCK {
                    match row.get::<_, i64>((word_num + 1) as usize).unwrap() as u64 {
                        0 => (),
                        u64::MAX => {
                            bm.insert_range(
                                block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS
                                    ..(block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS)
                                        + WORD_SIZE_BITS,
                            );
                        }
                        mut word => {
                            while word != 0 {
                                let trailing_zeros = word.trailing_zeros();
                                bm.insert(
                                    block_num * BITS_PER_BLOCK
                                        + word_num * WORD_SIZE_BITS
                                        + trailing_zeros,
                                );
                                word ^= 1 << trailing_zeros;
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(bm.len(), 100_000u64 / std::cmp::max(1, pos as u64 * 2));
    }
}

#[inline(always)]
fn query_layout1a(conn: &Connection) {
    for (pos, key) in [b"key1", b"key2"].into_iter().enumerate() {
        let mut query = conn
            .prepare_cached(
                "SELECT y, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p FROM l1 WHERE z = ?",
            )
            .unwrap();
        let mut rows = query.query([&key]).unwrap();

        let mut bm = roaring::RoaringBitmap::new();
        while let Some(row) = rows.next().unwrap() {
            let block_num = deserialize_be_u32(row.get_ref(0).unwrap().as_bytes().unwrap(), 0);

            for word_num in 0..WORDS_PER_BLOCK {
                match row.get::<_, i64>((word_num + 1) as usize).unwrap() as u64 {
                    0 => (),
                    u64::MAX => {
                        bm.insert_range(
                            block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS
                                ..(block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS)
                                    + WORD_SIZE_BITS,
                        );
                    }
                    mut word => {
                        while word != 0 {
                            let trailing_zeros = word.trailing_zeros();
                            bm.insert(
                                block_num * BITS_PER_BLOCK
                                    + word_num * WORD_SIZE_BITS
                                    + trailing_zeros,
                            );
                            word ^= 1 << trailing_zeros;
                        }
                    }
                }
            }
        }

        assert_eq!(bm.len(), 100_000u64 / std::cmp::max(1, pos as u64 * 2));
    }
}

#[inline(always)]
fn query_layout2(conn: &Connection) {
    for (pos, key) in [b"key1", b"key2"].into_iter().enumerate() {
        let bm = conn
            .prepare_cached("SELECT v FROM l2 WHERE k = ?")
            .unwrap()
            .query_row([key], |row| {
                Ok(RoaringBitmap::deserialize_unchecked_from(row.get_ref(0)?.as_bytes()?).unwrap())
            })
            .optional()
            .unwrap()
            .unwrap();

        assert_eq!(bm.len(), 100_000u64 / std::cmp::max(1, pos as u64 * 2));
    }
}

#[inline(always)]
fn query_layout3(conn: &Connection) {
    for (pos, key) in [b"key1", b"key2"].into_iter().enumerate() {
        let mut begin = key.to_vec();
        begin.extend_from_slice(0u32.to_be_bytes().as_ref());
        let key_len = begin.len();
        let mut end = key.to_vec();
        end.extend_from_slice(u32::MAX.to_be_bytes().as_ref());
        let mut query = conn
            .prepare_cached("SELECT k FROM l3 WHERE k >= ? AND k <= ?")
            .unwrap();
        let mut rows = query.query([&begin, &end]).unwrap();

        let mut bm = roaring::RoaringBitmap::new();
        while let Some(row) = rows.next().unwrap() {
            let key = row.get_ref(0).unwrap().as_bytes().unwrap();
            if key.len() == key_len {
                bm.insert(deserialize_be_u32(
                    key,
                    key.len() - std::mem::size_of::<u32>(),
                ));
            }
        }

        assert_eq!(bm.len(), 100_000u64 / std::cmp::max(1, pos as u64 * 2));
    }
}

// Criterion benchmarks
pub fn insertion_benchmark(c: &mut Criterion) {
    let path = PathBuf::from("/tmp/benchy.sqlite3");
    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }

    let mut conn = Connection::open_with_flags(path, OpenFlags::default()).unwrap();
    let mut group = c.benchmark_group("SQLite Layouts Insertion");
    group.measurement_time(std::time::Duration::new(15, 0));
    group.sample_size(10);

    conn.execute_batch(concat!(
        "PRAGMA journal_mode = WAL; ",
        "PRAGMA synchronous = NORMAL; ",
        "PRAGMA temp_store = memory;",
        "PRAGMA busy_timeout = 30000;"
    ))
    .unwrap();

    // Setup each layout and benchmark insertion
    conn.execute(
        "CREATE TABLE IF NOT EXISTS l1 (
                z BLOB PRIMARY KEY,
                a INTEGER NOT NULL DEFAULT 0,
                b INTEGER NOT NULL DEFAULT 0,
                c INTEGER NOT NULL DEFAULT 0,
                d INTEGER NOT NULL DEFAULT 0,
                e INTEGER NOT NULL DEFAULT 0,
                f INTEGER NOT NULL DEFAULT 0,
                g INTEGER NOT NULL DEFAULT 0,
                h INTEGER NOT NULL DEFAULT 0,
                i INTEGER NOT NULL DEFAULT 0,
                j INTEGER NOT NULL DEFAULT 0,
                k INTEGER NOT NULL DEFAULT 0,
                l INTEGER NOT NULL DEFAULT 0,
                m INTEGER NOT NULL DEFAULT 0,
                n INTEGER NOT NULL DEFAULT 0,
                o INTEGER NOT NULL DEFAULT 0,
                p INTEGER NOT NULL DEFAULT 0
            )",
        [],
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS l1a (
                z BLOB NOT NULL,
                y BLOB NOT NULL,
                a INTEGER NOT NULL DEFAULT 0,
                b INTEGER NOT NULL DEFAULT 0,
                c INTEGER NOT NULL DEFAULT 0,
                d INTEGER NOT NULL DEFAULT 0,
                e INTEGER NOT NULL DEFAULT 0,
                f INTEGER NOT NULL DEFAULT 0,
                g INTEGER NOT NULL DEFAULT 0,
                h INTEGER NOT NULL DEFAULT 0,
                i INTEGER NOT NULL DEFAULT 0,
                j INTEGER NOT NULL DEFAULT 0,
                k INTEGER NOT NULL DEFAULT 0,
                l INTEGER NOT NULL DEFAULT 0,
                m INTEGER NOT NULL DEFAULT 0,
                n INTEGER NOT NULL DEFAULT 0,
                o INTEGER NOT NULL DEFAULT 0,
                p INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (z, y)
            )",
        [],
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS l2 (
        k BLOB PRIMARY KEY,
        v BLOB NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS l3 (
        k BLOB PRIMARY KEY)",
        [],
    )
    .unwrap();

    group.bench_function("Insertion Layout 1", |b| {
        b.iter(|| insert_into_layout1(&mut conn))
    });

    group.bench_function("Insertion Layout 1a", |b| {
        b.iter(|| insert_into_layout1a(&mut conn))
    });

    /*group.bench_function("Insertion Layout 2", |b| {
        b.iter(|| insert_into_layout2(&mut conn))
    });

    group.bench_function("Insertion Layout 3", |b| {
        b.iter(|| insert_into_layout3(&mut conn))
    });*/

    group.finish();
}

pub fn query_benchmark(c: &mut Criterion) {
    let conn = Connection::open_with_flags("/tmp/benchy.sqlite3", OpenFlags::default()).unwrap();
    conn.execute_batch(concat!(
        "PRAGMA journal_mode = WAL; ",
        "PRAGMA synchronous = NORMAL; ",
        "PRAGMA temp_store = memory;",
        "PRAGMA busy_timeout = 30000;"
    ))
    .unwrap();

    let mut group = c.benchmark_group("SQLite Layouts Query");
    //group.measurement_time(Duration::new(5, 0));
    //group.sample_size(10);

    // Assume the layouts are already populated with data
    // Benchmark querying for each layout
    group.bench_function("Query Layout 1", |b| b.iter(|| query_layout1(&conn)));
    group.bench_function("Query Layout 1a", |b| b.iter(|| query_layout1(&conn)));

    //group.bench_function("Query Layout 2", |b| b.iter(|| query_layout2(&conn)));
    //group.bench_function("Query Layout 3", |b| b.iter(|| query_layout3(&conn)));

    group.finish();
}

// Criterion groups
//criterion_group!(insertion_benches, insertion_benchmark);
criterion_group!(query_benches, query_benchmark);
//criterion_main!(insertion_benches, query_benches);
criterion_main!(query_benches);

const INSERT_QUERIES: &[&str] = &[
    "INSERT INTO l1 (z, a) VALUES (?, ?)",
    "INSERT INTO l1 (z, b) VALUES (?, ?)",
    "INSERT INTO l1 (z, c) VALUES (?, ?)",
    "INSERT INTO l1 (z, d) VALUES (?, ?)",
    "INSERT INTO l1 (z, e) VALUES (?, ?)",
    "INSERT INTO l1 (z, f) VALUES (?, ?)",
    "INSERT INTO l1 (z, g) VALUES (?, ?)",
    "INSERT INTO l1 (z, h) VALUES (?, ?)",
    "INSERT INTO l1 (z, i) VALUES (?, ?)",
    "INSERT INTO l1 (z, j) VALUES (?, ?)",
    "INSERT INTO l1 (z, k) VALUES (?, ?)",
    "INSERT INTO l1 (z, l) VALUES (?, ?)",
    "INSERT INTO l1 (z, m) VALUES (?, ?)",
    "INSERT INTO l1 (z, n) VALUES (?, ?)",
    "INSERT INTO l1 (z, o) VALUES (?, ?)",
    "INSERT INTO l1 (z, p) VALUES (?, ?)",
];
const SET_QUERIES: &[&str] = &[
    "UPDATE l1 SET a = a | ? WHERE z = ?",
    "UPDATE l1 SET b = b | ? WHERE z = ?",
    "UPDATE l1 SET c = c | ? WHERE z = ?",
    "UPDATE l1 SET d = d | ? WHERE z = ?",
    "UPDATE l1 SET e = e | ? WHERE z = ?",
    "UPDATE l1 SET f = f | ? WHERE z = ?",
    "UPDATE l1 SET g = g | ? WHERE z = ?",
    "UPDATE l1 SET h = h | ? WHERE z = ?",
    "UPDATE l1 SET i = i | ? WHERE z = ?",
    "UPDATE l1 SET j = j | ? WHERE z = ?",
    "UPDATE l1 SET k = k | ? WHERE z = ?",
    "UPDATE l1 SET l = l | ? WHERE z = ?",
    "UPDATE l1 SET m = m | ? WHERE z = ?",
    "UPDATE l1 SET n = n | ? WHERE z = ?",
    "UPDATE l1 SET o = o | ? WHERE z = ?",
    "UPDATE l1 SET p = p | ? WHERE z = ?",
];

const INSERT_QUERIES2: &[&str] = &[
    "INSERT INTO l1a (z, y, a) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, b) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, c) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, d) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, e) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, f) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, g) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, h) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, i) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, j) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, k) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, l) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, m) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, n) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, o) VALUES (?, ?, ?)",
    "INSERT INTO l1a (z, y, p) VALUES (?, ?, ?)",
];
const SET_QUERIES2: &[&str] = &[
    "UPDATE l1a SET a = a | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET b = b | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET c = c | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET d = d | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET e = e | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET f = f | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET g = g | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET h = h | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET i = i | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET j = j | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET k = k | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET l = l | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET m = m | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET n = n | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET o = o | ? WHERE z = ? AND y = ?",
    "UPDATE l1a SET p = p | ? WHERE z = ? AND y = ?",
];

const WORD_SIZE_BITS: u32 = (WORD_SIZE * 8) as u32;
const WORD_SIZE: usize = std::mem::size_of::<u64>();
const WORDS_PER_BLOCK: u32 = 16;
pub const BITS_PER_BLOCK: u32 = WORD_SIZE_BITS * WORDS_PER_BLOCK;
const BITS_MASK: u32 = BITS_PER_BLOCK - 1;

fn deserialize_be_u32(bytes: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(
        bytes
            .get(index..index + std::mem::size_of::<u32>())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
