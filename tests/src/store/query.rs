/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    io::Write,
    sync::{Arc, Mutex},
    time::Instant,
};

use jmap_proto::types::keyword::Keyword;
use nlp::language::Language;
use store::{
    ahash::AHashMap,
    fts::{index::FtsDocument, Field, FtsFilter},
    query::sort::Pagination,
    write::ValueClass,
    FtsStore,
};

use store::{
    query::{Comparator, Filter},
    write::{BatchBuilder, F_BITMAP, F_INDEX, F_VALUE},
    Store, ValueKey,
};

use crate::store::deflate_test_resource;

pub const FIELDS: [&str; 20] = [
    "id",
    "accession_number",
    "artist",
    "artistRole",
    "artistId",
    "title",
    "dateText",
    "medium",
    "creditLine",
    "year",
    "acquisitionYear",
    "dimensions",
    "width",
    "height",
    "depth",
    "units",
    "inscription",
    "thumbnailCopyright",
    "thumbnailUrl",
    "url",
];

const COLLECTION_ID: u8 = 0;

enum FieldType {
    Keyword,
    Text,
    FullText,
    Integer,
}

const FIELDS_OPTIONS: [FieldType; 20] = [
    FieldType::Integer,  // "id",
    FieldType::Keyword,  // "accession_number",
    FieldType::Text,     // "artist",
    FieldType::Keyword,  // "artistRole",
    FieldType::Integer,  // "artistId",
    FieldType::FullText, // "title",
    FieldType::FullText, // "dateText",
    FieldType::FullText, // "medium",
    FieldType::FullText, // "creditLine",
    FieldType::Integer,  // "year",
    FieldType::Integer,  // "acquisitionYear",
    FieldType::FullText, // "dimensions",
    FieldType::Integer,  // "width",
    FieldType::Integer,  // "height",
    FieldType::Integer,  // "depth",
    FieldType::Text,     // "units",
    FieldType::FullText, // "inscription",
    FieldType::Text,     // "thumbnailCopyright",
    FieldType::Text,     // "thumbnailUrl",
    FieldType::Text,     // "url",
];

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FieldId(u8);

impl From<FieldId> for u8 {
    fn from(field_id: FieldId) -> Self {
        field_id.0
    }
}
impl Display for FieldId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", FIELDS[self.0 as usize])
    }
}

impl FieldId {
    pub fn new(field_id: u8) -> Field<FieldId> {
        Field::Header(Self(field_id))
    }

    pub fn inner(&self) -> u8 {
        self.0
    }
}

#[allow(clippy::mutex_atomic)]
pub async fn test(db: Store, fts_store: FtsStore, do_insert: bool) {
    println!("Running Store query tests...");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    let now = Instant::now();
    let documents = Arc::new(Mutex::new(Vec::new()));

    if do_insert {
        pool.scope_fifo(|s| {
            for (document_id, record) in csv::ReaderBuilder::new()
                .has_headers(true)
                .from_reader(&deflate_test_resource("artwork_data.csv.gz")[..])
                .records()
                .enumerate()
            {
                let record = record.unwrap();
                let documents = documents.clone();

                s.spawn_fifo(move |_| {
                    let mut fts_builder = FtsDocument::with_default_language(Language::English)
                        .with_account_id(0)
                        .with_collection(COLLECTION_ID)
                        .with_document_id(document_id as u32);
                    let mut builder = BatchBuilder::new();
                    builder
                        .with_account_id(0)
                        .with_collection(COLLECTION_ID)
                        .create_document_with_id(document_id as u32);
                    for (pos, field) in record.iter().enumerate() {
                        let field_id = pos as u8;
                        match FIELDS_OPTIONS[pos] {
                            FieldType::Text => {
                                if !field.is_empty() {
                                    builder.value(
                                        field_id,
                                        field.to_lowercase(),
                                        F_VALUE | F_BITMAP,
                                    );
                                }
                            }
                            FieldType::FullText => {
                                if !field.is_empty() {
                                    fts_builder.index(
                                        FieldId::new(field_id),
                                        field.to_lowercase(),
                                        Language::English,
                                    );
                                    if field_id == 7 {
                                        builder.value(field_id, field.to_lowercase(), F_INDEX);
                                    }
                                }
                            }
                            FieldType::Integer => {
                                builder.value(
                                    field_id,
                                    field.parse::<u32>().unwrap_or(0),
                                    F_VALUE | F_INDEX,
                                );
                            }
                            FieldType::Keyword => {
                                if !field.is_empty() {
                                    builder.value(
                                        field_id,
                                        Keyword::Other(field.to_lowercase()),
                                        F_VALUE | F_INDEX | F_BITMAP,
                                    );
                                }
                            }
                        }
                    }

                    documents
                        .lock()
                        .unwrap()
                        .push((builder.build(), fts_builder));
                });
            }
        });

        println!(
            "Parsed {} entries in {} ms.",
            documents.lock().unwrap().len(),
            now.elapsed().as_millis()
        );

        let now = Instant::now();
        let batches = documents.lock().unwrap().drain(..).collect::<Vec<_>>();
        let mut chunk = Vec::new();
        let mut fts_chunk = Vec::new();

        print!("Inserting... ",);
        for (batch, fts_batch) in batches {
            let chunk_instance = Instant::now();
            chunk.push({
                let db = db.clone();
                tokio::spawn(async move { db.write(batch).await })
            });
            fts_chunk.push({
                let fts_store = fts_store.clone();
                tokio::spawn(async move { fts_store.index(fts_batch).await })
            });
            if chunk.len() == 1000 {
                for handle in chunk {
                    handle.await.unwrap().unwrap();
                }
                for handle in fts_chunk {
                    handle.await.unwrap().unwrap();
                }
                print!(" [{} ms]", chunk_instance.elapsed().as_millis());
                std::io::stdout().flush().unwrap();
                chunk = Vec::new();
                fts_chunk = Vec::new();
            }
        }

        if !chunk.is_empty() {
            for handle in chunk {
                handle.await.unwrap().unwrap();
            }
        }

        println!("\nInsert took {} ms.", now.elapsed().as_millis());
    }

    println!("Running filter tests...");
    let now = Instant::now();
    test_filter(db.clone(), fts_store).await;
    println!("Filtering took {} ms.", now.elapsed().as_millis());

    println!("Running sort tests...");
    let now = Instant::now();
    test_sort(db).await;
    println!("Sorting took {} ms.", now.elapsed().as_millis());
}

pub async fn test_filter(db: Store, fts: FtsStore) {
    let mut fields = AHashMap::default();
    let mut fields_u8 = AHashMap::default();
    for (field_num, field) in FIELDS.iter().enumerate() {
        fields.insert(field.to_string(), FieldId::new(field_num as u8));
        fields_u8.insert(field.to_string(), field_num as u8);
    }

    let tests = [
        (
            vec![
                Filter::is_in_set(
                    fts.query(
                        0,
                        COLLECTION_ID,
                        vec![FtsFilter::has_english_text(
                            fields["title"].clone(),
                            "water",
                        )],
                    )
                    .await
                    .unwrap(),
                ),
                Filter::eq(fields_u8["year"], 1979u32),
            ],
            vec!["p11293"],
        ),
        (
            vec![
                Filter::is_in_set(
                    fts.query(
                        0,
                        COLLECTION_ID,
                        vec![FtsFilter::has_english_text(
                            fields["medium"].clone(),
                            "gelatin",
                        )],
                    )
                    .await
                    .unwrap(),
                ),
                Filter::gt(fields_u8["year"], 2000u32),
                Filter::lt(fields_u8["width"], 180u32),
                Filter::gt(fields_u8["width"], 0u32),
            ],
            vec!["p79426", "p79427", "p79428", "p79429", "p79430"],
        ),
        (
            vec![Filter::is_in_set(
                fts.query(
                    0,
                    COLLECTION_ID,
                    vec![FtsFilter::has_english_text(
                        fields["title"].clone(),
                        "'rustic bridge'",
                    )],
                )
                .await
                .unwrap(),
            )],
            vec!["d05503"],
        ),
        (
            vec![Filter::is_in_set(
                fts.query(
                    0,
                    COLLECTION_ID,
                    vec![
                        FtsFilter::has_english_text(fields["title"].clone(), "'rustic'"),
                        FtsFilter::has_english_text(fields["title"].clone(), "study"),
                    ],
                )
                .await
                .unwrap(),
            )],
            vec!["d00399", "d05352"],
        ),
        (
            vec![
                Filter::has_text(fields_u8["artist"], "mauro kunst"),
                Filter::is_in_bitmap(
                    fields_u8["artistRole"],
                    Keyword::Other("artist".to_string()),
                ),
                Filter::Or,
                Filter::eq(fields_u8["year"], 1969u32),
                Filter::eq(fields_u8["year"], 1971u32),
                Filter::End,
            ],
            vec!["p01764", "t05843"],
        ),
        (
            vec![
                Filter::is_in_set(
                    fts.query(
                        0,
                        COLLECTION_ID,
                        vec![
                            FtsFilter::Not,
                            FtsFilter::has_english_text(fields["medium"].clone(), "oil"),
                            FtsFilter::End,
                            FtsFilter::has_english_text(fields["creditLine"].clone(), "bequeath"),
                        ],
                    )
                    .await
                    .unwrap(),
                ),
                Filter::Or,
                Filter::And,
                Filter::ge(fields_u8["year"], 1900u32),
                Filter::lt(fields_u8["year"], 1910u32),
                Filter::End,
                Filter::And,
                Filter::ge(fields_u8["year"], 2000u32),
                Filter::lt(fields_u8["year"], 2010u32),
                Filter::End,
                Filter::End,
            ],
            vec![
                "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721", "n04739",
                "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
                "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155",
            ],
        ),
        (
            vec![
                Filter::And,
                Filter::has_text(fields_u8["artist"], "warhol"),
                Filter::Not,
                Filter::is_in_set(
                    fts.query(
                        0,
                        COLLECTION_ID,
                        vec![FtsFilter::has_english_text(
                            fields["title"].clone(),
                            "'campbell'",
                        )],
                    )
                    .await
                    .unwrap(),
                ),
                Filter::End,
                Filter::Not,
                Filter::Or,
                Filter::gt(fields_u8["year"], 1980u32),
                Filter::And,
                Filter::gt(fields_u8["width"], 500u32),
                Filter::gt(fields_u8["height"], 500u32),
                Filter::End,
                Filter::End,
                Filter::End,
                Filter::eq(fields_u8["acquisitionYear"], 2008u32),
                Filter::End,
            ],
            vec!["ar00039", "t12600"],
        ),
        (
            vec![
                Filter::is_in_set(
                    fts.query(
                        0,
                        COLLECTION_ID,
                        vec![
                            FtsFilter::has_english_text(fields["title"].clone(), "study"),
                            FtsFilter::has_english_text(fields["medium"].clone(), "paper"),
                            FtsFilter::has_english_text(
                                fields["creditLine"].clone(),
                                "'purchased'",
                            ),
                            FtsFilter::Not,
                            FtsFilter::has_english_text(fields["title"].clone(), "'anatomical'"),
                            FtsFilter::has_english_text(fields["title"].clone(), "'for'"),
                            FtsFilter::End,
                        ],
                    )
                    .await
                    .unwrap(),
                ),
                Filter::gt(fields_u8["year"], 1900u32),
                Filter::gt(fields_u8["acquisitionYear"], 2000u32),
            ],
            vec![
                "p80042", "p80043", "p80044", "p80045", "p80203", "t11937", "t12172",
            ],
        ),
    ];

    for (filter, expected_results) in tests {
        //println!("Running test: {:?}", filter);
        let docset = db.filter(0, COLLECTION_ID, filter).await.unwrap();
        let sorted_docset = db
            .sort(
                docset,
                vec![Comparator::ascending(fields_u8["accession_number"])],
                Pagination::new(0, 0, None, 0),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in sorted_docset.ids {
            results.push(
                db.get_value::<String>(ValueKey {
                    account_id: 0,
                    collection: COLLECTION_ID,
                    document_id: document_id as u32,
                    class: ValueClass::Property(fields_u8["accession_number"]),
                })
                .await
                .unwrap()
                .unwrap(),
            );
        }
        assert_eq!(results, expected_results);
    }
}

pub async fn test_sort(db: Store) {
    let mut fields = AHashMap::default();
    for (field_num, field) in FIELDS.iter().enumerate() {
        fields.insert(field.to_string(), field_num as u8);
    }

    let tests = [
        (
            vec![
                Filter::gt(fields["year"], 0u32),
                Filter::gt(fields["acquisitionYear"], 0u32),
                Filter::gt(fields["width"], 0u32),
            ],
            vec![
                Comparator::descending(fields["year"]),
                Comparator::ascending(fields["acquisitionYear"]),
                Comparator::ascending(fields["width"]),
                Comparator::descending(fields["accession_number"]),
            ],
            vec![
                "t13655", "t13811", "p13352", "p13351", "p13350", "p13349", "p13348", "p13347",
                "p13346", "p13345", "p13344", "p13342", "p13341", "p13340", "p13339", "p13338",
                "p13337", "p13336", "p13335", "p13334", "p13333", "p13332", "p13331", "p13330",
                "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323", "t13786",
                "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
                "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444",
                "ar01154", "ar01153",
            ],
        ),
        (
            vec![
                Filter::gt(fields["width"], 0u32),
                Filter::gt(fields["height"], 0u32),
            ],
            vec![
                Comparator::descending(fields["width"]),
                Comparator::ascending(fields["height"]),
            ],
            vec![
                "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
                "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855",
                "t01355", "t12800", "t12557", "t02078",
            ],
        ),
        (
            vec![],
            vec![
                Comparator::descending(fields["medium"]),
                Comparator::descending(fields["artistRole"]),
                Comparator::ascending(fields["accession_number"]),
            ],
            vec![
                "ar00627", "ar00052", "t00352", "t07275", "t12318", "t04931", "t13683", "t13686",
                "t13687", "t13688", "t13689", "t13690", "t13691", "t07766", "t07918", "t12993",
                "ar00044", "t13326", "t07614", "t12414",
            ],
        ),
    ];

    for (filter, sort, expected_results) in tests {
        //println!("Running test: {:?}", sort);
        let docset = db.filter(0, COLLECTION_ID, filter).await.unwrap();

        let sorted_docset = db
            .sort(
                docset,
                sort,
                Pagination::new(expected_results.len(), 0, None, 0),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in sorted_docset.ids {
            results.push(
                db.get_value::<String>(ValueKey {
                    account_id: 0,
                    collection: COLLECTION_ID,
                    document_id: document_id as u32,
                    class: ValueClass::Property(fields["accession_number"]),
                })
                .await
                .unwrap()
                .unwrap(),
            );
        }
        assert_eq!(results, expected_results);
    }
}
