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

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use jmap_proto::types::keyword::Keyword;
use nlp::language::Language;
use store::{ahash::AHashMap, query::sort::Pagination, write::ValueClass, StoreWrite};

use store::{
    query::{Comparator, Filter},
    write::{BatchBuilder, F_BITMAP, F_INDEX, F_VALUE},
    Store, ValueKey,
};

use crate::store::deflate_artwork_data;

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

#[allow(clippy::mutex_atomic)]
pub async fn test(db: Arc<impl Store + Send + 'static>, do_insert: bool) {
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
                .from_reader(&deflate_artwork_data()[..])
                .records()
                .enumerate()
            {
                let record = record.unwrap();
                let documents = documents.clone();

                s.spawn_fifo(move |_| {
                    /*let mut fts_builder = FtsIndexBuilder::with_default_language(Language::English);
                    let mut builder = BatchBuilder::new();
                    builder
                        .with_account_id(0)
                        .with_collection(COLLECTION_ID)
                        .create_document(document_id as u32);
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
                                        field_id,
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

                    builder.custom(fts_builder);
                    documents.lock().unwrap().push(builder.build());*/
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

        for batch in batches {
            let chunk_instance = Instant::now();
            chunk.push({
                let db = db.clone();
                tokio::spawn(async move { db.write(batch).await })
            });
            if chunk.len() == 1000 {
                for handle in chunk {
                    handle.await.unwrap().unwrap();
                }
                println!(
                    "Chunk insert took {} ms.",
                    chunk_instance.elapsed().as_millis()
                );
                chunk = Vec::new();
            }
        }

        if !chunk.is_empty() {
            for handle in chunk {
                handle.await.unwrap().unwrap();
            }
        }

        println!("Insert took {} ms.", now.elapsed().as_millis());
    }

    println!("Running filter tests...");
    test_filter(db.clone()).await;

    println!("Running sort tests...");
    test_sort(db).await;
}

pub async fn test_filter(db: Arc<impl Store>) {
    /*
        let mut fields = AHashMap::default();
        for (field_num, field) in FIELDS.iter().enumerate() {
            fields.insert(field.to_string(), field_num as u8);
        }

        let tests = [
            (
                vec![
                    Filter::has_english_text(fields["title"], "water"),
                    Filter::eq(fields["year"], 1979u32),
                ],
                vec!["p11293"],
            ),
            (
                vec![
                    Filter::has_english_text(fields["medium"], "gelatin"),
                    Filter::gt(fields["year"], 2000u32),
                    Filter::lt(fields["width"], 180u32),
                    Filter::gt(fields["width"], 0u32),
                ],
                vec!["p79426", "p79427", "p79428", "p79429", "p79430"],
            ),
            (
                vec![Filter::has_english_text(fields["title"], "'rustic bridge'")],
                vec!["d05503"],
            ),
            (
                vec![
                    Filter::has_english_text(fields["title"], "'rustic'"),
                    Filter::has_english_text(fields["title"], "study"),
                ],
                vec!["d00399", "d05352"],
            ),
            (
                vec![
                    Filter::has_text(fields["artist"], "mauro kunst", Language::None),
                    Filter::is_in_bitmap(fields["artistRole"], Keyword::Other("artist".to_string())),
                    Filter::Or,
                    Filter::eq(fields["year"], 1969u32),
                    Filter::eq(fields["year"], 1971u32),
                    Filter::End,
                ],
                vec!["p01764", "t05843"],
            ),
            (
                vec![
                    Filter::Not,
                    Filter::has_english_text(fields["medium"], "oil"),
                    Filter::End,
                    Filter::has_english_text(fields["creditLine"], "bequeath"),
                    Filter::Or,
                    Filter::And,
                    Filter::ge(fields["year"], 1900u32),
                    Filter::lt(fields["year"], 1910u32),
                    Filter::End,
                    Filter::And,
                    Filter::ge(fields["year"], 2000u32),
                    Filter::lt(fields["year"], 2010u32),
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
                    Filter::has_text(fields["artist"], "warhol", Language::None),
                    Filter::Not,
                    Filter::has_english_text(fields["title"], "'campbell'"),
                    Filter::End,
                    Filter::Not,
                    Filter::Or,
                    Filter::gt(fields["year"], 1980u32),
                    Filter::And,
                    Filter::gt(fields["width"], 500u32),
                    Filter::gt(fields["height"], 500u32),
                    Filter::End,
                    Filter::End,
                    Filter::End,
                    Filter::eq(fields["acquisitionYear"], 2008u32),
                    Filter::End,
                ],
                vec!["ar00039", "t12600"],
            ),
            (
                vec![
                    Filter::has_english_text(fields["title"], "study"),
                    Filter::has_english_text(fields["medium"], "paper"),
                    Filter::has_english_text(fields["creditLine"], "'purchased'"),
                    Filter::Not,
                    Filter::has_english_text(fields["title"], "'anatomical'"),
                    Filter::has_english_text(fields["title"], "'for'"),
                    Filter::End,
                    Filter::gt(fields["year"], 1900u32),
                    Filter::gt(fields["acquisitionYear"], 2000u32),
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
                    vec![Comparator::ascending(fields["accession_number"])],
                    Pagination::new(0, 0, None, 0),
                )
                .await
                .unwrap();

            assert_eq!(
                db.get_values::<String>(
                    sorted_docset
                        .ids
                        .into_iter()
                        .map(|document_id| ValueKey {
                            account_id: 0,
                            collection: COLLECTION_ID,
                            document_id: document_id as u32,
                            family: 0,
                            field: fields["accession_number"],
                        })
                        .collect()
                )
                .await
                .unwrap()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
                expected_results
            );
        }

    */
}

pub async fn test_sort(db: Arc<impl Store>) {
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

        assert_eq!(
            db.get_values::<String>(
                sorted_docset
                    .ids
                    .into_iter()
                    .map(|document_id| ValueKey {
                        account_id: 0,
                        collection: COLLECTION_ID,
                        document_id: document_id as u32,
                        class: ValueClass::Property(fields["accession_number"])
                    })
                    .collect()
            )
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
            expected_results
        );
    }
}
