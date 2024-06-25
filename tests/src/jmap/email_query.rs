/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::hash_map::Entry, time::Instant};

use crate::{
    jmap::{assert_is_empty, mailbox::destroy_all_mailboxes, wait_for_index},
    store::{deflate_test_resource, query::FIELDS},
};
use jmap_client::{
    client::Client,
    core::query::{Comparator, Filter},
    email,
};
use jmap_proto::types::{collection::Collection, id::Id, property::Property};
use mail_parser::{DateTime, HeaderName};

use store::{
    ahash::AHashMap,
    write::{now, BatchBuilder, ValueClass},
};

use super::JMAPTest;

const MAX_THREADS: usize = 100;
const MAX_MESSAGES: usize = 1000;
const MAX_MESSAGES_PER_THREAD: usize = 100;

pub async fn test(params: &mut JMAPTest, insert: bool) {
    println!("Running Email Query tests...");
    let server = params.server.clone();
    let client = &mut params.client;
    client.set_default_account_id(Id::new(1));
    if insert {
        // Add some "virtual" mailbox ids so create doesn't fail
        let mut batch = BatchBuilder::new();
        let account_id = Id::from_bytes(client.default_account_id().as_bytes())
            .unwrap()
            .document_id();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox);
        for mailbox_id in 1545..3010 {
            batch.create_document_with_id(mailbox_id);
        }
        server.core.storage.data.write(batch.build()).await.unwrap();

        // Create test messages
        println!("Inserting JMAP Mail query test messages...");
        create(client).await;

        // Remove mailboxes
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox);
        for mailbox_id in 1545..3010 {
            batch
                .delete_document(mailbox_id)
                .clear(ValueClass::Property(Property::EmailIds.into()));
        }
        server.core.storage.data.write(batch.build()).await.unwrap();

        assert_eq!(
            params
                .server
                .get_document_ids(account_id, Collection::Thread)
                .await
                .unwrap()
                .unwrap()
                .len() as usize,
            MAX_THREADS
        );

        // Wait for indexing to complete
        wait_for_index(&server).await;
    }

    println!("Running JMAP Mail query tests...");
    query(client).await;

    println!("Running JMAP Mail query options tests...");
    query_options(client).await;

    println!("Deleting all messages...");
    let mut request = client.build();
    let result_ref = request.query_email().result_reference();
    request.set_email().destroy_ref(result_ref);
    let response = request.send().await.unwrap();
    response
        .unwrap_method_responses()
        .pop()
        .unwrap()
        .unwrap_set_email()
        .unwrap();

    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}

pub async fn query(client: &mut Client) {
    for (filter, sort, expected_results) in [
        (
            Filter::and(vec![
                (email::query::Filter::after(1850)),
                (email::query::Filter::from("george")),
            ]),
            vec![
                email::query::Comparator::subject(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N01389", "T10115", "N00618", "N03500", "T01587", "T00397", "N01561", "N05250",
                "N03973", "N04973", "N04057", "N01940", "N01539", "N01612", "N04484", "N01954",
                "N05998", "T02053", "AR00171", "AR00172", "AR00176",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::in_mailbox(Id::new(1768u64).to_string())),
                (email::query::Filter::cc("canvas")),
            ]),
            vec![
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec!["T01882", "N04689", "T00925", "N00121"],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::subject("study")),
                (email::query::Filter::in_mailbox_other_than(vec![
                    Id::new(1991).to_string(),
                    Id::new(1870).to_string(),
                    Id::new(2011).to_string(),
                    Id::new(1951).to_string(),
                    Id::new(1902).to_string(),
                    Id::new(1808).to_string(),
                    Id::new(1963).to_string(),
                ])),
            ]),
            vec![
                email::query::Comparator::subject(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "T10330", "N01744", "N01743", "N04885", "N02688", "N02122", "A00059", "A00058",
                "N02123", "T00651", "T09439", "N05001", "T05848", "T05508",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::has_keyword("N0")).into(),
                Filter::not(vec![(email::query::Filter::from("collins"))]),
                (email::query::Filter::body("bequeathed")).into(),
            ]),
            vec![
                email::query::Comparator::subject(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N02640", "A01020", "N01250", "T03430", "N01800", "N00620", "N05250", "N04630",
                "A01040",
            ],
        ),
        (
            email::query::Filter::not_keyword("artist").into(),
            vec![
                email::query::Comparator::subject(),
                email::query::Comparator::sent_at(),
            ],
            vec!["T08626", "T09334", "T09455", "N01737", "T10965"],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::after(1970)),
                (email::query::Filter::before(1972)),
                (email::query::Filter::text("colour")),
            ]),
            vec![
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec!["T01745", "P01436", "P01437"],
        ),
        (
            Filter::and(vec![(email::query::Filter::text("'cats and dogs'"))]),
            vec![email::query::Comparator::from()],
            vec!["P77623"],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::header(
                    HeaderName::Comments.to_string(),
                    Some("attributed"),
                )),
                (email::query::Filter::from("john")),
                (email::query::Filter::cc("oil")),
            ]),
            vec![email::query::Comparator::from()],
            vec!["T10965"],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::all_in_thread_have_keyword("N")),
                (email::query::Filter::before(1800)),
            ]),
            vec![
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N01496", "N05916", "N01046", "N00675", "N01320", "N01321", "N00273", "N01453",
                "N02984",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::none_in_thread_have_keyword("N")),
                (email::query::Filter::after(1995)),
            ]),
            vec![
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "AR00163", "AR00164", "AR00472", "P11481", "AR00066", "AR00178", "P77895",
                "P77896", "P77897",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::some_in_thread_have_keyword("Bronze")),
                (email::query::Filter::before(1878)),
            ]),
            vec![
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N04326", "N01610", "N02920", "N01587", "T00167", "T00168", "N01554", "N01535",
                "N01536", "N01622", "N01754", "N01594",
            ],
        ),
        // Sorting tests
        (
            email::query::Filter::before(1800).into(),
            vec![
                email::query::Comparator::all_in_thread_have_keyword("N"),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N01496", "N05916", "N01046", "N00675", "N01320", "N01321", "N00273", "N01453",
                "N02984", "T09417", "T01882", "T08820", "N04689", "T08891", "T00986", "N00316",
                "N03544", "N04296", "N04297", "T08234", "N00112", "T00211", "N01497", "N02639",
                "N02640", "T00925", "T11683", "T08269", "D00001", "D00002", "D00046", "N00121",
                "N00126", "T08626",
            ],
        ),
        (
            email::query::Filter::before(1800).into(),
            vec![
                email::query::Comparator::all_in_thread_have_keyword("N").descending(),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "T09417", "T01882", "T08820", "N04689", "T08891", "T00986", "N00316", "N03544",
                "N04296", "N04297", "T08234", "N00112", "T00211", "N01497", "N02639", "N02640",
                "T00925", "T11683", "T08269", "D00001", "D00002", "D00046", "N00121", "N00126",
                "T08626", "N01496", "N05916", "N01046", "N00675", "N01320", "N01321", "N00273",
                "N01453", "N02984",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::after(1875)),
                (email::query::Filter::before(1878)),
            ]),
            vec![
                email::query::Comparator::some_in_thread_have_keyword("Bronze"),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N04326", "N01610", "N02920", "N01587", "T00167", "T00168", "N01554", "N01535",
                "N01536", "N01622", "N01754", "N01594", "N01559", "N02123", "N01940", "N03594",
                "N01494", "N04271",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::after(1875)),
                (email::query::Filter::before(1878)),
            ]),
            vec![
                email::query::Comparator::some_in_thread_have_keyword("Bronze").descending(),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "N01559", "N02123", "N01940", "N03594", "N01494", "N04271", "N04326", "N01610",
                "N02920", "N01587", "T00167", "T00168", "N01554", "N01535", "N01536", "N01622",
                "N01754", "N01594",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::after(1786)),
                (email::query::Filter::before(1840)),
                (email::query::Filter::has_keyword("T")),
            ]),
            vec![
                email::query::Comparator::has_keyword("attributed to"),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "T09455", "T09334", "T10965", "T08626", "T09417", "T08951", "T01851", "T01852",
                "T08761", "T08123", "T08756", "T10561", "T10562", "T10563", "T00986", "T03424",
                "T03427", "T08234", "T08133", "T06866", "T08897", "T00996", "T00997", "T01095",
                "T03393", "T09456", "T00188", "T02362", "T09065", "T09547", "T10330", "T09187",
                "T03433", "T08635", "T02366", "T03436", "T09150", "T01861", "T09759", "T11683",
                "T02368", "T02369", "T08269", "T01018", "T10066", "T01710", "T01711", "T05764",
            ],
        ),
        (
            Filter::and(vec![
                (email::query::Filter::after(1786)),
                (email::query::Filter::before(1840)),
                (email::query::Filter::has_keyword("T")),
            ]),
            vec![
                email::query::Comparator::has_keyword("attributed to").descending(),
                email::query::Comparator::from(),
                email::query::Comparator::sent_at(),
            ],
            vec![
                "T09417", "T08951", "T01851", "T01852", "T08761", "T08123", "T08756", "T10561",
                "T10562", "T10563", "T00986", "T03424", "T03427", "T08234", "T08133", "T06866",
                "T08897", "T00996", "T00997", "T01095", "T03393", "T09456", "T00188", "T02362",
                "T09065", "T09547", "T10330", "T09187", "T03433", "T08635", "T02366", "T03436",
                "T09150", "T01861", "T09759", "T11683", "T02368", "T02369", "T08269", "T01018",
                "T10066", "T01710", "T01711", "T05764", "T09455", "T09334", "T10965", "T08626",
            ],
        ),
    ] {
        let mut request = client.build();
        let query_request = request
            .query_email()
            .filter(filter.clone())
            .sort(sort.clone())
            .calculate_total(true);
        query_request.arguments().collapse_threads(false);
        let query_result_ref = query_request.result_reference();
        request
            .get_email()
            .ids_ref(query_result_ref)
            .properties([email::Property::MessageId]);
        let results = request
            .send()
            .await
            .unwrap_or_else(|_| panic!("invalid response for {filter:?}"))
            .unwrap_method_responses()
            .pop()
            .unwrap_or_else(|| panic!("invalid response for {filter:?}"))
            .unwrap_get_email()
            .unwrap_or_else(|_| panic!("invalid response for {filter:?}"))
            .take_list()
            .into_iter()
            .map(|e| e.message_id().unwrap().first().unwrap().to_string())
            .collect::<Vec<_>>();

        let mut missing = Vec::new();
        let mut extra = Vec::new();
        for &expected in &expected_results {
            if !results.iter().any(|r| r.as_str() == expected) {
                missing.push(expected);
            }
        }
        for result in &results {
            if !expected_results.contains(&result.as_str()) {
                extra.push(result.as_str());
            }
        }

        assert_eq!(
            results, expected_results,
            "failed test!\nfilter: {filter:?}\nsort: {sort:?}\nmissing: {missing:?}\nextra: {extra:?}"
        );
    }
}

pub async fn query_options(client: &mut Client) {
    for (query, expected_results, expected_results_collapsed) in [
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: None,
                anchor_offset: 0,
                limit: 10,
            },
            vec![
                "N01496", "N01320", "N01321", "N05916", "N00273", "N01453", "N02984", "T08820",
                "N00112", "T00211",
            ],
            vec![
                "N01496", "N01320", "N05916", "N01453", "T08820", "N01046", "N00675", "T08891",
                "T01882", "N04296",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 10,
                anchor: None,
                anchor_offset: 0,
                limit: 10,
            },
            vec![
                "N01046", "N00675", "T08891", "N00126", "T01882", "N04689", "T00925", "N00121",
                "N04296", "N04297",
            ],
            vec![
                "T08234", "T09417", "N01110", "T08123", "N01039", "T09456", "T08951", "N01273",
                "N00373", "T09547",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: -10,
                anchor: None,
                anchor_offset: 0,
                limit: 0,
            },
            vec![
                "T07236", "P11481", "AR00066", "P77895", "P77896", "P77897", "AR00163", "AR00164",
                "AR00472", "AR00178",
            ],
            vec![
                "P07639", "P07522", "AR00089", "P02949", "T05820", "P11441", "T06971", "P11481",
                "AR00163", "AR00164",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: -20,
                anchor: None,
                anchor_offset: 0,
                limit: 10,
            },
            vec![
                "P20079", "AR00024", "AR00182", "P20048", "P20044", "P20045", "P20046", "T06971",
                "AR00177", "P77935",
            ],
            vec![
                "T00300", "P06033", "T02310", "T02135", "P04006", "P03166", "P01358", "P07133",
                "P03138", "T03562",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: -100000,
                anchor: None,
                anchor_offset: 0,
                limit: 1,
            },
            vec!["N01496"],
            vec!["N01496"],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: -1,
                anchor: None,
                anchor_offset: 0,
                limit: 100000,
            },
            vec!["AR00178"],
            vec!["AR00164"],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "N01205").await,
                anchor_offset: 0,
                limit: 10,
            },
            vec![
                "N01205", "N01976", "T01139", "N01525", "T00176", "N01405", "N02396", "N04885",
                "N01526", "N02134",
            ],
            vec![
                "N01205", "N01526", "T01455", "N01969", "N05250", "N01781", "N00759", "A00057",
                "N03527", "N01558",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "N01205").await,
                anchor_offset: 10,
                limit: 10,
            },
            vec![
                "N01933", "N03618", "T03904", "N02398", "N02399", "N02688", "T01455", "N03051",
                "N01500", "N03411",
            ],
            vec![
                "N01559", "N04326", "N06017", "N01553", "N01617", "N01528", "N01539", "T09439",
                "N01593", "N03988",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "N01205").await,
                anchor_offset: -10,
                limit: 10,
            },
            vec![
                "N05779", "N04652", "N01534", "A00845", "N03409", "N03410", "N02061", "N02426",
                "N00662", "N01205",
            ],
            vec![
                "N00443", "N02237", "T03025", "N01722", "N01356", "N01800", "T05475", "T01587",
                "N05779", "N01205",
            ],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "N01496").await,
                anchor_offset: -10,
                limit: 10,
            },
            vec!["N01496"],
            vec!["N01496"],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "AR00164").await,
                anchor_offset: 10,
                limit: 10,
            },
            vec![],
            vec![],
        ),
        (
            EmailQuery {
                filter: None,
                sort: vec![
                    email::query::Comparator::subject(),
                    email::query::Comparator::from(),
                    email::query::Comparator::sent_at(),
                ],
                position: 0,
                anchor: get_anchor(client, "AR00164").await,
                anchor_offset: 0,
                limit: 0,
            },
            vec!["AR00164", "AR00472", "AR00178"],
            vec!["AR00164"],
        ),
    ] {
        for (test_num, expected_results) in [expected_results, expected_results_collapsed]
            .into_iter()
            .enumerate()
        {
            let mut request = client.build();
            let query_request = request
                .query_email()
                .sort(query.sort.clone())
                .position(query.position)
                .calculate_total(true);
            if query.limit > 0 {
                query_request.limit(query.limit);
            }
            if let Some(filter) = query.filter.as_ref() {
                query_request.filter(filter.clone());
            }
            if let Some(anchor) = query.anchor.as_ref() {
                query_request.anchor(anchor);
                query_request.anchor_offset(query.anchor_offset);
            }
            query_request.arguments().collapse_threads(test_num == 1);

            if !expected_results.is_empty() {
                let query_result_ref = query_request.result_reference();
                request
                    .get_email()
                    .ids_ref(query_result_ref)
                    .properties([email::Property::MessageId]);

                assert_eq!(
                    request
                        .send()
                        .await
                        .unwrap()
                        .unwrap_method_responses()
                        .pop()
                        .unwrap()
                        .unwrap_get_email()
                        .unwrap()
                        .take_list()
                        .into_iter()
                        .map(|e| e.message_id().unwrap().first().unwrap().to_string())
                        .collect::<Vec<_>>(),
                    expected_results,
                    "{:#?} ({})",
                    query,
                    test_num == 1
                );
            } else {
                assert_eq!(
                    request.send_query_email().await.unwrap().ids(),
                    Vec::<&str>::new()
                );
            }
        }
    }
}

pub async fn create(client: &mut Client) {
    let sent_at = now();
    let now = Instant::now();
    let mut fields = AHashMap::default();
    for (field_num, field) in FIELDS.iter().enumerate() {
        fields.insert(field.to_string(), field_num);
    }

    let mut total_messages = 0;
    let mut total_threads = 0;
    let mut thread_count = AHashMap::default();
    let mut artist_count = AHashMap::default();

    'outer: for (idx, record) in csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(&deflate_test_resource("artwork_data.csv.gz")[..])
        .records()
        .enumerate()
    {
        let record = record.unwrap();
        let mut values_str = AHashMap::default();
        let mut values_int = AHashMap::default();

        for field_name in [
            "year",
            "acquisitionYear",
            "accession_number",
            "artist",
            "artistRole",
            "medium",
            "title",
            "creditLine",
            "inscription",
        ] {
            let field = record.get(fields[field_name]).unwrap();
            if field.is_empty()
                || (field_name == "title" && (field.contains('[') || field.contains(']')))
            {
                continue 'outer;
            } else if field_name == "year" || field_name == "acquisitionYear" {
                let field = field.parse::<i32>().unwrap_or(0);
                if field < 1000 {
                    continue 'outer;
                }
                values_int.insert(field_name.to_string(), field);
            } else {
                values_str.insert(field_name.to_string(), field.to_string());
            }
        }

        let val = artist_count
            .entry(values_str["artist"].clone())
            .or_insert(0);
        if *val == 3 {
            continue;
        }
        *val += 1;

        match thread_count.entry(values_int["year"]) {
            Entry::Occupied(mut e) => {
                let messages_per_thread = e.get_mut();
                if *messages_per_thread == MAX_MESSAGES_PER_THREAD {
                    continue;
                }
                *messages_per_thread += 1;
            }
            Entry::Vacant(e) => {
                if total_threads == MAX_THREADS {
                    continue;
                }
                total_threads += 1;
                e.insert(1);
            }
        }

        total_messages += 1;

        client
            .email_import(
                format!(
                    concat!(
                        "Date: {}\nFrom: \"{}\" <artist@domain.com>\nCc: \"{}\" <cc@domain.com>\nMessage-ID: <{}>\n",
                        "References: <{}>\nComments: {}\nSubject: [{}]",
                        " Year {}\n\n{}\n{}\n"
                    ),
                    DateTime::from_timestamp(sent_at as i64 + idx as i64).to_rfc822(),
                    values_str["artist"],
                    values_str["medium"],
                    values_str["accession_number"],
                    values_int["year"],
                    values_str["artistRole"],
                    values_str["title"],
                    values_int["year"],
                    values_str["creditLine"],
                    values_str["inscription"]
                )
                .into_bytes(),
                [
                    Id::new(values_int["year"] as u64).to_string(),
                    Id::new((values_int["acquisitionYear"] + 1000) as u64).to_string(),
                ],
                [
                    values_str["medium"].to_string(),
                    values_str["artistRole"].to_string(),
                    values_str["accession_number"][0..1].to_string(),
                    format!(
                        "N{}",
                        &values_str["accession_number"][values_str["accession_number"].len() - 1..]
                    ),
                ]
                .into(),
                Some(values_int["year"] as i64),
            )
            .await
            .unwrap();

        if total_messages == MAX_MESSAGES {
            break;
        }
    }
    println!(
        "Imported {} messages in {} ms (single thread).",
        total_messages,
        now.elapsed().as_millis()
    );
}

async fn get_anchor(client: &mut Client, anchor: &str) -> Option<String> {
    client
        .email_query(
            email::query::Filter::header("Message-Id", anchor.into()).into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap()
        .take_ids()
        .pop()
        .unwrap()
        .into()
}

#[derive(Debug, Clone)]
pub struct EmailQuery {
    pub filter: Option<Filter<email::query::Filter>>,
    pub sort: Vec<Comparator<email::query::Comparator>>,
    pub position: i32,
    pub anchor: Option<String>,
    pub anchor_offset: i32,
    pub limit: usize,
}
