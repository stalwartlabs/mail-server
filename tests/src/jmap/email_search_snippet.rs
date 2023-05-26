/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::{fs, path::PathBuf, sync::Arc};

use jmap::{mailbox::INBOX_ID, JMAP};
use jmap_client::{client::Client, core::query, email::query::Filter};
use jmap_proto::types::id::Id;
use store::ahash::AHashMap;

use crate::jmap::mailbox::destroy_all_mailboxes;

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running SearchSnippet tests...");

    let mailbox_id = Id::from(INBOX_ID).to_string();
    client.set_default_account_id(Id::from(1u64));

    let mut email_ids = AHashMap::default();

    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("jmap_mail_snippet");

    // Import test messages
    for email_name in [
        "html",
        "subpart",
        "mixed",
        "text_plain",
        "text_plain_chinese",
    ] {
        let mut file_name = test_dir.clone();
        file_name.push(format!("{}.eml", email_name));
        let email_id = client
            .email_import(
                fs::read(&file_name).unwrap(),
                [&mailbox_id],
                None::<Vec<&str>>,
                None,
            )
            .await
            .unwrap()
            .take_id();
        email_ids.insert(email_name, email_id);
    }

    // Run tests
    for (filter, email_name, snippet_subject, snippet_preview) in [
        (
            query::Filter::or(vec![
                query::Filter::or(vec![Filter::subject("friend"), Filter::subject("help")]),
                query::Filter::or(vec![Filter::body("secret"), Filter::body("call")]),
            ]),
            "text_plain",
            Some("<mark>Help</mark> a <mark>friend</mark> from Abidjan Côte d'Ivoire"),
            Some(concat!(
                "d'Ivoire. He <mark>secretly</mark> <mark>called</mark> me on his bedside ",
                "and told me that he has a sum of $7.5M (Seven Million five Hundred Thousand",
                " Dollars) left in a suspense account in a local bank here in Abidjan Côte ",
                "d'Ivoire, that he used my name a"
            )),
        ),
        (
            Filter::text("côte").into(),
            "text_plain",
            Some("Help a friend from Abidjan <mark>Côte</mark> d'Ivoire"),
            Some(concat!(
                "in Abidjan <mark>Côte</mark> d'Ivoire. He secretly called me on ",
                "his bedside and told me that he has a sum of $7.5M (Seven ",
                "Million five Hundred Thousand Dollars) left in a suspense ",
                "account in a local bank here in Abidjan <mark>Côte</mark> d'Ivoire, that "
            )),
        ),
        (
            Filter::text("\"your country\"").into(),
            "text_plain",
            None,
            Some(concat!(
                "over to <mark>your</mark> <mark>country</mark> to further my education and ",
                "to secure a residential permit for me in <mark>your</mark> <mark>country",
                "</mark>. Moreover, I am willing to offer you 30 percent of the total sum as ",
                "compensation for your effort inp",
            )),
        ),
        (
            Filter::text("overseas").into(),
            "text_plain",
            None,
            Some("nominated account <mark>overseas</mark>. "),
        ),
        (
            Filter::text("孫子兵法").into(),
            "text_plain_chinese",
            Some("<mark>孫</mark><mark>子</mark><mark>兵法</mark>"),
            Some(concat!(
                "&lt;&quot;<mark>孫</mark><mark>子</mark><mark>兵法</mark>：&quot;&gt; ",
                "<mark>孫</mark><mark>子</mark>曰：兵者，國之大事，死生之地，存亡之道，",
                "不可不察也。 <mark>孫</mark><mark>子</mark>曰：凡用兵之法，馳車千駟"
            )),
        ),
        (
            Filter::text("cia").into(),
            "subpart",
            None,
            Some("shouldn't the <mark>CIA</mark> have something like that? Bill"),
        ),
        (
            Filter::text("frösche").into(),
            "html",
            Some("Die Hasen und die <mark>Frösche</mark>"),
            Some(concat!(
            "und die <mark>Frösche</mark> Die Hasen klagten einst über ihre mißliche Lage; ",
            "&quot;wir leben&quot;, sprach ein Redner, &quot;in steter Furcht vor Menschen und ",
            "Tieren, eine Beute der Hunde, der Adler, ja fast aller Raubtiere! ",
            "Unsere stete Angst ist är")),
        ),
        (
            Filter::text("es:galería vasto biblioteca").into(),
            "mixed",
            Some("<mark>Biblioteca</mark> de Babel"),
            Some(concat!(
                "llaman la *<mark>Biblioteca</mark>*) se compone de un número indefinido, y tal ",
                "vez infinito, de <mark>galerías</mark> hexagonales, con <mark>vastos</mark> ",
                "pozos de ventilación en el medio, cercados por barandas bajísimas. Desde ",
                "cualquier hexágono se "
            )),
        ),
    ] {
        let mut request = client.build();
        let result_ref = request
            .query_email()
            .filter(filter.clone())
            .result_reference();
        request
            .get_search_snippet()
            .filter(filter)
            .email_ids_ref(result_ref);
        let response = request
            .send()
            .await
            .unwrap()
            .unwrap_method_responses()
            .pop()
            .unwrap()
            .unwrap_get_search_snippet()
            .unwrap();
        let snippet = response
            .snippet(email_ids.get(email_name).unwrap())
            .unwrap_or_else(|| panic!("No snippet for {}", email_name));
        assert_eq!(snippet_subject, snippet.subject());
        assert_eq!(snippet_preview, snippet.preview());
        assert!(
            snippet.preview().map_or(0, |p| p.len()) <= 255,
            "len: {}",
            snippet.preview().map_or(0, |p| p.len())
        );
    }

    // Destroy test data
    destroy_all_mailboxes(client).await;
    server.store.assert_is_empty().await;
}
