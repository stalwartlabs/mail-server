/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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

use std::time::Duration;

use imap_proto::ResponseType;
use mail_send::smtp::tls::build_tls_connector;
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use super::AssertResult;

pub async fn test() {
    println!("Running ManageSieve tests...");

    // Connect to ManageSieve
    let mut sieve = SieveConnection::connect().await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("IMPLEMENTATION");

    // Authenticate
    sieve
        .send("AUTHENTICATE \"PLAIN\" \"AGpkb2VAZXhhbXBsZS5jb20Ac2VjcmV0\"")
        .await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("MAXREDIRECTS");

    // CheckScript
    sieve.send("CHECKSCRIPT \"if true { keep; }\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve.send("CHECKSCRIPT \"keep :invalidtag;\"").await;
    sieve.assert_read(ResponseType::No).await;

    // PutScript
    sieve
        .send_literal("PUTSCRIPT \"simple script\" ", "if true { keep; }\r\n")
        .await;
    sieve.assert_read(ResponseType::Ok).await;

    // PutScript should overwrite existing scripts
    sieve.send("PUTSCRIPT \"holidays\" \"discard;\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve
        .send_literal(
            "PUTSCRIPT \"holidays\" ",
            "require \"vacation\"; vacation \"Gone fishin'\";\r\n",
        )
        .await;
    sieve.assert_read(ResponseType::Ok).await;

    // GetScript
    sieve.send("GETSCRIPT \"simple script\"").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("if true");
    sieve.send("GETSCRIPT \"holidays\"").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("Gone fishin'");
    sieve.send("GETSCRIPT \"dummy\"").await;
    sieve.assert_read(ResponseType::No).await;

    // ListScripts
    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("simple script")
        .assert_contains("holidays")
        .assert_count("ACTIVE", 0);

    // RenameScript
    sieve
        .send("RENAMESCRIPT \"simple script\" \"minimalist script\"")
        .await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve
        .send("RENAMESCRIPT \"holidays\" \"minimalist script\"")
        .await;
    sieve
        .assert_read(ResponseType::No)
        .await
        .assert_contains("ALREADYEXISTS");

    // SetActive
    sieve.send("SETACTIVE \"holidays\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("minimalist script")
        .assert_contains("holidays\" ACTIVE");

    // Deleting an active script should not be allowed
    sieve.send("DELETESCRIPT \"holidays\"").await;
    sieve
        .assert_read(ResponseType::No)
        .await
        .assert_contains("ACTIVE");

    // Deactivate all
    sieve.send("SETACTIVE \"\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("minimalist script")
        .assert_contains("holidays")
        .assert_count("ACTIVE", 0);

    // DeleteScript
    sieve.send("DELETESCRIPT \"holidays\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve.send("DELETESCRIPT \"minimalist script\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_count("minimalist script", 0)
        .assert_count("holidays", 0);
}

pub struct SieveConnection {
    reader: Lines<BufReader<ReadHalf<TlsStream<TcpStream>>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl SieveConnection {
    pub async fn connect() -> Self {
        let (reader, writer) = tokio::io::split(
            build_tls_connector(true)
                .connect(
                    ServerName::try_from("imap.example.org").unwrap().to_owned(),
                    TcpStream::connect("127.0.0.1:4190").await.unwrap(),
                )
                .await
                .unwrap(),
        );
        SieveConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    pub async fn assert_read(&mut self, rt: ResponseType) -> Vec<String> {
        let lines = self.read().await;
        let mut buf = Vec::with_capacity(10);
        rt.serialize(&mut buf);
        if lines
            .last()
            .unwrap()
            .starts_with(&String::from_utf8(buf).unwrap())
        {
            lines
        } else {
            panic!("Expected {:?} from server but got: {:?}", rt, lines);
        }
    }

    pub async fn read(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done =
                        line.starts_with("OK") || line.starts_with("NO") || line.starts_with("BYE");
                    //println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn send(&mut self, text: &str) {
        //println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }

    pub async fn send_literal(&mut self, text: &str, literal: &str) {
        self.send(&format!("{}{{{}+}}\r\n{}", text, literal.len(), literal))
            .await;
    }
}
