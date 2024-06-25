/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashMap, fmt::Display, io::Read};

use jmap_client::{
    client::Client,
    principal::query::{self},
};
use serde::{Deserialize, Serialize};

pub mod account;
pub mod cli;
pub mod database;
pub mod domain;
pub mod export;
pub mod group;
pub mod import;
pub mod list;
pub mod queue;
pub mod report;

const RETRY_ATTEMPTS: usize = 5;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,

    #[serde(rename = "type")]
    pub typ: Option<Type>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<u32>,

    #[serde(rename = "usedQuota")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_quota: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "memberOf")]
    pub member_of: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "members")]
    pub members: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "individual")]
    #[default]
    Individual = 0,
    #[serde(rename = "group")]
    Group = 1,
    #[serde(rename = "resource")]
    Resource = 2,
    #[serde(rename = "location")]
    Location = 3,
    #[serde(rename = "superuser")]
    Superuser = 4,
    #[serde(rename = "list")]
    List = 5,
    #[serde(rename = "other")]
    Other = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalField {
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "type")]
    Type,
    #[serde(rename = "quota")]
    Quota,
    #[serde(rename = "description")]
    Description,
    #[serde(rename = "secrets")]
    Secrets,
    #[serde(rename = "emails")]
    Emails,
    #[serde(rename = "memberOf")]
    MemberOf,
    #[serde(rename = "members")]
    Members,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct List<T> {
    pub items: Vec<T>,
    pub total: u64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Response<T> {
    pub items: T,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrincipalUpdate {
    action: PrincipalAction,
    field: PrincipalField,
    value: PrincipalValue,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalAction {
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "addItem")]
    AddItem,
    #[serde(rename = "removeItem")]
    RemoveItem,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PrincipalValue {
    String(String),
    StringList(Vec<String>),
    Integer(u64),
}

impl PrincipalUpdate {
    pub fn set(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::Set,
            field,
            value,
        }
    }

    pub fn add_item(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::AddItem,
            field,
            value,
        }
    }

    pub fn remove_item(field: PrincipalField, value: PrincipalValue) -> PrincipalUpdate {
        PrincipalUpdate {
            action: PrincipalAction::RemoveItem,
            field,
            value,
        }
    }
}

pub trait UnwrapResult<T> {
    fn unwrap_result(self, action: &str) -> T;
}

impl<T> UnwrapResult<T> for Option<T> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                eprintln!("Failed to {}", message);
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: Display> UnwrapResult<T> for Result<T, E> {
    fn unwrap_result(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Failed to {}: {}", message, err);
                std::process::exit(1);
            }
        }
    }
}

pub fn read_file(path: &str) -> Vec<u8> {
    if path == "-" {
        let mut stdin = std::io::stdin().lock();
        let mut raw_message = Vec::with_capacity(1024);
        let mut buf = [0; 1024];
        loop {
            let n = stdin.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            raw_message.extend_from_slice(&buf[..n]);
        }
        raw_message
    } else {
        std::fs::read(path).unwrap_or_else(|_| {
            eprintln!("Failed to read file: {}", path);
            std::process::exit(1);
        })
    }
}

pub async fn name_to_id(client: &Client, name: &str) -> String {
    let filter = if name.contains('@') {
        query::Filter::email(name)
    } else {
        query::Filter::name(name)
    };
    let mut response = client
        .principal_query(filter.into(), None::<Vec<_>>)
        .await
        .unwrap_result("query principals");
    match response.ids().len() {
        1 => response.take_ids().pop().unwrap(),
        0 => {
            eprintln!("Error: No principal found with name '{}'.", name);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Error: Multiple principals found with name '{}'.", name);
            std::process::exit(1);
        }
    }
}

pub fn is_localhost(url: &str) -> bool {
    url.split_once("://")
        .map(|(_, url)| url.split_once('/').map_or(url, |(host, _)| host))
        .map_or(false, |host| {
            let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        })
}

pub trait OAuthResponse {
    fn property(&self, name: &str) -> &str;
}

impl OAuthResponse for HashMap<String, serde_json::Value> {
    fn property(&self, name: &str) -> &str {
        self.get(name)
            .unwrap_result(&format!("find '{}' in OAuth response", name))
            .as_str()
            .unwrap_result(&format!("invalid '{}' value", name))
    }
}
