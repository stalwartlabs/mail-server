/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

pub mod config;
pub mod lookup;

use std::time::Duration;

use store::Store;

pub struct OpenIdDirectory {
    config: OpenIdConfig,
    pub(crate) data_store: Store,
}

struct OpenIdConfig {
    pub endpoint: String,
    pub endpoint_type: EndpointType,
    pub endpoint_timeout: Duration,
    pub email_field: String,
    pub username_field: Option<String>,
    pub full_name_field: Option<String>,
}

#[derive(Debug)]
pub enum EndpointType {
    Introspect(Authentication),
    UserInfo,
}

#[derive(Debug)]
pub enum Authentication {
    Header(String),
    Bearer,
    None,
}
