/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod auth;
pub mod autoconfig;
pub mod form;
pub mod management;
pub mod request;

use std::sync::Arc;

use common::Inner;

#[derive(Clone)]
pub struct HttpSessionManager {
    pub inner: Arc<Inner>,
}

impl HttpSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}
