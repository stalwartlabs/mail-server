/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::schema::{
    response::{List, MkColResponse, PropStat},
    Namespace, Namespaces,
};

impl Display for MkColResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<D:mkcol-response {}>{}</D:mkcol-response>",
            self.namespaces, self.propstat
        )
    }
}

impl MkColResponse {
    pub fn new(propstat: Vec<PropStat>) -> Self {
        Self {
            namespaces: Namespaces::default(),
            propstat: List(propstat),
        }
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespaces.set(namespace);
        self
    }
}
