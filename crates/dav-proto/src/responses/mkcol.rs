/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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
        write!(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        if !self.mkcalendar {
            write!(
                f,
                "<D:mkcol-response {}>{}</D:mkcol-response>",
                self.namespaces, self.propstat
            )
        } else {
            write!(
                f,
                "<A:mkcalendar-response {}>{}</A:mkcalendar-response>",
                self.namespaces, self.propstat
            )
        }
    }
}

impl MkColResponse {
    pub fn new(propstat: Vec<PropStat>) -> Self {
        Self {
            namespaces: Namespaces::default(),
            propstat: List(propstat),
            mkcalendar: false,
        }
    }

    pub fn with_mkcalendar(mut self, mkcalendar: bool) -> Self {
        self.mkcalendar = mkcalendar;
        if mkcalendar {
            self.namespaces.set(Namespace::CalDav);
        }
        self
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespaces.set(namespace);
        self
    }
}
