/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use hyper::StatusCode;

use crate::schema::{
    request::DavPropertyValue,
    response::{Condition, List, Prop, PropStat, ResponseDescription, Status},
};

impl Display for PropStat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:propstat>")?;
        self.prop.fmt(f)?;
        self.status.fmt(f)?;
        if let Some(error) = &self.error {
            error.fmt(f)?;
        }
        if let Some(response_description) = &self.response_description {
            response_description.fmt(f)?;
        }
        write!(f, "</D:propstat>")
    }
}

impl Display for Prop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:prop>{}</D:prop>", self.0)
    }
}

impl PropStat {
    #[cfg(test)]
    pub(crate) fn new(prop: impl Into<DavPropertyValue>) -> Self {
        PropStat {
            prop: Prop(List(vec![prop.into()])),
            status: Status(StatusCode::OK),
            error: None,
            response_description: None,
        }
    }

    pub fn new_list(props: Vec<DavPropertyValue>) -> Self {
        PropStat {
            prop: Prop(List(props)),
            status: Status(StatusCode::OK),
            error: None,
            response_description: None,
        }
    }

    pub fn with_prop(mut self, prop: impl Into<DavPropertyValue>) -> Self {
        self.prop.0 .0.push(prop.into());
        self
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Status(status);
        self
    }

    pub fn with_error(mut self, error: impl Into<Condition>) -> Self {
        self.error = Some(error.into());
        self
    }

    pub fn with_response_description(mut self, response_description: impl Into<String>) -> Self {
        self.response_description = Some(ResponseDescription(response_description.into()));
        self
    }
}
