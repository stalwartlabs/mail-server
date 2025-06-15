/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use hyper::StatusCode;

use crate::schema::{
    response::{
        Condition, Href, List, Location, MultiStatus, PropStat, Response, ResponseDescription,
        ResponseType, Status, SyncToken,
    },
    Namespace, Namespaces,
};

impl Display for MultiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><D:multistatus {}>{}",
            self.namespaces, self.response
        )?;
        if let Some(response_description) = &self.response_description {
            write!(f, "{response_description}")?;
        }

        if let Some(sync_token) = &self.sync_token {
            write!(f, "{sync_token}")?;
        }

        write!(f, "</D:multistatus>")
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:response>")?;
        self.href.fmt(f)?;
        self.typ.fmt(f)?;
        if let Some(error) = &self.error {
            error.fmt(f)?;
        }
        if let Some(response_description) = &self.response_description {
            response_description.fmt(f)?;
        }
        if let Some(location) = &self.location {
            location.fmt(f)?;
        }
        write!(f, "</D:response>")
    }
}

impl Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseType::PropStat(list) => list.fmt(f),
            ResponseType::Status { href, status } => {
                href.fmt(f)?;
                status.fmt(f)
            }
        }
    }
}

impl MultiStatus {
    pub fn new(response: Vec<Response>) -> Self {
        MultiStatus {
            namespaces: Namespaces::default(),
            response: List(response),
            response_description: None,
            sync_token: None,
        }
    }

    pub fn with_response(mut self, response: Response) -> Self {
        self.response.0.push(response);
        self
    }

    pub fn add_response(&mut self, response: Response) {
        self.response.0.push(response);
    }

    pub fn with_response_description(mut self, response_description: impl Into<String>) -> Self {
        self.response_description = Some(ResponseDescription(response_description.into()));
        self
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespaces.set(namespace);
        self
    }

    pub fn set_namespace(&mut self, namespace: Namespace) {
        self.namespaces.set(namespace);
    }

    pub fn with_sync_token(mut self, sync_token: impl Into<String>) -> Self {
        self.sync_token = Some(SyncToken(sync_token.into()));
        self
    }

    pub fn set_sync_token(&mut self, sync_token: impl Into<String>) {
        self.sync_token = Some(SyncToken(sync_token.into()));
    }
}

impl Response {
    pub fn new_propstat(href: impl Into<Href>, propstat: Vec<PropStat>) -> Self {
        Response {
            href: href.into(),
            typ: ResponseType::PropStat(List(propstat)),
            error: None,
            response_description: None,
            location: None,
        }
    }

    pub fn new_status<T, H>(href: T, status: StatusCode) -> Self
    where
        T: IntoIterator<Item = H>,
        H: Into<String>,
    {
        let mut href = href.into_iter().map(|h| Href(h.into()));
        Response {
            href: href.next().unwrap(),
            typ: ResponseType::Status {
                href: List(href.collect()),
                status: Status(status),
            },
            error: None,
            response_description: None,
            location: None,
        }
    }

    pub fn with_error(mut self, error: impl Into<Condition>) -> Self {
        self.error = Some(error.into());
        self
    }

    pub fn with_response_description(mut self, response_description: impl Into<String>) -> Self {
        self.response_description = Some(ResponseDescription(response_description.into()));
        self
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(Location(Href(location.into())));
        self
    }
}
