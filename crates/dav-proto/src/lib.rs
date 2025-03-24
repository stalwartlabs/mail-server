/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod parser;
pub mod requests;
pub mod responses;
pub mod schema;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RequestHeaders<'x> {
    pub uri: &'x str,
    pub depth: Depth,
    pub timeout: Timeout,
    pub content_type: Option<&'x str>,
    pub destination: Option<&'x str>,
    pub lock_token: Option<&'x str>,
    pub overwrite_fail: bool,
    pub no_timezones: bool,
    pub ret: Return,
    pub depth_no_root: bool,
    pub if_: Vec<If<'x>>,
}

pub struct ResourceState<T: AsRef<str>> {
    pub resource: Option<T>,
    pub etag: T,
    pub state_token: T,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Return {
    Minimal,
    Representation,
    #[default]
    Default,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct If<'x> {
    pub resource: Option<&'x str>,
    pub list: Vec<Condition<'x>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Condition<'x> {
    StateToken { is_not: bool, token: &'x str },
    ETag { is_not: bool, tag: &'x str },
    Exists { is_not: bool },
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum Timeout {
    Infinite,
    Second(u64),
    #[default]
    None,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Depth {
    Zero,
    One,
    Infinity,
    #[default]
    None,
}

/*

   Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, COPY, MOVE
   Allow: MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT, ACL
   DAV: 1, 2, 3, access-control, extended-mkcol
calendar-no-timezone


TODO:


Implemented:

RFC4918 - HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)
RFC5689 - Extended MKCOL for Web Distributed Authoring and Versioning (WebDAV)
RFC6578 - Collection Synchronization for Web Distributed Authoring and Versioning (WebDAV)
RFC3744 - Web Distributed Authoring and Versioning (WebDAV) Access Control Protocol
RFC4331 - Quota and Size Properties for Distributed Authoring and Versioning (DAV) Collections
RFC5397 - WebDAV Current Principal Extension
RFC8144 - Use of the Prefer Header Field in Web Distributed Authoring and Versioning (WebDAV)
RFC4791 - Calendaring Extensions to WebDAV (CalDAV)
RFC7809 - Calendaring Extensions to WebDAV (CalDAV) Time Zones by Reference
RFC6638 - Scheduling Extensions to CalDAV
RFC6352 - CardDAV vCard Extensions to Web Distributed Authoring and Versioning (WebDAV)
RFC6764 - Locating Services for Calendaring Extensions to WebDAV (CalDAV) and vCard Extensions to WebDAV (CardDAV)

Out of scope:

RFC5842 - Binding Extensions to Web Distributed Authoring and Versioning (WebDAV)
RFC4316 - Datatypes for Web Distributed Authoring and Versioning (WebDAV) Properties
RFC4709 - Mounting Web Distributed Authoring and Versioning (WebDAV) Servers
RFC3648 - Web Distributed Authoring and Versioning (WebDAV) Ordered Collections Protocol
RFC4437 - Web Distributed Authoring and Versioning (WebDAV) Redirect Reference Resources
RFC8607 - Calendaring Extensions to WebDAV (CalDAV) Managed Attachments
RFC5995 - Using POST to Add Members to Web Distributed Authoring and Versioning (WebDAV) Collections
RFC3253 - Versioning Extensions to WebDAV (Web Distributed Authoring and Versioning)
RFC5323 - Web Distributed Authoring and Versioning (WebDAV) SEARCH


*/
