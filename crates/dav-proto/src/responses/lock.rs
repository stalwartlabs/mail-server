/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::{
    schema::{
        property::{ActiveLock, LockDiscovery, LockEntry, LockScope, LockType, SupportedLock},
        request::{DeadProperty, LockInfo},
        response::{Href, List},
    },
    Depth, Timeout,
};

impl Display for SupportedLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:supportedlock>{}</D:supportedlock>", self.0)
    }
}

impl Display for LockDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:lockdiscovery>{}</D:lockdiscovery>", self.0)
    }
}

impl Display for ActiveLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<D:activelock>{}{}{}",
            self.lock_scope, self.lock_type, self.depth
        )?;

        if let Some(owner) = &self.owner {
            write!(f, "<D:owner>{}</D:owner>", owner)?;
        }

        write!(f, "{}", self.timeout)?;

        if let Some(lock_token) = &self.lock_token {
            write!(f, "<D:locktoken>{}</D:locktoken>", lock_token)?;
        }

        write!(
            f,
            "<D:lockroot>{}</D:lockroot></D:activelock>",
            self.lock_root
        )
    }
}

impl Display for Depth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Depth::Zero => write!(f, "<D:depth>0</D:depth>"),
            Depth::One => write!(f, "<D:depth>1</D:depth>"),
            Depth::Infinity => write!(f, "<D:depth>infinity</D:depth>"),
            Depth::None => write!(f, "<D:depth/>"),
        }
    }
}

impl Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Timeout::Infinite => write!(f, "<D:timeout>Infinite</D:timeout>"),
            Timeout::Second(s) => write!(f, "<D:timeout>Second-{}</D:timeout>", s),
            Timeout::None => Ok(()),
        }
    }
}

impl Display for LockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:lockinfo>{}{}", self.lock_scope, self.lock_type)?;

        if let Some(owner) = &self.owner {
            write!(f, "<D:owner>{}</D:owner>", owner)?;
        }

        write!(f, "</D:lockinfo>",)
    }
}

impl Display for LockEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<D:lockentry>{}{}</D:lockentry>",
            self.lock_scope, self.lock_type
        )
    }
}

impl Display for LockScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockScope::Exclusive => write!(f, "<D:lockscope><D:exclusive/></D:lockscope>"),
            LockScope::Shared => write!(f, "<D:lockscope><D:shared/></D:lockscope>"),
        }
    }
}

impl Display for LockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockType::Write => write!(f, "<D:locktype><D:write/></D:locktype>"),
            LockType::Other => write!(f, "<D:locktype><D:other/></D:locktype>"),
        }
    }
}

impl ActiveLock {
    pub fn new(href: impl Into<String>, lock_scope: LockScope) -> Self {
        Self {
            lock_scope,
            lock_type: LockType::Write,
            depth: Depth::Infinity,
            owner: None,
            timeout: Timeout::Infinite,
            lock_token: None,
            lock_root: Href(href.into()),
        }
    }

    pub fn with_depth(mut self, depth: Depth) -> Self {
        self.depth = depth;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Timeout::Second(timeout);
        self
    }

    pub fn with_owner_opt(mut self, owner: Option<DeadProperty>) -> Self {
        self.owner = owner;
        self
    }

    pub fn with_owner(mut self, owner: DeadProperty) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn with_lock_token(mut self, token: impl Into<String>) -> Self {
        self.lock_token = Some(Href(token.into()));
        self
    }
}

impl Default for SupportedLock {
    fn default() -> Self {
        Self(List(vec![
            LockEntry {
                lock_scope: LockScope::Exclusive,
                lock_type: LockType::Write,
            },
            LockEntry {
                lock_scope: LockScope::Shared,
                lock_type: LockType::Write,
            },
        ]))
    }
}
