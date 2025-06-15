/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, Token},
    schema::{
        property::{LockScope, LockType},
        request::{DeadProperty, LockInfo},
        Element, NamedElement, Namespace,
    },
};

impl DavParser for LockInfo {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut lockinfo = LockInfo {
            lock_scope: LockScope::Exclusive,
            lock_type: LockType::Write,
            owner: None,
        };

        if stream.expect_named_element_or_eof(NamedElement::dav(Element::Lockinfo))? {
            loop {
                match stream.token()? {
                    Token::ElementStart {
                        name:
                            NamedElement {
                                ns: Namespace::Dav,
                                element: Element::Lockscope,
                            },
                        ..
                    } => {
                        lockinfo.lock_scope = LockScope::parse(stream)?;
                    }
                    Token::ElementStart {
                        name:
                            NamedElement {
                                ns: Namespace::Dav,
                                element: Element::Locktype,
                            },
                        ..
                    } => {
                        lockinfo.lock_type = LockType::parse(stream)?;
                    }
                    Token::ElementStart {
                        name:
                            NamedElement {
                                ns: Namespace::Dav,
                                element: Element::Owner,
                            },
                        ..
                    } => {
                        lockinfo.owner = Some(DeadProperty::parse(stream)?);
                    }
                    Token::ElementEnd | Token::Eof => {
                        break;
                    }
                    other => {
                        return Err(other.into_unexpected());
                    }
                }
            }
        }

        Ok(lockinfo)
    }
}

impl DavParser for LockScope {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        match stream.unwrap_named_element()? {
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Exclusive,
            } => {
                stream.expect_element_end()?;
                stream.expect_element_end()?;
                Ok(LockScope::Exclusive)
            }
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Shared,
            } => {
                stream.expect_element_end()?;
                stream.expect_element_end()?;
                Ok(LockScope::Shared)
            }
            other => Err(other.into_unexpected()),
        }
    }
}

impl DavParser for LockType {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        match stream.unwrap_named_element()? {
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Write,
            } => {
                stream.expect_element_end()?;
                stream.expect_element_end()?;
                Ok(LockType::Write)
            }
            other => Err(other.into_unexpected()),
        }
    }
}
