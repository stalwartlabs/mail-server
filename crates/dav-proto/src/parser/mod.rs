/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

use quick_xml::events::BytesStart;
use tokenizer::Tokenizer;

use crate::schema::{Element, NamedElement, Namespace};

pub mod header;
pub mod property;
pub mod tokenizer;

#[derive(Debug, Clone)]
pub enum Error {
    Xml(Box<quick_xml::Error>),
    UnexpectedToken(Box<UnexpectedToken>),
}

#[derive(Debug, Clone)]
pub struct UnexpectedToken {
    pub expected: Option<Token<'static>>,
    pub found: Token<'static>,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Token<'x> {
    ElementStart {
        name: NamedElement,
        raw: RawElement<'x>,
    },
    ElementEnd,
    Bytes(Cow<'x, [u8]>),
    Text(Cow<'x, str>),
    UnknownElement(RawElement<'x>),
    Eof,
}

#[derive(Debug, Clone)]
pub struct RawElement<'x> {
    pub element: BytesStart<'x>,
    pub namespace: Option<Cow<'static, [u8]>>,
}

pub trait DavParser: Sized {
    fn parse(stream: &mut Tokenizer<'_>) -> Result<Self>;
}

pub trait XmlValueParser: Sized {
    fn parse_bytes(bytes: &[u8]) -> Option<Self>;
    fn parse_str(text: &str) -> Option<Self>;
}

impl NamedElement {
    pub fn dav(element: Element) -> NamedElement {
        NamedElement {
            ns: Namespace::Dav,
            element,
        }
    }

    pub fn caldav(element: Element) -> NamedElement {
        NamedElement {
            ns: Namespace::CalDav,
            element,
        }
    }

    pub fn carddav(element: Element) -> NamedElement {
        NamedElement {
            ns: Namespace::CardDav,
            element,
        }
    }

    pub fn calendarserver(element: Element) -> NamedElement {
        NamedElement {
            ns: Namespace::CalendarServer,
            element,
        }
    }
}

impl Token<'_> {
    pub fn into_owned(self) -> Token<'static> {
        match self {
            Token::ElementStart { name, raw } => Token::ElementStart {
                name,
                raw: raw.into_owned(),
            },
            Token::ElementEnd => Token::ElementEnd,
            Token::Bytes(bytes) => Token::Bytes(bytes.into_owned().into()),
            Token::Text(text) => Token::Text(text.into_owned().into()),
            Token::UnknownElement(raw) => Token::UnknownElement(raw.into_owned()),
            Token::Eof => Token::Eof,
        }
    }

    pub fn into_unexpected(self) -> Error {
        Error::UnexpectedToken(Box::new(UnexpectedToken {
            expected: None,
            found: self.into_owned(),
        }))
    }
}

impl<'x> RawElement<'x> {
    pub fn new(element: BytesStart<'x>) -> Self {
        RawElement {
            element,
            namespace: None,
        }
    }

    pub fn with_namespace(self, namespace: quick_xml::name::Namespace<'_>) -> Self {
        RawElement {
            element: self.element,
            namespace: Some(Cow::Owned(namespace.into_inner().to_vec())),
        }
    }

    pub fn with_namespace_static(self, namespace: &'static [u8]) -> Self {
        RawElement {
            element: self.element,
            namespace: Some(Cow::Borrowed(namespace)),
        }
    }

    pub fn into_owned(self) -> RawElement<'static> {
        RawElement {
            element: self.element.into_owned(),
            namespace: self.namespace,
        }
    }
}

#[cfg(test)]
impl PartialEq for Token<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::ElementStart {
                    name: l_name,
                    raw: l_raw,
                },
                Self::ElementStart {
                    name: r_name,
                    raw: r_raw,
                },
            ) => {
                l_name == r_name
                    && l_raw
                        .element
                        .attributes_raw()
                        .trim_ascii()
                        .eq_ignore_ascii_case(r_raw.element.attributes_raw().trim_ascii())
            }
            (Self::Bytes(l0), Self::Bytes(r0)) => l0 == r0,
            (Self::Text(l0), Self::Text(r0)) => l0 == r0,
            (Self::UnknownElement(l0), Self::UnknownElement(r0)) => l0
                .element
                .as_ref()
                .eq_ignore_ascii_case(r0.element.as_ref()),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl NamedElement {
    pub fn into_unexpected(self) -> Error {
        Error::UnexpectedToken(Box::new(UnexpectedToken {
            expected: None,
            found: Token::ElementStart {
                name: self,
                raw: RawElement::new(BytesStart::new("")),
            },
        }))
    }
}

impl Default for RawElement<'_> {
    fn default() -> Self {
        RawElement::new(BytesStart::new(""))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Xml(err) => write!(f, "XML error: {}", err),
            Error::UnexpectedToken(err) => {
                write!(f, "Unexpected token: {:?}", err.found)?;
                if let Some(expected) = &err.expected {
                    write!(f, ", expected: {expected:?}")?;
                }
                Ok(())
            }
        }
    }
}
