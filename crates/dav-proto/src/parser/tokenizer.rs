/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use quick_xml::{
    events::{attributes::AttrError, Event},
    name::ResolveResult,
    NsReader,
};

use crate::schema::{Attribute, AttributeValue, Element, NamedElement, Namespace};

use super::{Error, RawElement, Token, UnexpectedToken, XmlValueParser};

pub struct Tokenizer<'x> {
    xml: NsReader<&'x [u8]>,
    last_is_end: bool,
}

impl<'x> Tokenizer<'x> {
    pub fn new(input: &'x [u8]) -> Self {
        let mut xml = NsReader::from_reader(input);
        xml.config_mut().trim_text(true);
        Self {
            xml,
            last_is_end: false,
        }
    }

    pub fn token(&mut self) -> super::Result<Token> {
        loop {
            if self.last_is_end {
                self.last_is_end = false;
                return Ok(Token::ElementEnd);
            }

            let (resolve_result, event) = self.xml.read_resolved_event()?;
            let tag = match event {
                Event::Start(tag) => tag,
                Event::Empty(tag) => {
                    self.last_is_end = true;
                    tag
                }
                Event::End(_) => {
                    return Ok(Token::ElementEnd);
                }
                Event::Text(text) if text.iter().any(|ch| !ch.is_ascii_whitespace()) => {
                    return text
                        .unescape()
                        .map(Token::Text)
                        .map_err(|err| Error::Xml(Box::new(err)));
                }
                Event::CData(bytes) => return Ok(Token::Bytes(bytes.into_inner())),
                Event::Eof => return Ok(Token::Eof),
                _ => {
                    continue;
                }
            };

            // Parse element
            let name = tag.name();
            match resolve_result {
                ResolveResult::Bound(raw_ns) if !raw_ns.as_ref().is_empty() => {
                    if let (Some(ns), Some(element)) = (
                        Namespace::try_parse(raw_ns.as_ref()),
                        Element::try_parse(name.local_name().as_ref()).copied(),
                    ) {
                        return Ok(Token::ElementStart {
                            name: NamedElement { ns, element },
                            raw: RawElement::new(tag)
                                .with_namespace_static(ns.namespace().as_bytes()),
                        });
                    } else {
                        return Ok(Token::UnknownElement(
                            RawElement::new(tag).with_namespace(raw_ns),
                        ));
                    }
                }
                ResolveResult::Unknown(p) => {
                    return Err(Error::Xml(Box::new(quick_xml::Error::Namespace(
                        quick_xml::name::NamespaceError::UnknownPrefix(p),
                    ))))
                }
                _ => {
                    return Ok(Token::UnknownElement(RawElement::new(tag)));
                }
            }
        }
    }

    pub fn unwrap_named_element(&mut self) -> super::Result<NamedElement> {
        match self.token()? {
            Token::ElementStart { name, .. } => Ok(name),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: None,
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_named_element(&mut self, expected: NamedElement) -> super::Result<()> {
        match self.token()? {
            Token::ElementStart { name, .. } if name == expected => Ok(()),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementStart {
                    name: expected,
                    raw: RawElement::default(),
                }
                .into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_named_element_or_eof(&mut self, expected: NamedElement) -> super::Result<bool> {
        match self.token()? {
            Token::ElementStart { name, .. } if name == expected => Ok(true),
            Token::Eof => Ok(false),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementStart {
                    name: expected,
                    raw: RawElement::default(),
                }
                .into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_element_end(&mut self) -> super::Result<()> {
        match self.token()? {
            Token::ElementEnd => Ok(()),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementEnd.into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn seek_element_end(&mut self) -> super::Result<()> {
        let mut depth = 1;
        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
                _ => {}
            }
        }
    }

    pub fn collect_string_value(&mut self) -> super::Result<Option<String>> {
        let mut depth = 1;
        let mut value = None;

        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Text(text) => {
                    value = Some(text.into_owned());
                }
                Token::Bytes(bytes) => {
                    value = Some(String::from_utf8_lossy(&bytes).into_owned());
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
            }
        }

        Ok(value)
    }

    pub fn parse_value<T: XmlValueParser>(&mut self) -> super::Result<Option<Result<T, String>>> {
        let mut depth = 1;
        let mut result: Option<Result<T, String>> = None;

        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Text(text) => {
                    if let Some(value) = T::parse_str(&text) {
                        result = Some(Ok(value));
                    } else {
                        result = Some(Err(text.into_owned()));
                    }
                }
                Token::Bytes(bytes) => {
                    if let Some(value) = T::parse_bytes(&bytes) {
                        result = Some(Ok(value));
                    } else {
                        result = Some(Err(String::from_utf8_lossy(&bytes).into_owned()));
                    }
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
            }
        }

        Ok(result)
    }

    pub fn collect_elements<T>(&mut self) -> super::Result<Vec<T>>
    where
        T: TryFrom<NamedElement>,
    {
        let mut elements = Vec::with_capacity(2);
        let mut depth = 1;

        loop {
            match self.token()? {
                Token::ElementStart { name, .. } => {
                    if depth == 1 {
                        if let Ok(element) = T::try_from(name) {
                            elements.push(element);
                        }
                    }

                    depth += 1;
                }
                Token::UnknownElement(_) => {
                    depth += 1;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Eof => break,
                _ => {}
            }
        }
        Ok(elements)
    }
}

impl RawElement<'_> {
    pub fn attributes<T: AttributeValue>(
        &self,
    ) -> impl Iterator<Item = super::Result<Attribute<T>>> + '_ {
        self.element.attributes().filter_map(|attr| match attr {
            Ok(attr) => match attr.unescape_value() {
                Ok(value) => Attribute::from_param(attr.key.as_ref(), value).map(Ok),
                Err(err) => Some(Err(err.into())),
            },
            Err(err) => Some(Err(err.into())),
        })
    }
}

impl From<quick_xml::Error> for Error {
    fn from(err: quick_xml::Error) -> Self {
        Error::Xml(Box::new(err))
    }
}

impl From<AttrError> for Error {
    fn from(err: AttrError) -> Self {
        Error::Xml(Box::new(err.into()))
    }
}

#[cfg(test)]
mod tests {

    use std::borrow::Cow;

    use crate::schema::{Collation, MatchType};

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TestToken<'x> {
        ElementStart(NamedElement),
        ElementEnd,
        Attribute(Attribute<String>),
        Bytes(Cow<'x, [u8]>),
        Text(Cow<'x, str>),
    }

    #[test]
    fn test_tokenizer() {
        for (input, expected) in [
            (
                r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:"
                    xmlns:C="urn:ietf:params:xml:ns:caldav">
    <D:prop>
      <D:getetag/>
      <C:calendar-data/>
    </D:prop>
    <C:filter>
      <C:comp-filter name="VCALENDAR"/>
    </C:filter>
   </C:calendar-query>"#,
                vec![
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::CalendarQuery,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Getetag,
                    }),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::CalendarData,
                    }),
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Filter,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::CompFilter,
                    }),
                    TestToken::Attribute(Attribute::Name("VCALENDAR".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                ],
            ),
            (
                r#" <?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-query xmlns:D="DAV:"
                     xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
       <C:address-data>
         <C:prop name="VERSION"/>
         <C:prop name="UID"/>
         <C:prop name="NICKNAME"/>
         <C:prop name="EMAIL"/>
         <C:prop name="FN"/>
       </C:address-data>
     </D:prop>
     <C:filter>
       <C:prop-filter name="NICKNAME">
         <C:text-match collation="i;unicode-casemap"
                       match-type="equals"
         >me</C:text-match>
       </C:prop-filter>
     </C:filter>
   </C:addressbook-query>"#,
                vec![
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::AddressbookQuery,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Getetag,
                    }),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::AddressData,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Prop,
                    }),
                    TestToken::Attribute(Attribute::Name("VERSION".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Prop,
                    }),
                    TestToken::Attribute(Attribute::Name("UID".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Prop,
                    }),
                    TestToken::Attribute(Attribute::Name("NICKNAME".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Prop,
                    }),
                    TestToken::Attribute(Attribute::Name("EMAIL".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Prop,
                    }),
                    TestToken::Attribute(Attribute::Name("FN".to_string())),
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Filter,
                    }),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::PropFilter,
                    }),
                    TestToken::Attribute(Attribute::Name("NICKNAME".to_string())),
                    TestToken::ElementStart(NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::TextMatch,
                    }),
                    TestToken::Attribute(Attribute::Collation(Collation::UnicodeCasemap)),
                    TestToken::Attribute(Attribute::MatchType(MatchType::Equals)),
                    TestToken::Text("me".into()),
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                    TestToken::ElementEnd,
                ],
            ),
        ] {
            let mut tokenizer = Tokenizer::new(input.as_bytes());
            let mut result = vec![];

            loop {
                match tokenizer.token() {
                    Ok(token) => match token {
                        Token::ElementStart { name, raw } => {
                            result.push(TestToken::ElementStart(name));
                            for attr in raw.attributes::<String>() {
                                result.push(TestToken::Attribute(attr.unwrap()));
                            }
                        }
                        Token::ElementEnd => {
                            result.push(TestToken::ElementEnd);
                        }
                        Token::Bytes(cow) => {
                            result.push(TestToken::Bytes(cow.into_owned().into()));
                        }
                        Token::Text(cow) => {
                            result.push(TestToken::Text(cow.into_owned().into()));
                        }
                        Token::UnknownElement(_) => {
                            //result.push(TestToken::UnknownElement(unknown_element));
                        }
                        Token::Eof => break,
                    },
                    Err(err) => {
                        panic!("Error: {:?}", err);
                    }
                }
            }

            assert_eq!(result, expected);
        }
    }
}
