/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, Token},
    schema::{request::PropertyUpdate, Element, NamedElement, Namespace},
};

impl DavParser for PropertyUpdate {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        stream.expect_named_element(NamedElement::dav(Element::Propertyupdate))?;
        let mut update = PropertyUpdate {
            set: Vec::with_capacity(4),
            remove: Vec::with_capacity(4),
            set_first: true,
        };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Set,
                        },
                    ..
                } => {
                    stream.expect_named_element(NamedElement::dav(Element::Prop))?;
                    stream.collect_property_values(&mut update.set)?;
                    stream.expect_element_end()?;
                    update.set_first = update.remove.is_empty();
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Remove,
                        },
                    ..
                } => {
                    stream.expect_named_element(NamedElement::dav(Element::Prop))?;
                    update.remove = stream.collect_properties(update.remove)?;
                    stream.expect_element_end()?;
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                Token::UnknownElement(_) => {
                    // Ignore unknown elements
                    stream.seek_element_end()?;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(update)
    }
}
