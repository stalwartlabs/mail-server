/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, Token},
    schema::{request::MkCol, Element, NamedElement, Namespace},
};

impl DavParser for MkCol {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut mkcol = MkCol {
            is_mkcalendar: false,
            props: Vec::new(),
        };
        match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Mkcol,
                    },
                ..
            } => {}
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Mkcalendar,
                    },
                ..
            } => {
                mkcol.is_mkcalendar = true;
            }
            Token::Eof => {
                return Ok(mkcol);
            }
            other => return Err(other.into_unexpected()),
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
                    stream.collect_property_values(&mut mkcol.props)?;
                    stream.expect_element_end()?;
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(mkcol)
    }
}
