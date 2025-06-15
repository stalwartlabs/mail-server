/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, Token},
    schema::{request::PropFind, Element, NamedElement, Namespace},
};

impl DavParser for PropFind {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        if stream.expect_named_element_or_eof(NamedElement::dav(Element::Propfind))? {
            match stream.unwrap_named_element()? {
                NamedElement {
                    ns: Namespace::Dav,
                    element: Element::Propname,
                } => Ok(PropFind::PropName),
                NamedElement {
                    ns: Namespace::Dav,
                    element: Element::Allprop,
                } => {
                    stream.expect_element_end()?;
                    if matches!(
                        stream.token()?,
                        Token::ElementStart {
                            name: NamedElement {
                                ns: Namespace::Dav,
                                element: Element::Include
                            },
                            ..
                        }
                    ) {
                        stream.collect_properties(Vec::new()).map(PropFind::AllProp)
                    } else {
                        Ok(PropFind::AllProp(vec![]))
                    }
                }
                NamedElement {
                    ns: Namespace::Dav,
                    element: Element::Prop,
                } => stream.collect_properties(Vec::new()).map(PropFind::Prop),
                element => Err(element.into_unexpected()),
            }
        } else {
            Ok(PropFind::AllProp(vec![]))
        }
    }
}
