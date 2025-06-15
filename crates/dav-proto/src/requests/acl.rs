/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, Token},
    schema::{
        property::{DavValue, Privilege},
        request::{
            Acl, AclPrincipalPropSet, DavPropertyValue, PrincipalMatch, PrincipalMatchProperties,
            PrincipalPropertySearch, PropertySearch,
        },
        response::{Ace, GrantDeny, Href, List, Principal},
        Element, NamedElement, Namespace,
    },
};

impl DavParser for Acl {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        stream.expect_named_element(NamedElement::dav(Element::Acl))?;

        let mut acl = Acl { aces: vec![] };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Ace,
                        },
                    ..
                } => {
                    acl.aces.push(Ace::parse(stream)?);
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(acl)
    }
}

impl DavParser for Ace {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut ace = Ace {
            principal: Principal::All,
            invert: false,
            grant_deny: GrantDeny::Grant(List(vec![])),
            protected: false,
            inherited: None,
        };
        let mut depth = 1;

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Principal,
                        },
                    ..
                } => {
                    ace.principal = Principal::parse(stream)?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Invert,
                        },
                    ..
                } if depth == 1 => {
                    ace.invert = true;
                    depth += 1;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Protected,
                        },
                    ..
                } if depth == 1 => {
                    ace.protected = true;
                    stream.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Inherited,
                        },
                    ..
                } if depth == 1 => {
                    stream.expect_named_element(NamedElement::dav(Element::Href))?;
                    ace.inherited = stream.collect_string_value()?.map(Href);
                    stream.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Grant,
                        },
                    ..
                } if depth == 1 => {
                    ace.grant_deny = GrantDeny::Grant(List(stream.collect_privileges()?));
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Deny,
                        },
                    ..
                } if depth == 1 => {
                    ace.grant_deny = GrantDeny::Deny(List(stream.collect_privileges()?));
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(ace)
    }
}

impl DavParser for Principal {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let result = match stream.unwrap_named_element()? {
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Href,
            } => Principal::Href(Href(stream.collect_string_value()?.unwrap_or_default())),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::All,
            } => {
                stream.expect_element_end()?;
                Principal::All
            }
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Authenticated,
            } => {
                stream.expect_element_end()?;
                Principal::Authenticated
            }
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Unauthenticated,
            } => {
                stream.expect_element_end()?;
                Principal::Unauthenticated
            }
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Property,
            } => {
                let property = stream.collect_properties(Vec::new())?;
                Principal::Property(List(
                    property
                        .into_iter()
                        .map(|prop| DavPropertyValue::new(prop, DavValue::Null))
                        .collect(),
                ))
            }
            NamedElement {
                ns: Namespace::Dav,
                element: Element::Self_,
            } => {
                stream.expect_element_end()?;
                Principal::Self_
            }
            other => return Err(other.into_unexpected()),
        };
        stream.expect_element_end()?;
        Ok(result)
    }
}

impl Tokenizer<'_> {
    pub fn collect_privileges(&mut self) -> crate::parser::Result<Vec<Privilege>> {
        let mut privileges = Vec::new();
        let mut depth = 1;

        loop {
            match self.token()? {
                Token::ElementStart { name, .. } => {
                    if let Some(privilege) = Privilege::from_element(name) {
                        privileges.push(privilege);
                        self.expect_element_end()?;
                    } else {
                        depth += 1;
                    }
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::UnknownElement(_) => {
                    self.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(privileges)
    }
}

impl Privilege {
    pub fn from_element(element: NamedElement) -> Option<Self> {
        match (element.ns, element.element) {
            (Namespace::Dav, Element::Read) => Some(Privilege::Read),
            (Namespace::Dav, Element::Write) => Some(Privilege::Write),
            (Namespace::Dav, Element::WriteProperties) => Some(Privilege::WriteProperties),
            (Namespace::Dav, Element::WriteContent) => Some(Privilege::WriteContent),
            (Namespace::Dav, Element::Unlock) => Some(Privilege::Unlock),
            (Namespace::Dav, Element::ReadAcl) => Some(Privilege::ReadAcl),
            (Namespace::Dav, Element::ReadCurrentUserPrivilegeSet) => {
                Some(Privilege::ReadCurrentUserPrivilegeSet)
            }
            (Namespace::Dav, Element::WriteAcl) => Some(Privilege::WriteAcl),
            (Namespace::Dav, Element::Bind) => Some(Privilege::Bind),
            (Namespace::Dav, Element::Unbind) => Some(Privilege::Unbind),
            (Namespace::Dav, Element::All) => Some(Privilege::All),
            (Namespace::CalDav, Element::ReadFreeBusy) => Some(Privilege::ReadFreeBusy),
            _ => None,
        }
    }
}

impl DavParser for AclPrincipalPropSet {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut acps = AclPrincipalPropSet { properties: vec![] };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Prop,
                        },
                    ..
                } => {
                    acps.properties = stream.collect_properties(acps.properties)?;
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(acps)
    }
}

impl DavParser for PrincipalMatch {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut pm = PrincipalMatch {
            principal_properties: PrincipalMatchProperties::Self_,
            properties: vec![],
        };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::PrincipalProperty,
                        },
                    ..
                } => {
                    pm.principal_properties = PrincipalMatchProperties::Properties(
                        stream.collect_properties(Vec::new())?,
                    );
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Self_,
                        },
                    ..
                } => {
                    pm.principal_properties = PrincipalMatchProperties::Self_;
                    stream.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Prop,
                        },
                    ..
                } => {
                    pm.properties = stream.collect_properties(pm.properties)?;
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(pm)
    }
}

impl DavParser for PrincipalPropertySearch {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut pps = PrincipalPropertySearch {
            property_search: vec![],
            properties: vec![],
            apply_to_principal_collection_set: false,
        };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::PropertySearch,
                        },
                    ..
                } => {
                    if let Some(prop) = PropertySearch::parse(stream)? {
                        pps.property_search.push(prop);
                    }
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Prop,
                        },
                    ..
                } => {
                    pps.properties = stream.collect_properties(pps.properties)?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::ApplyToPrincipalCollectionSet,
                        },
                    ..
                } => {
                    stream.expect_element_end()?;
                    pps.apply_to_principal_collection_set = true;
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(pps)
    }
}

impl PropertySearch {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Option<Self>> {
        let mut property = None;
        let mut match_ = None;

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Prop,
                        },
                    ..
                } => {
                    property = stream.collect_properties(Vec::new())?.into_iter().next();
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Match,
                        },
                    ..
                } => {
                    match_ = stream.collect_string_value()?;
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                other => {
                    return Err(other.into_unexpected());
                }
            }
        }

        Ok(property.map(|property| PropertySearch {
            property,
            match_: match_.unwrap_or_default(),
        }))
    }
}
