/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::VCardParameterName,
};

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, RawElement, Token, XmlValueParser},
    schema::{
        property::{DavProperty, TimeRange},
        request::{
            AclPrincipalPropSet, AddressbookQuery, CalendarQuery, DeadElementTag, ExpandProperty,
            ExpandPropertyItem, Filter, FilterOp, FreeBusyQuery, MultiGet, PrincipalMatch,
            PrincipalPropertySearch, PropFind, Report, SyncCollection, TextMatch, Timezone,
            VCardPropertyWithGroup,
        },
        Attribute, Collation, Element, MatchType, NamedElement, Namespace,
    },
    Depth,
};

impl DavParser for Report {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        match stream.unwrap_named_element()? {
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::CalendarQuery,
            } => CalendarQuery::parse(stream).map(Report::CalendarQuery),
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::FreeBusyQuery,
            } => FreeBusyQuery::parse(stream).map(Report::FreeBusyQuery),
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::CalendarMultiget,
            } => MultiGet::parse(stream).map(Report::CalendarMultiGet),
            NamedElement {
                ns: Namespace::CardDav,
                element: Element::AddressbookQuery,
            } => AddressbookQuery::parse(stream).map(Report::AddressbookQuery),
            NamedElement {
                ns: Namespace::CardDav,
                element: Element::AddressbookMultiget,
            } => MultiGet::parse(stream).map(Report::AddressbookMultiGet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::SyncCollection,
            } => SyncCollection::parse(stream).map(Report::SyncCollection),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::AclPrincipalPropSet,
            } => AclPrincipalPropSet::parse(stream).map(Report::AclPrincipalPropSet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalMatch,
            } => PrincipalMatch::parse(stream).map(Report::PrincipalMatch),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalPropertySearch,
            } => PrincipalPropertySearch::parse(stream).map(Report::PrincipalPropertySearch),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalSearchPropertySet,
            } => stream
                .expect_element_end()
                .map(|_| Report::PrincipalSearchPropertySet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::ExpandProperty,
            } => ExpandProperty::parse(stream).map(Report::ExpandProperty),
            other => Err(other.into_unexpected()),
        }
    }
}

impl DavParser for CalendarQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut cq = CalendarQuery {
            properties: PropFind::AllProp(vec![]),
            filters: vec![],
            timezone: Timezone::None,
        };
        let mut depth = 1;
        let mut components = Vec::with_capacity(3);
        let mut property = None;
        let mut parameter = None;

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } if depth == 1 => {
                        cq.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } if depth == 1 => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } if depth == 1 => {
                        cq.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Filter,
                    } if depth == 1 => {
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Timezone,
                    } if depth == 1 => {
                        cq.timezone =
                            Timezone::Name(stream.collect_string_value()?.unwrap_or_default());
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TimezoneId,
                    } if depth == 1 => {
                        cq.timezone =
                            Timezone::Id(stream.collect_string_value()?.unwrap_or_default());
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::CompFilter,
                    } if depth >= 2 => {
                        for attribute in raw.attributes::<ICalendarComponentType>() {
                            if let Attribute::Name(name) = attribute? {
                                components.push((name, depth));
                            }
                        }
                        depth += 1;
                    }

                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::PropFilter,
                    } if depth >= 3 => {
                        for attribute in raw.attributes::<ICalendarProperty>() {
                            if let Attribute::Name(name) = attribute? {
                                property = Some(name);
                            }
                        }
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::ParamFilter,
                    } if depth >= 4 => {
                        for attribute in raw.attributes::<ICalendarParameterName>() {
                            if let Attribute::Name(name) = attribute? {
                                parameter = Some(name);
                            }
                        }
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::IsNotDefined,
                    } => {
                        stream.expect_element_end()?;
                        if let Some(filter) = Filter::from_parts(
                            components.iter().map(|(c, _)| c.clone()).collect(),
                            property.clone(),
                            parameter.clone(),
                            FilterOp::Undefined,
                        ) {
                            cq.filters.push(filter);
                        }
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TextMatch,
                    } => {
                        let mut tm = TextMatch::parse(raw)?;
                        tm.value = stream.collect_string_value()?.unwrap_or_default();
                        if let Some(filter) = Filter::from_parts(
                            components.iter().map(|(c, _)| c.clone()).collect(),
                            property.clone(),
                            parameter.clone(),
                            FilterOp::TextMatch(tm),
                        ) {
                            cq.filters.push(filter);
                        }
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TimeRange,
                    } => {
                        let range = TimeRange::from_raw(&raw)?;
                        stream.expect_element_end()?;
                        if let Some(filter) = range.and_then(|range| {
                            Filter::from_parts(
                                components.iter().map(|(c, _)| c.clone()).collect(),
                                property.clone(),
                                parameter.clone(),
                                FilterOp::TimeRange(range),
                            )
                        }) {
                            cq.filters.push(filter);
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    if matches!(components.last(), Some((_, d)) if *d == depth) {
                        if components.len() > 1
                            && cq
                                .filters
                                .last()
                                .and_then(|c| c.components())
                                .is_none_or(|c| c.len() < components.len())
                        {
                            cq.filters.push(Filter::Component {
                                comp: components.iter().map(|(c, _)| c.clone()).collect(),
                                op: FilterOp::Exists,
                            });
                        }
                        components.pop();
                    }
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(cq)
    }
}

impl DavParser for AddressbookQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut aq = AddressbookQuery {
            properties: PropFind::AllProp(vec![]),
            filters: vec![],
            limit: None,
        };
        let mut depth = 1;
        let mut property = None;
        let mut parameter = None;

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } if depth == 1 => {
                        aq.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } if depth == 1 => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } if depth == 1 => {
                        aq.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Filter,
                    } if depth == 1 => {
                        if let Some(filter) = Filter::parse(raw)? {
                            aq.filters.push(filter);
                        }
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Limit,
                    } if depth == 1 => {
                        stream.expect_named_element(NamedElement::carddav(Element::Nresults))?;
                        if let Some(Ok(limit)) = stream.parse_value::<u32>()? {
                            aq.limit = limit.into();
                        }
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::PropFilter,
                    } if depth == 2 => {
                        let mut filter = None;
                        for attribute in raw.attributes::<VCardPropertyWithGroup>() {
                            match attribute? {
                                Attribute::Name(name) => {
                                    property = Some(name);
                                }
                                Attribute::TestAllOf(all_of) => {
                                    filter =
                                        (if all_of { Filter::AllOf } else { Filter::AnyOf }).into();
                                }
                                _ => {}
                            }
                        }
                        if let Some(filter) = filter {
                            aq.filters.push(filter);
                        }
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::ParamFilter,
                    } if depth == 3 => {
                        for attribute in raw.attributes::<VCardParameterName>() {
                            if let Attribute::Name(name) = attribute? {
                                parameter = Some(name);
                            }
                        }
                        depth += 1;
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::IsNotDefined,
                    } => {
                        stream.expect_element_end()?;
                        if let Some(filter) = Filter::from_parts(
                            (),
                            property.clone(),
                            parameter.clone(),
                            FilterOp::Undefined,
                        ) {
                            aq.filters.push(filter);
                        }
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::TextMatch,
                    } => {
                        let mut tm = TextMatch::parse(raw)?;
                        tm.value = stream.collect_string_value()?.unwrap_or_default();
                        if let Some(filter) = Filter::from_parts(
                            (),
                            property.clone(),
                            parameter.clone(),
                            FilterOp::TextMatch(tm),
                        ) {
                            aq.filters.push(filter);
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(aq)
    }
}

impl DavParser for FreeBusyQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TimeRange,
                    },
                raw,
            } => TimeRange::from_raw(&raw).map(|range| FreeBusyQuery { range }),
            other => Err(other.into_unexpected()),
        }
    }
}

impl DavParser for MultiGet {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut mg = MultiGet {
            properties: PropFind::AllProp(vec![]),
            hrefs: vec![],
        };

        loop {
            match stream.token()? {
                Token::ElementStart { name, .. } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } => {
                        mg.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        mg.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Href,
                    } => {
                        if let Some(href) = stream.collect_string_value()? {
                            mg.hrefs.push(href);
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(mg)
    }
}

impl DavParser for SyncCollection {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut sc = SyncCollection {
            properties: PropFind::AllProp(vec![]),
            limit: None,
            sync_token: None,
            depth: Depth::None,
        };

        loop {
            match stream.token()? {
                Token::ElementStart { name, .. } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        sc.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Limit,
                    } => {
                        stream.expect_named_element(NamedElement::dav(Element::Nresults))?;
                        if let Some(Ok(limit)) = stream.parse_value::<u32>()? {
                            sc.limit = limit.into();
                        }
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::SyncToken,
                    } => {
                        sc.sync_token = stream.collect_string_value()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::SyncLevel,
                    } => {
                        if let Some(Ok(depth)) = stream.parse_value::<Depth>()? {
                            sc.depth = depth;
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(sc)
    }
}

impl DavParser for ExpandProperty {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut ep = ExpandProperty { properties: vec![] };
        let mut depth = 1;

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => match name {
                    NamedElement {
                        ns,
                        element: Element::Property,
                    } => {
                        for attribute in raw.attributes::<String>() {
                            if let Attribute::Name(name) = attribute? {
                                if let Some(property) = Element::try_parse(name.as_bytes())
                                    .copied()
                                    .and_then(|element| {
                                        DavProperty::from_element(NamedElement { ns, element })
                                    })
                                {
                                    ep.properties.push(ExpandPropertyItem {
                                        property,
                                        depth: depth - 1,
                                    });
                                } else {
                                    let attrs = raw.element.attributes_raw().trim_ascii();
                                    ep.properties.push(ExpandPropertyItem {
                                        property: DavProperty::DeadProperty(DeadElementTag {
                                            name,
                                            attrs: (!attrs.is_empty()).then(|| {
                                                String::from_utf8_lossy(attrs).into_owned()
                                            }),
                                        }),
                                        depth: depth - 1,
                                    });
                                }
                                break;
                            }
                        }
                        depth += 1;
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    depth -= 1;

                    if depth == 0 {
                        break;
                    }
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(ep)
    }
}

impl TextMatch {
    fn parse(raw: RawElement<'_>) -> crate::parser::Result<Self> {
        let mut tm = TextMatch {
            match_type: MatchType::Contains,
            value: String::new(),
            collation: Collation::AsciiCasemap,
            negate: false,
        };

        for attribute in raw.attributes::<String>() {
            match attribute? {
                Attribute::MatchType(match_type) => {
                    tm.match_type = match_type;
                }
                Attribute::NegateCondition(negate) => {
                    tm.negate = negate;
                }
                Attribute::Collation(collation) => {
                    tm.collation = collation;
                }
                _ => {}
            }
        }

        Ok(tm)
    }
}

impl<A, B, C> Filter<A, B, C> {
    fn from_parts(comp: A, prop: Option<B>, param: Option<C>, op: FilterOp) -> Option<Self> {
        match (prop, param) {
            (Some(prop), Some(param)) => Some(Filter::Parameter {
                comp,
                prop,
                param,
                op,
            }),
            (Some(prop), None) => Some(Filter::Property { comp, prop, op }),
            (None, None) => Some(Filter::Component { comp, op }),
            _ => None,
        }
    }

    fn components(&self) -> Option<&A> {
        match self {
            Filter::Component { comp, .. } => Some(comp),
            Filter::Property { comp, .. } => Some(comp),
            Filter::Parameter { comp, .. } => Some(comp),
            _ => None,
        }
    }

    fn parse(raw: RawElement<'_>) -> crate::parser::Result<Option<Self>> {
        for attribute in raw.attributes::<String>() {
            if let Attribute::TestAllOf(all_of) = attribute? {
                return Ok(Some(if all_of { Filter::AllOf } else { Filter::AnyOf }));
            }
        }

        Ok(None)
    }
}

impl XmlValueParser for Depth {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        Depth::parse(bytes)
    }

    fn parse_str(text: &str) -> Option<Self> {
        Depth::parse(text.as_bytes())
    }
}
