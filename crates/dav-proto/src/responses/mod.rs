/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod error;
pub mod lock;
pub mod mkcol;
pub mod multistatus;
pub mod property;
pub mod propstat;

use std::fmt::{Display, Write};

use crate::schema::{
    property::{Comp, ResourceType, SupportedCollation},
    request::{DeadProperty, DeadPropertyTag},
    response::{Href, List, Location, ResponseDescription, Status, SyncToken},
    Namespaces,
};

trait XmlEscape {
    fn write_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result;
}

trait XmlCdataEscape {
    fn write_cdata_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result;
}

impl<T: AsRef<str>> XmlEscape for T {
    fn write_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result {
        let str = self.as_ref();

        for c in str.chars() {
            match c {
                '<' => out.write_str("&lt;")?,
                '>' => out.write_str("&gt;")?,
                '&' => out.write_str("&amp;")?,
                '"' => out.write_str("&quot;")?,
                '\'' => out.write_str("&apos;")?,
                _ => out.write_char(c)?,
            }
        }

        Ok(())
    }
}

impl<T: AsRef<str>> XmlCdataEscape for T {
    fn write_cdata_escaped_to(&self, out: &mut impl Write) -> std::fmt::Result {
        let str = self.as_ref();
        let mut last_ch = '\0';
        let mut last_ch2 = '\0';

        out.write_str("<![CDATA[")?;

        for ch in str.chars() {
            match ch {
                '>' if last_ch == ']' && last_ch2 == ']' => {
                    out.write_str("]]><![CDATA[>")?;
                }
                _ => out.write_char(ch)?,
            }

            last_ch2 = last_ch;
            last_ch = ch;
        }

        out.write_str("]]>")
    }
}

impl Display for Namespaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("xmlns:D=\"DAV:\"")?;
        if self.cal {
            f.write_str(" xmlns:A=\"urn:ietf:params:xml:ns:caldav\"")?;
        }
        if self.card {
            f.write_str(" xmlns:B=\"urn:ietf:params:xml:ns:carddav\"")?;
        }
        if self.cs {
            f.write_str(" xmlns:C=\"http://calendarserver.org/ns/\"")?;
        }
        Ok(())
    }
}

impl Display for Href {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:href>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:href>")
    }
}

impl<T: Display> Display for List<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in &self.0 {
            item.fmt(f)?;
        }

        Ok(())
    }
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:status>")?;
        write!(f, "HTTP/1.1 {}", self.0)?;
        write!(f, "</D:status>")
    }
}

impl Display for ResponseDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:responsedescription>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:responsedescription>")
    }
}

impl Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:location>")?;
        self.0.fmt(f)?;
        write!(f, "</D:location>")
    }
}

impl Display for SyncToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:sync-token>")?;
        self.0.write_escaped_to(f)?;
        write!(f, "</D:sync-token>")
    }
}

impl Display for Comp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<A:comp name=\"{}\">", self.0.as_str())
    }
}

impl Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Collection => write!(f, "<D:collection/>"),
            ResourceType::Principal => write!(f, "<D:principal/>"),
            ResourceType::AddressBook => write!(f, "<B:addressbook/>"),
            ResourceType::Calendar => write!(f, "<A:calendar/>"),
        }
    }
}

impl Display for SupportedCollation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ns = self.namespace.prefix();
        write!(
            f,
            "<{ns}:supported-collation>{}</{ns}:supported-collation>",
            self.collation.as_str()
        )
    }
}

impl Display for DeadProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut last_tag = "";

        for item in &self.0 {
            match item {
                DeadPropertyTag::ElementStart(tag) => {
                    let name = &tag.name;
                    if let Some(attrs) = &tag.attrs {
                        write!(f, "<{name} {attrs}>")?;
                    } else {
                        write!(f, "<{name}>")?;
                    }
                    last_tag = name;
                }
                DeadPropertyTag::ElementEnd => {
                    write!(f, "</{}>", last_tag)?;
                }
                DeadPropertyTag::Text(text) => {
                    text.write_escaped_to(f)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use calcard::{icalendar::ICalendar, vcard::VCard};
    use hyper::StatusCode;
    use mail_parser::DateTime;

    use crate::{
        parser::{tokenizer::Tokenizer, Token},
        responses::XmlCdataEscape,
        schema::{
            property::{
                ActiveLock, CalDavProperty, CardDavProperty, DavValue, LockScope, Privilege,
                ResourceType, Rfc1123DateTime, SupportedLock, WebDavProperty,
            },
            request::{DavPropertyValue, DeadElementTag, DeadProperty, DeadPropertyTag},
            response::{
                Ace, AclRestrictions, BaseCondition, ErrorResponse, GrantDeny, Href, List,
                MkColResponse, MultiStatus, Principal, PrincipalSearchProperty,
                PrincipalSearchPropertySet, PropResponse, PropStat, RequiredPrincipal, Resource,
                Response, SupportedPrivilege,
            },
            Namespace,
        },
        Depth,
    };

    impl<T: Display> List<T> {
        pub fn new(vec: impl IntoIterator<Item = T>) -> Self {
            List(vec.into_iter().collect())
        }
    }

    impl From<ICalendar> for DavValue {
        fn from(v: ICalendar) -> Self {
            DavValue::ICalendar(v)
        }
    }

    impl From<VCard> for DavValue {
        fn from(v: VCard) -> Self {
            DavValue::VCard(v)
        }
    }

    #[test]
    fn parse_responses() {
        for (num, test) in [
            // 001.xml
            ErrorResponse::new(BaseCondition::LockTokenSubmitted(List::new([Href(
                "/locked/".to_string(),
            )])))
            .to_string(),
            // 002.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/file",
                vec![
                    PropStat::new(DavPropertyValue::new(
                        WebDavProperty::DisplayName,
                        "Box type A",
                    )),
                    PropStat::new(DavPropertyValue::new(
                        WebDavProperty::DisplayName,
                        "Box type B",
                    ))
                    .with_status(StatusCode::FORBIDDEN)
                    .with_response_description(
                        "The user does not have access to the DingALing property.",
                    ),
                ],
            )])
            .with_response_description("There has been an access violation error.")
            .to_string(),
            // 003.xml
            MultiStatus::new(vec![
                Response::new_propstat(
                    "/container/",
                    vec![PropStat::new_list(vec![
                        DavPropertyValue::new(
                            WebDavProperty::CreationDate,
                            DateTime::parse_rfc3339("1997-12-01T17:42:21-08:00Z").unwrap(),
                        ),
                        DavPropertyValue::new(WebDavProperty::DisplayName, "Example collection"),
                        DavPropertyValue::new(
                            WebDavProperty::ResourceType,
                            vec![ResourceType::Collection],
                        ),
                        DavPropertyValue::new(
                            WebDavProperty::SupportedLock,
                            SupportedLock::default(),
                        ),
                    ])],
                ),
                Response::new_propstat(
                    "/container/front.html",
                    vec![PropStat::new_list(vec![
                        DavPropertyValue::new(
                            WebDavProperty::CreationDate,
                            DateTime::parse_rfc3339("1997-12-01T18:27:21-08:00").unwrap(),
                        ),
                        DavPropertyValue::new(WebDavProperty::DisplayName, "Example HTML resource"),
                        DavPropertyValue::new(WebDavProperty::GetContentLength, 4525u64),
                        DavPropertyValue::new(WebDavProperty::GetContentType, "text/html"),
                        DavPropertyValue::new(WebDavProperty::GetETag, "\"zzyzx\""),
                        DavPropertyValue::new(
                            WebDavProperty::GetLastModified,
                            DavValue::Rfc1123Date(Rfc1123DateTime::new(
                                DateTime::parse_rfc822("Mon, 12 Jan 1998 09:25:56 GMT")
                                    .unwrap()
                                    .to_timestamp(),
                            )),
                        ),
                        DavPropertyValue::new(WebDavProperty::ResourceType, DavValue::Null),
                        DavPropertyValue::new(
                            WebDavProperty::SupportedLock,
                            SupportedLock::default(),
                        ),
                    ])],
                ),
            ])
            .to_string(),
            // 004.xml
            MultiStatus::new(vec![Response::new_status(
                ["http://www.example.com/container/resource3"],
                StatusCode::LOCKED,
            )
            .with_error(BaseCondition::LockTokenSubmitted(List(vec![])))])
            .to_string(),
            // 005.xml
            PropResponse::new(vec![DavPropertyValue::new(
                WebDavProperty::LockDiscovery,
                vec![ActiveLock::new(
                    "http://example.com/workspace/webdav/proposal.doc",
                    LockScope::Exclusive,
                )
                .with_owner(DeadProperty(vec![
                    DeadPropertyTag::ElementStart(DeadElementTag {
                        name: "D:href".to_string(),
                        attrs: None,
                    }),
                    DeadPropertyTag::Text("http://example.org/~ejw/contact.html".to_string()),
                    DeadPropertyTag::ElementEnd,
                ]))
                .with_timeout(604800)
                .with_lock_token("urn:uuid:e71d4fae-5dec-22d6-fea5-00a0c91e6be4")],
            )])
            .to_string(),
            // 006.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/container/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::LockDiscovery,
                    vec![
                        ActiveLock::new("http://www.example.com/container/", LockScope::Shared)
                            .with_owner(DeadProperty(vec![DeadPropertyTag::Text(
                                "Jane Smith".to_string(),
                            )]))
                            .with_depth(Depth::Zero)
                            .with_lock_token("urn:uuid:f81de2ad-7f3d-a1b2-4f3c-00a0c91a9d76"),
                    ],
                )])],
            )])
            .to_string(),
            // 007.xml
            ErrorResponse::new(BaseCondition::LockTokenSubmitted(List(vec![Href(
                "/workspace/webdav/".to_string(),
            )])))
            .to_string(),
            // 008.xml
            MultiStatus::new(vec![
                Response::new_propstat(
                    "http://cal.example.com/bernard/work/abcd2.ics",
                    vec![PropStat::new_list(vec![
                        DavPropertyValue::new(WebDavProperty::GetETag, "\"fffff-abcd2\""),
                        DavPropertyValue::new(
                            CalDavProperty::CalendarData(Default::default()),
                            ICalendar::parse(
                                r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060106T140000
DURATION:PT1H
RECURRENCE-ID;TZID=US/Eastern:20060106T120000
SUMMARY:Event #2 bis bis
UID:00959BC664CA650E933C892C@example.com
END:VEVENT
END:VCALENDAR
"#,
                            )
                            .unwrap(),
                        ),
                    ])],
                ),
                Response::new_propstat(
                    "http://cal.example.com/bernard/work/abcd3.ics",
                    vec![PropStat::new_list(vec![
                        DavPropertyValue::new(WebDavProperty::GetETag, "\"fffff-abcd3\""),
                        DavPropertyValue::new(
                            CalDavProperty::CalendarData(Default::default()),
                            ICalendar::parse(
                                r#"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
DTSTART;TZID=US/Eastern:20060104T100000
DURATION:PT1H
SUMMARY:Event #3
UID:DC6C50A017428C5216A2F1CD@example.com
END:VEVENT
END:VCALENDAR
"#,
                            )
                            .unwrap(),
                        ),
                    ])],
                ),
            ])
            .with_namespace(Namespace::CalDav)
            .to_string(),
            // 009.xml
            MkColResponse::new(vec![PropStat::new_list(vec![
                DavPropertyValue::new(WebDavProperty::ResourceType, DavValue::Null),
                DavPropertyValue::new(WebDavProperty::DisplayName, DavValue::Null),
                DavPropertyValue::new(CardDavProperty::AddressbookDescription, DavValue::Null),
            ])])
            .with_namespace(Namespace::CardDav)
            .to_string(),
            // 010.xml
            MultiStatus::new(vec![Response::new_propstat(
                "/home/bernard/addressbook/v102.vcf",
                vec![PropStat::new_list(vec![
                    DavPropertyValue::new(WebDavProperty::GetETag, "\"23ba4d-ff11fb\""),
                    DavPropertyValue::new(
                        CardDavProperty::AddressData(Default::default()),
                        VCard::parse(
                            r#"BEGIN:VCARD
VERSION:3.0
NICKNAME:me
UID:34222-232@example.com
FN:Cyrus Daboo
EMAIL:daboo@example.com
END:VCARD
"#,
                        )
                        .unwrap(),
                    ),
                ])],
            )])
            .with_namespace(Namespace::CardDav)
            .to_string(),
            // 011.xml
            MultiStatus::new(vec![
                Response::new_status(
                    ["/home/bernard/addressbook/"],
                    StatusCode::INSUFFICIENT_STORAGE,
                )
                .with_error(BaseCondition::NumberOfMatchesWithinLimit)
                .with_response_description("Only two matching records were returned"),
                Response::new_propstat(
                    "/home/bernard/addressbook/v102.vcf",
                    vec![PropStat::new_list(vec![DavPropertyValue::new(
                        WebDavProperty::GetETag,
                        "\"23ba4d-ff11fb\"",
                    )])],
                ),
                Response::new_propstat(
                    "/home/bernard/addressbook/v104.vcf",
                    vec![PropStat::new_list(vec![DavPropertyValue::new(
                        WebDavProperty::GetETag,
                        "\"23ba4d-ff11fc\"",
                    )])],
                ),
            ])
            .with_namespace(Namespace::CardDav)
            .to_string(),
            // 012.xml
            ErrorResponse::new(BaseCondition::NeedPrivileges(List(vec![
                Resource::new("/a", Privilege::Unbind),
                Resource::new("/c", Privilege::Bind),
            ])))
            .to_string(),
            // 013.xml
            PrincipalSearchPropertySet::new(vec![
                PrincipalSearchProperty::new(WebDavProperty::DisplayName, "Full name"),
                PrincipalSearchProperty::new(WebDavProperty::DisplayName, "Job title"),
            ])
            .to_string(),
            // 014.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/papers/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::SupportedPrivilegeSet,
                    vec![SupportedPrivilege::new(Privilege::All, "Any operation")
                        .with_abstract()
                        .with_supported_privilege(
                            SupportedPrivilege::new(Privilege::Read, "Read any object")
                                .with_supported_privilege(
                                    SupportedPrivilege::new(Privilege::ReadAcl, "Read ACL")
                                        .with_abstract(),
                                )
                                .with_supported_privilege(
                                    SupportedPrivilege::new(
                                        Privilege::ReadCurrentUserPrivilegeSet,
                                        "Read current user privilege set property",
                                    )
                                    .with_abstract(),
                                ),
                        )
                        .with_supported_privilege(
                            SupportedPrivilege::new(Privilege::Write, "Write any object")
                                .with_supported_privilege(
                                    SupportedPrivilege::new(Privilege::WriteAcl, "Write ACL")
                                        .with_abstract(),
                                )
                                .with_supported_privilege(SupportedPrivilege::new(
                                    Privilege::WriteProperties,
                                    "Write properties",
                                ))
                                .with_supported_privilege(SupportedPrivilege::new(
                                    Privilege::WriteContent,
                                    "Write resource content",
                                )),
                        )
                        .with_supported_privilege(SupportedPrivilege::new(
                            Privilege::Unlock,
                            "Unlock resource",
                        ))],
                )])],
            )])
            .to_string(),
            // 015.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/papers/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::CurrentUserPrivilegeSet,
                    vec![Privilege::Read],
                )])],
            )])
            .to_string(),
            // 016.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/papers/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::Acl,
                    vec![
                        Ace::new(
                            Principal::Href(Href(
                                "http://www.example.com/acl/groups/maintainers".to_string(),
                            )),
                            GrantDeny::grant(vec![Privilege::Write]),
                        ),
                        Ace::new(Principal::All, GrantDeny::grant(vec![Privilege::Read])),
                    ],
                )])],
            )])
            .to_string(),
            // 017.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/papers/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::AclRestrictions,
                    AclRestrictions::new()
                        .with_grant_only()
                        .with_required_principal(RequiredPrincipal::All),
                )])],
            )])
            .to_string(),
            // 018.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/papers/",
                vec![PropStat::new_list(vec![DavPropertyValue::new(
                    WebDavProperty::PrincipalCollectionSet,
                    vec![
                        Href("http://www.example.com/acl/users/".to_string()),
                        Href("http://www.example.com/acl/groups/".to_string()),
                    ],
                )])],
            )])
            .to_string(),
            // 019.xml
            MultiStatus::new(vec![Response::new_propstat(
                "http://www.example.com/top/container/",
                vec![PropStat::new_list(vec![
                    DavPropertyValue::new(
                        WebDavProperty::Owner,
                        vec![Href("http://www.example.com/users/gclemm".to_string())],
                    ),
                    DavPropertyValue::new(
                        WebDavProperty::SupportedPrivilegeSet,
                        vec![SupportedPrivilege::new(Privilege::All, "Any operation")
                            .with_abstract()
                            .with_supported_privilege(SupportedPrivilege::new(
                                Privilege::Read,
                                "Read any object",
                            ))
                            .with_supported_privilege(
                                SupportedPrivilege::new(Privilege::Write, "Write any object")
                                    .with_abstract(),
                            )
                            .with_supported_privilege(SupportedPrivilege::new(
                                Privilege::ReadAcl,
                                "Read the ACL",
                            ))
                            .with_supported_privilege(SupportedPrivilege::new(
                                Privilege::WriteAcl,
                                "Write the ACL",
                            ))],
                    ),
                    DavPropertyValue::new(
                        WebDavProperty::CurrentUserPrivilegeSet,
                        vec![Privilege::Read, Privilege::ReadAcl],
                    ),
                    DavPropertyValue::new(
                        WebDavProperty::Acl,
                        vec![
                            Ace::new(
                                Principal::Href(Href(
                                    "http://www.example.com/users/esedlar".to_string(),
                                )),
                                GrantDeny::grant(vec![
                                    Privilege::Read,
                                    Privilege::Write,
                                    Privilege::ReadAcl,
                                ]),
                            ),
                            Ace::new(
                                Principal::Href(Href(
                                    "http://www.example.com/groups/mrktng".to_string(),
                                )),
                                GrantDeny::deny(vec![Privilege::Read]),
                            ),
                            Ace::new(
                                Principal::Property(List(vec![DavPropertyValue::new(
                                    WebDavProperty::Owner,
                                    DavValue::Null,
                                )])),
                                GrantDeny::grant(vec![Privilege::ReadAcl, Privilege::WriteAcl]),
                            ),
                            Ace::new(Principal::All, GrantDeny::grant(vec![Privilege::Read]))
                                .with_inherited("http://www.example.com/top"),
                        ],
                    ),
                ])],
            )])
            .to_string(),
        ]
        .into_iter()
        .enumerate()
        {
            let xml =
                std::fs::read_to_string(format!("resources/responses/{:03}.xml", num + 1)).unwrap();
            let mut output_token = Tokenizer::new(test.as_bytes());
            let mut expected_token = Tokenizer::new(xml.as_bytes());

            loop {
                let mut output = output_token.token().unwrap();
                let mut expected = expected_token.token().unwrap();

                for token in [&mut output, &mut expected] {
                    if let Token::Bytes(text) = token {
                        // Remove '\r'
                        *text = text
                            .iter()
                            .copied()
                            .filter(|&c| c != b'\r')
                            .collect::<Vec<_>>()
                            .into();
                    }
                }

                if output != expected {
                    eprintln!("{test}");
                }
                assert_eq!(output, expected, "failed for {:03}.xml", num + 1);
                if output == Token::Eof {
                    break;
                }
            }
        }
    }

    #[test]
    fn escape_cdata() {
        for (test, expected) in [
            ("", "<![CDATA[]]>"),
            ("hello", "<![CDATA[hello]]>"),
            ("hello world", "<![CDATA[hello world]]>"),
            ("<hello>", "<![CDATA[<hello>]]>"),
            ("&hello;", "<![CDATA[&hello;]]>"),
            ("'hello'", "<![CDATA['hello']]>"),
            ("\"hello\"", "<![CDATA[\"hello\"]]>"),
            ("<>&'\"", "<![CDATA[<>&'\"]]>"),
            (">", "<![CDATA[>]]>"),
            ("]]>]", "<![CDATA[]]]]><![CDATA[>]]]>"),
            ("]]>", "<![CDATA[]]]]><![CDATA[>]]>"),
            ("hello]]>world", "<![CDATA[hello]]]]><![CDATA[>world]]>"),
            (
                "hello]]><nasty-xml>pure-evil</nasty-xml>",
                "<![CDATA[hello]]]]><![CDATA[><nasty-xml>pure-evil</nasty-xml>]]>",
            ),
        ] {
            let mut output = String::new();
            test.write_cdata_escaped_to(&mut output).unwrap();
            assert_eq!(output, expected, "failed for input: {test:?}");
        }
    }
}
