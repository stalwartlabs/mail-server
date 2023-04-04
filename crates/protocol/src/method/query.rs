use std::fmt::Display;

use crate::{
    error::method::MethodError,
    object::{email, mailbox},
    parser::{json::Parser, Error, Ignore, JsonObjectParser, Token},
    request::{method::MethodObject, RequestProperty, RequestPropertyParser},
    types::{date::UTCDate, id::Id, keyword::Keyword, state::State},
};

#[derive(Debug, Clone)]
pub struct QueryRequest {
    pub account_id: Id,
    pub filter: Vec<Filter>,
    pub sort: Option<Vec<Comparator>>,
    pub position: Option<i64>,
    pub anchor: Option<Id>,
    pub anchor_offset: Option<i64>,
    pub limit: Option<usize>,
    pub calculate_total: Option<bool>,
    pub arguments: RequestArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "queryState")]
    pub query_state: State,

    #[serde(rename = "canCalculateChanges")]
    pub can_calculate_changes: bool,

    #[serde(rename = "position")]
    pub position: i32,

    #[serde(rename = "ids")]
    pub ids: Vec<Id>,

    #[serde(rename = "total")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    #[serde(rename = "limit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum Filter {
    Email(String),
    Name(String),
    DomainName(String),
    Text(String),
    Type(String),
    Timezone(String),
    Members(Id),
    QuotaLt(u64),
    QuotaGt(u64),
    IdentityIds(Vec<Id>),
    EmailIds(Vec<Id>),
    ThreadIds(Vec<Id>),
    UndoStatus(String),
    Before(UTCDate),
    After(UTCDate),
    InMailbox(Id),
    InMailboxOtherThan(Vec<Id>),
    MinSize(u64),
    MaxSize(u64),
    AllInThreadHaveKeyword(Keyword),
    SomeInThreadHaveKeyword(Keyword),
    NoneInThreadHaveKeyword(Keyword),
    HasKeyword(Keyword),
    NotKeyword(Keyword),
    HasAttachment(bool),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Subject(String),
    Body(String),
    Header(Vec<String>),
    Id(Vec<Id>),
    SentBefore(UTCDate),
    SentAfter(UTCDate),
    InThread(Id),
    ParentId(Option<Id>),
    Role(Option<String>),
    HasAnyRole(bool),
    IsSubscribed(bool),
    IsActive(bool),
    _T(String),

    And,
    Or,
    Not,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparator {
    pub is_ascending: bool,
    pub collation: Option<String>,
    pub property: SortProperty,
    pub keyword: Option<Keyword>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SortProperty {
    Type,
    Name,
    Email,
    EmailId,
    ThreadId,
    SentAt,
    ReceivedAt,
    Size,
    From,
    To,
    Subject,
    Cc,
    SortOrder,
    ParentId,
    IsActive,
    HasKeyword,
    AllInThreadHaveKeyword,
    SomeInThreadHaveKeyword,
    _T(String),
}

#[derive(Debug, Clone)]
pub enum RequestArguments {
    Email(email::QueryArguments),
    Mailbox(mailbox::QueryArguments),
    EmailSubmission,
    SieveScript,
    Principal,
}

impl JsonObjectParser for QueryRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = QueryRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email(Default::default()),
                MethodObject::Mailbox => RequestArguments::Mailbox(Default::default()),
                MethodObject::EmailSubmission => RequestArguments::EmailSubmission,
                MethodObject::SieveScript => RequestArguments::SieveScript,
                MethodObject::Principal => RequestArguments::Principal,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/query",
                        parser.ctx
                    ))))
                }
            },
            filter: vec![],
            sort: None,
            position: None,
            anchor: None,
            anchor_offset: None,
            limit: None,
            calculate_total: None,
            account_id: Id::default(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while {
            let property = parser.next_dict_key::<RequestProperty>()?;
            match &property.hash[0] {
                0x6449_746e_756f_6363_61 => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x7265_746c_6966 => match parser.next_token::<Ignore>()? {
                    Token::DictStart => {
                        request.filter = parse_filter(parser)?;
                    }
                    Token::Null => (),
                    token => {
                        return Err(token.error("filter", "object or null"));
                    }
                },
                0x7472_6f73 => {
                    request.sort = <Option<Vec<Comparator>>>::parse(parser)?;
                }
                0x6e6f_6974_6973_6f70 => {
                    request.position = parser
                        .next_token::<Ignore>()?
                        .unwrap_int_or_null("position")?;
                }
                0x726f_6863_6e61 => {
                    request.anchor = parser.next_token::<Id>()?.unwrap_string_or_null("anchor")?;
                }
                0x7465_7366_664f_726f_6863_6e61 => {
                    request.anchor_offset = parser
                        .next_token::<Ignore>()?
                        .unwrap_int_or_null("anchorOffset")?
                }
                0x7469_6d69_6c => {
                    request.limit = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("limit")?;
                }
                0x6c61_746f_5465_7461_6c75_636c_6163 => {
                    request.calculate_total = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("calculateTotal")?;
                }

                _ => {
                    if !request.arguments.parse(parser, property)? {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                    }
                }
            }

            !parser.is_dict_end()?
        } {}

        Ok(request)
    }
}

pub fn parse_filter(parser: &mut Parser) -> crate::parser::Result<Vec<Filter>> {
    let mut filter = vec![Filter::Close];
    let mut pos_stack = vec![0];

    loop {
        match parser.next_token::<RequestProperty>()? {
            Token::String(property) => {
                parser.next_token::<Ignore>()?.assert(Token::Colon)?;
                filter[*pos_stack.last().unwrap()] = match &property.hash[0] {
                    0x726f_7461_7265_706f => {
                        match parser.next_token::<u64>()?.unwrap_string("operator")? {
                            0x444e_41 => Filter::And,
                            0x524f => Filter::Or,
                            0x544f_4e => Filter::Not,
                            _ => return Err(parser.error_value()),
                        }
                    }
                    0x736e_6f69_7469_646e_6f63 => {
                        parser.next_token::<Ignore>()?.assert(Token::ArrayStart)?;
                        continue;
                    }
                    _ => match (&property.hash[0], &property.hash[1]) {
                        (0x6c69_616d_65, _) => {
                            Filter::Email(parser.next_token::<String>()?.unwrap_string("email")?)
                        }
                        (0x656d_616e, _) => {
                            Filter::Name(parser.next_token::<String>()?.unwrap_string("name")?)
                        }
                        (0x656d_614e_6e69_616d_6f64, _) => Filter::DomainName(
                            parser.next_token::<String>()?.unwrap_string("domainName")?,
                        ),
                        (0x7478_6574, _) => {
                            Filter::Text(parser.next_token::<String>()?.unwrap_string("text")?)
                        }
                        (0x6570_7974, _) => {
                            Filter::Type(parser.next_token::<String>()?.unwrap_string("type")?)
                        }
                        (0x656e_6f7a_656d_6974, _) => Filter::Timezone(
                            parser.next_token::<String>()?.unwrap_string("timezone")?,
                        ),
                        (0x7372_6562_6d65_6d, _) => {
                            Filter::Members(parser.next_token::<Id>()?.unwrap_string("members")?)
                        }
                        (0x6e61_6854_7265_776f_4c61_746f_7571, _) => Filter::QuotaLt(
                            parser
                                .next_token::<String>()?
                                .unwrap_uint_or_null("quotaLowerThan")?
                                .unwrap_or_default(),
                        ),
                        (0x6e61_6854_7265_7461_6572_4761_746f_7571, _) => Filter::QuotaGt(
                            parser
                                .next_token::<String>()?
                                .unwrap_uint_or_null("quotaGreaterThan")?
                                .unwrap_or_default(),
                        ),
                        (0x7364_4979_7469_746e_6564_69, _) => {
                            Filter::IdentityIds(<Vec<Id>>::parse(parser)?)
                        }
                        (0x7364_496c_6961_6d65, _) => Filter::EmailIds(<Vec<Id>>::parse(parser)?),
                        (0x7364_4964_6165_7268_74, _) => {
                            Filter::ThreadIds(<Vec<Id>>::parse(parser)?)
                        }
                        (0x7375_7461_7453_6f64_6e75, _) => Filter::UndoStatus(
                            parser.next_token::<String>()?.unwrap_string("undoStatus")?,
                        ),
                        (0x6572_6f66_6562, _) => {
                            Filter::Before(parser.next_token::<UTCDate>()?.unwrap_string("before")?)
                        }
                        (0x7265_7466_61, _) => {
                            Filter::After(parser.next_token::<UTCDate>()?.unwrap_string("after")?)
                        }
                        (0x786f_626c_6961_4d6e_69, _) => Filter::InMailbox(
                            parser.next_token::<Id>()?.unwrap_string("inMailbox")?,
                        ),
                        (0x6854_7265_6874_4f78_6f62_6c69_614d_6e69, 0x6e61) => {
                            Filter::InMailboxOtherThan(<Vec<Id>>::parse(parser)?)
                        }
                        (0x657a_6953_6e69_6d, _) => Filter::MinSize(
                            parser
                                .next_token::<String>()?
                                .unwrap_uint_or_null("minSize")?
                                .unwrap_or_default(),
                        ),
                        (0x657a_6953_7861_6d, _) => Filter::MaxSize(
                            parser
                                .next_token::<String>()?
                                .unwrap_uint_or_null("maxSize")?
                                .unwrap_or_default(),
                        ),
                        (0x4b65_7661_4864_6165_7268_546e_496c_6c61, 0x6472_6f77_7965) => {
                            Filter::AllInThreadHaveKeyword(
                                parser
                                    .next_token::<Keyword>()?
                                    .unwrap_string("allInThreadHaveKeyword")?,
                            )
                        }
                        (0x6576_6148_6461_6572_6854_6e49_656d_6f73, 0x6472_6f77_7965_4b) => {
                            Filter::SomeInThreadHaveKeyword(
                                parser
                                    .next_token::<Keyword>()?
                                    .unwrap_string("someInThreadHaveKeyword")?,
                            )
                        }
                        (0x6576_6148_6461_6572_6854_6e49_656e_6f6e, 0x6472_6f77_7965_4b) => {
                            Filter::NoneInThreadHaveKeyword(
                                parser
                                    .next_token::<Keyword>()?
                                    .unwrap_string("noneInThreadHaveKeyword")?,
                            )
                        }
                        (0x6472_6f77_7965_4b73_6168, _) => Filter::HasKeyword(
                            parser
                                .next_token::<Keyword>()?
                                .unwrap_string("hasKeyword")?,
                        ),
                        (0x6472_6f77_7965_4b74_6f6e, _) => Filter::NotKeyword(
                            parser
                                .next_token::<Keyword>()?
                                .unwrap_string("notKeyword")?,
                        ),
                        (0x746e_656d_6863_6174_7441_7361_68, _) => Filter::HasAttachment(
                            parser
                                .next_token::<String>()?
                                .unwrap_bool("hasAttachment")?,
                        ),
                        (0x6d6f_7266, _) => {
                            Filter::From(parser.next_token::<String>()?.unwrap_string("from")?)
                        }
                        (0x6f74, _) => {
                            Filter::To(parser.next_token::<String>()?.unwrap_string("to")?)
                        }
                        (0x6363, _) => {
                            Filter::Cc(parser.next_token::<String>()?.unwrap_string("cc")?)
                        }
                        (0x6363_62, _) => {
                            Filter::Bcc(parser.next_token::<String>()?.unwrap_string("bcc")?)
                        }
                        (0x7463_656a_6275_73, _) => Filter::Subject(
                            parser.next_token::<String>()?.unwrap_string("subject")?,
                        ),
                        (0x7964_6f62, _) => {
                            Filter::Body(parser.next_token::<String>()?.unwrap_string("body")?)
                        }
                        (0x7265_6461_6568, _) => Filter::Header(<Vec<String>>::parse(parser)?),
                        (0x6469, _) => Filter::Id(<Vec<Id>>::parse(parser)?),
                        (0x6572_6f66_6542_746e_6573, _) => Filter::SentBefore(
                            parser
                                .next_token::<UTCDate>()?
                                .unwrap_string("sentBefore")?,
                        ),
                        (0x7265_7466_4174_6e65_73, _) => Filter::SentAfter(
                            parser.next_token::<UTCDate>()?.unwrap_string("sentAfter")?,
                        ),
                        (0x6461_6572_6854_6e69, _) => {
                            Filter::InThread(parser.next_token::<Id>()?.unwrap_string("inThread")?)
                        }
                        (0x6449_746e_6572_6170, _) => Filter::ParentId(
                            parser
                                .next_token::<Id>()?
                                .unwrap_string_or_null("parentId")?,
                        ),
                        (0x656c_6f72, _) => Filter::Role(
                            parser
                                .next_token::<String>()?
                                .unwrap_string_or_null("role")?,
                        ),
                        (0x656c_6f52_796e_4173_6168, _) => Filter::HasAnyRole(
                            parser.next_token::<String>()?.unwrap_bool("hasAnyRole")?,
                        ),
                        (0x6465_6269_7263_7362_7553_7369, _) => Filter::IsSubscribed(
                            parser.next_token::<String>()?.unwrap_bool("isSubscribed")?,
                        ),
                        (0x6576_6974_6341_7369, _) => Filter::IsActive(
                            parser.next_token::<String>()?.unwrap_bool("isActive")?,
                        ),
                        _ => {
                            if parser.is_eof || parser.skip_string() {
                                let filter = Filter::_T(
                                    String::from_utf8_lossy(
                                        parser.bytes[parser.pos_marker..parser.pos - 1].as_ref(),
                                    )
                                    .into_owned(),
                                );
                                parser.skip_token(parser.depth_array, parser.depth_dict)?;
                                filter
                            } else {
                                return Err(parser.error_unterminated());
                            }
                        }
                    },
                };
            }
            Token::DictStart => {
                pos_stack.push(filter.len());
                filter.push(Filter::Close);
            }
            Token::DictEnd => {
                if !matches!(filter[pos_stack.pop().unwrap()], Filter::Close) {
                    if pos_stack.is_empty() {
                        break;
                    }
                } else {
                    return Err(Error::Method(MethodError::InvalidArguments(
                        "Malformed filter".to_string(),
                    )));
                }
            }
            Token::ArrayEnd => {
                filter.push(Filter::Close);
            }
            Token::Comma => (),
            token => {
                return Err(token.error("filter", "object or array"));
            }
        }
    }

    Ok(filter)
}

impl JsonObjectParser for Comparator {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut comp = Comparator {
            is_ascending: true,
            collation: None,
            property: SortProperty::Type,
            keyword: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while {
            match parser.next_dict_key::<u128>()? {
                0x676e_6964_6e65_6373_4173_69 => {
                    comp.is_ascending = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("isAscending")?
                        .unwrap_or_default();
                }
                0x6e6f_6974_616c_6c6f_63 => {
                    comp.collation = parser
                        .next_token::<String>()?
                        .unwrap_string_or_null("collation")?;
                }
                0x7974_7265_706f_7270 => {
                    comp.property = parser
                        .next_token::<SortProperty>()?
                        .unwrap_string("property")?;
                }
                0x6472_6f77_7965_6b => {
                    comp.keyword = parser
                        .next_token::<Keyword>()?
                        .unwrap_string_or_null("keyword")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }

            !parser.is_dict_end()?
        } {}

        Ok(comp)
    }
}

impl JsonObjectParser for SortProperty {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if ch.is_ascii_alphabetic() {
                if shift < 128 {
                    hash |= (ch as u128) << shift;
                    shift += 8;
                } else {
                    break;
                }
            } else {
                hash = 0;
                break;
            }
        }

        match hash {
            0x6570_7974 => Ok(SortProperty::Type),
            0x656d_616e => Ok(SortProperty::Name),
            0x6c69_616d_65 => Ok(SortProperty::Email),
            0x6449_6c69_616d_65 => Ok(SortProperty::EmailId),
            0x6449_6461_6572_6874 => Ok(SortProperty::ThreadId),
            0x7441_746e_6573 => Ok(SortProperty::SentAt),
            0x7441_6465_7669_6563_6572 => Ok(SortProperty::ReceivedAt),
            0x657a_6973 => Ok(SortProperty::Size),
            0x6d6f_7266 => Ok(SortProperty::From),
            0x6f74 => Ok(SortProperty::To),
            0x7463_656a_6275_73 => Ok(SortProperty::Subject),
            0x6363 => Ok(SortProperty::Cc),
            0x7265_6472_4f74_726f_73 => Ok(SortProperty::SortOrder),
            0x6449_746e_6572_6170 => Ok(SortProperty::ParentId),
            0x6576_6974_6341_7369 => Ok(SortProperty::IsActive),
            0x6472_6f77_7965_4b73_6168 => Ok(SortProperty::HasKeyword),
            0x4b65_7661_4864_6165_7268_546e_496c_6c61 => Ok(SortProperty::AllInThreadHaveKeyword),
            0x6576_6148_6461_6572_6854_6e49_656d_6f73 => Ok(SortProperty::SomeInThreadHaveKeyword),
            _ => {
                if parser.is_eof || parser.skip_string() {
                    Ok(SortProperty::_T(
                        String::from_utf8_lossy(
                            parser.bytes[parser.pos_marker..parser.pos - 1].as_ref(),
                        )
                        .into_owned(),
                    ))
                } else {
                    Err(parser.error_unterminated())
                }
            }
        }
    }
}

impl Display for SortProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SortProperty::Type => "type",
            SortProperty::Name => "name",
            SortProperty::Email => "email",
            SortProperty::EmailId => "emailId",
            SortProperty::ThreadId => "threadId",
            SortProperty::SentAt => "sentAt",
            SortProperty::ReceivedAt => "receivedAt",
            SortProperty::Size => "size",
            SortProperty::From => "from",
            SortProperty::To => "to",
            SortProperty::Subject => "subject",
            SortProperty::Cc => "cc",
            SortProperty::SortOrder => "sortOrder",
            SortProperty::ParentId => "parentId",
            SortProperty::IsActive => "isActive",
            SortProperty::HasKeyword => "hasKeyword",
            SortProperty::AllInThreadHaveKeyword => "allInThreadHaveKeyword",
            SortProperty::SomeInThreadHaveKeyword => "someInThreadHaveKeyword",
            SortProperty::_T(s) => s,
        })
    }
}

impl RequestPropertyParser for RequestArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match self {
            RequestArguments::Email(args) => args.parse(parser, property),
            RequestArguments::Mailbox(args) => args.parse(parser, property),
            _ => Ok(false),
        }
    }
}
