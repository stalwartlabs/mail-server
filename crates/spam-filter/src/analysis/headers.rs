use std::future::Future;

use common::Server;
use mail_parser::HeaderName;
use store::ahash::AHashSet;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeHeaders: Sync + Send {
    fn spam_filter_analyze_headers(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeHeaders for Server {
    async fn spam_filter_analyze_headers(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut list_score = 0.0;
        let mut unique_headers = AHashSet::new();
        let raw_message = ctx.input.message.raw_message();

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::ContentType
                | HeaderName::ContentTransferEncoding
                | HeaderName::Date
                | HeaderName::From
                | HeaderName::Sender
                | HeaderName::To
                | HeaderName::Cc
                | HeaderName::Bcc
                | HeaderName::ReplyTo
                | HeaderName::Subject
                | HeaderName::MessageId
                | HeaderName::References
                | HeaderName::InReplyTo => {
                    if !unique_headers.insert(header.name.clone()) {
                        ctx.result.add_tag("MULTIPLE_UNIQUE_HEADERS");
                    }

                    if !matches!(raw_message.get(header.offset_start), Some(b' ')) {
                        ctx.result.add_tag("HEADER_EMPTY_DELIMITER");
                    }
                }
                HeaderName::ListArchive
                | HeaderName::ListOwner
                | HeaderName::ListHelp
                | HeaderName::ListPost => {
                    list_score += 0.125;
                }
                HeaderName::ListId => {
                    list_score += 0.5125;
                }
                HeaderName::ListSubscribe => {
                    list_score += 0.25;
                }
                HeaderName::ListUnsubscribe => {
                    list_score += 0.25;
                    ctx.result.add_tag("HAS_LIST_UNSUB");
                }
                HeaderName::Other(name) => {
                    let value = header
                        .value()
                        .as_text()
                        .unwrap_or_default()
                        .trim()
                        .to_lowercase();

                    if name.eq_ignore_ascii_case("Precedence") {
                        if value == "bulk" {
                            list_score += 0.25;
                            ctx.result.add_tag("PRECEDENCE_BULK");
                        } else if value == "list" {
                            list_score += 0.25;
                        }
                    } else if name.eq_ignore_ascii_case("X-Loop") {
                        list_score += 0.125;
                    } else if name.eq_ignore_ascii_case("X-Priority") {
                        match value.parse::<i32>().unwrap_or(i32::MAX) {
                            0 => {
                                ctx.result.add_tag("HAS_X_PRIO_ZERO");
                            }
                            1 => {
                                ctx.result.add_tag("HAS_X_PRIO_ONE");
                            }
                            2 => {
                                ctx.result.add_tag("HAS_X_PRIO_TWO");
                            }
                            3 | 4 => {
                                ctx.result.add_tag("HAS_X_PRIO_THREE");
                            }
                            4..=10000 => {
                                ctx.result.add_tag("HAS_X_PRIO_FIVE");
                            }
                            _ => {}
                        }
                    } else if name.eq_ignore_ascii_case("X-Mailer") {
                        if name != "X-Mailer" {
                            ctx.result.add_tag("XM_CASE");
                        }
                        if !value.is_empty() {
                            if !value.as_bytes().iter().any(|&b| b.is_ascii_digit()) {
                                ctx.result.add_tag("XM_UA_NO_VERSION");
                            }

                            if value.contains("phpmailer") {
                                ctx.result.add_tag("HAS_PHPMAILER_SIG");
                            }
                        }
                    } else if name.eq_ignore_ascii_case("User-Agent") {
                        if !value.is_empty()
                            && !value.as_bytes().iter().any(|&b| b.is_ascii_digit())
                        {
                            ctx.result.add_tag("XM_UA_NO_VERSION");
                        }
                    } else if name.eq_ignore_ascii_case("Organization")
                        || name.eq_ignore_ascii_case("Organisation")
                    {
                        ctx.result.add_tag("HAS_ORG_HEADER");
                    } else if name.eq_ignore_ascii_case("X-Originating-IP") {
                        ctx.result.add_tag("HAS_XOIP");
                    } else if name.eq_ignore_ascii_case("X-KLMS-AntiSpam-Status") {
                        if value.contains("spam") {
                            ctx.result.add_tag("KLMS_SPAM");
                        }
                    } else if name.eq_ignore_ascii_case("X-Spam")
                        || name.eq_ignore_ascii_case("X-Spam-Flag")
                        || name.eq_ignore_ascii_case("X-Spam-Status")
                    {
                        if value.contains("yes") || value.contains("true") || value.contains("spam")
                        {
                            ctx.result.add_tag("SPAM_FLAG");
                        }
                    } else if name.eq_ignore_ascii_case("X-UI-Filterresults")
                        || name.eq_ignore_ascii_case("X-UI-Out-Filterresults")
                    {
                        if value.contains("junk") {
                            ctx.result.add_tag("UNITEDINTERNET_SPAM");
                        }
                    } else if name.eq_ignore_ascii_case("X-PHP-Originating-Script") {
                        ctx.result.add_tag("HAS_X_POS");
                        if value.contains("eval()") {
                            ctx.result.add_tag("X_PHP_EVAL");
                        }
                        if value.contains("../") {
                            ctx.result.add_tag("HIDDEN_SOURCE_OBJ");
                        }
                    } else if name.eq_ignore_ascii_case("X-PHP-Script") {
                        ctx.result.add_tag("HAS_X_PHP_SCRIPT");
                        if value.contains("eval()") {
                            ctx.result.add_tag("X_PHP_EVAL");
                        }
                        if value.contains("../") {
                            ctx.result.add_tag("HIDDEN_SOURCE_OBJ");
                        }
                        if value.contains("sendmail.php") {
                            ctx.result.add_tag("PHP_XPS_PATTERN");
                        }
                    } else if name.eq_ignore_ascii_case("X-Source")
                        || name.eq_ignore_ascii_case("X-Source-Args")
                        || name.eq_ignore_ascii_case("X-Source-Dir")
                    {
                        ctx.result.add_tag("HAS_X_SOURCE");
                        if value.contains("'../") {
                            ctx.result.add_tag("HIDDEN_SOURCE_OBJ");
                        }
                    } else if name.eq_ignore_ascii_case("X-Authenticated-Sender") {
                        if value.contains(": ") {
                            ctx.result.add_tag("HAS_X_AS");
                        }
                    } else if name.eq_ignore_ascii_case("X-Get-Message-Sender-Via") {
                        if value.contains("authenticated_id:") {
                            ctx.result.add_tag("HAS_X_GMSV");
                        }
                    } else if name.eq_ignore_ascii_case("X-AntiAbuse") {
                        ctx.result.add_tag("HAS_X_ANTIABUSE");
                    } else if name.eq_ignore_ascii_case("X-Authentication-Warning") {
                        ctx.result.add_tag("HAS_XAW");
                    }
                }
                _ => {}
            }
        }

        if list_score >= 1.0 {
            ctx.result.add_tag("MAILLIST");
        }

        if unique_headers.is_empty() {
            ctx.result.add_tag("MISSING_ESSENTIAL_HEADERS");
        }
    }
}
