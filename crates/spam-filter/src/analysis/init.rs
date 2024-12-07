use common::Core;
use mail_parser::{parsers::fields::thread::thread_name, HeaderName};

use crate::{
    Email, Hostname, Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput,
    SpamFilterResult,
};

pub trait SpamFilterInit {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x>;
}

const POSTMASTER_ADDRESSES: [&str; 3] = ["postmaster", "mailer-daemon", "root"];

impl SpamFilterInit for Core {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x> {
        let mut subject = String::new();
        let mut from = None;
        let mut reply_to = None;
        let mut recipients_to = Vec::new();
        let mut recipients_cc = Vec::new();
        let mut recipients_bcc = Vec::new();

        for header in input.message.headers() {
            match &header.name {
                HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    if let Some(addrs) = header.value().as_address() {
                        for addr in addrs.iter() {
                            let rcpt = Recipient {
                                email: Email::new(addr.address().unwrap_or_default()),
                                name: addr.name().and_then(|s| {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        Some(s.to_lowercase())
                                    } else {
                                        None
                                    }
                                }),
                            };
                            if header.name == HeaderName::To {
                                recipients_to.push(rcpt);
                            } else if header.name == HeaderName::Cc {
                                recipients_cc.push(rcpt);
                            } else {
                                recipients_bcc.push(rcpt);
                            }
                        }
                    }
                }
                HeaderName::ReplyTo => {
                    reply_to = header
                        .value()
                        .as_address()
                        .and_then(|addrs| addrs.first())
                        .and_then(|addr| {
                            Some(Recipient {
                                email: Email::new(addr.address()?),
                                name: addr.name().and_then(|s| {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        Some(s.to_lowercase())
                                    } else {
                                        None
                                    }
                                }),
                            })
                        });
                }
                HeaderName::Subject => {
                    subject = header.value().as_text().unwrap_or_default().to_lowercase();
                }
                HeaderName::From => {
                    from = header.value().as_address().and_then(|addrs| addrs.first());
                }
                _ => {}
            }
        }

        let env_from_addr = Email::new(input.env_from);
        SpamFilterContext {
            output: SpamFilterOutput {
                ehlo_host: Hostname::new(input.ehlo_domain),
                iprev_ptr: input
                    .iprev_result
                    .ptr
                    .as_ref()
                    .and_then(|ptr| ptr.first())
                    .map(|ptr| ptr.strip_suffix('.').unwrap_or(ptr).to_lowercase()),
                env_from_postmaster: env_from_addr.address.is_empty()
                    || POSTMASTER_ADDRESSES.contains(&env_from_addr.local_part.as_str()),
                env_from_addr,
                env_to_addr: input
                    .env_rcpt_to
                    .iter()
                    .map(|rcpt| Email::new(rcpt))
                    .collect(),
                from: Recipient {
                    email: Email::new(from.and_then(|f| f.address()).unwrap_or_default()),
                    name: from.and_then(|f| f.name()).map(|s| s.to_lowercase()),
                },
                reply_to,
                subject_thread: thread_name(&subject).to_string(),
                subject,
                recipients_to,
                recipients_cc,
                recipients_bcc,
            },
            input,
            result: SpamFilterResult {
                tags: Default::default(),
            },
        }
    }
}

/*

use std::future::Future;

use common::Core;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyze!: Sync + Send {
    fn spam_filter_analyze_*(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyze! for Core {
    async fn spam_filter_analyze_*(&self, ctx: &mut SpamFilterContext<'_>) {
        todo!()
    }
}


*/
