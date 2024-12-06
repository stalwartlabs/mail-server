use common::Core;
use mail_parser::{parsers::fields::thread::thread_name, HeaderName};
use store::ahash::AHashSet;

use crate::{Email, Hostname, SpamFilterContext, SpamFilterInput, SpamFilterOutput};

pub trait SpamFilterInit {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x>;
}

impl SpamFilterInit for Core {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x> {
        let subject = input.message.subject().unwrap_or_default().to_lowercase();
        let from = input.message.from().and_then(|f| f.first());
        let mut recipients = AHashSet::new();
        for header in input.message.headers() {
            if matches!(
                header.name,
                HeaderName::To | HeaderName::Cc | HeaderName::Bcc
            ) {
                if let Some(addrs) = header.value().as_address() {
                    for addr in addrs.iter() {
                        if let Some(addr) = addr.address() {
                            recipients.insert(Email::new(addr));
                        }
                    }
                }
            }
        }

        let output = SpamFilterOutput {
            tags: Default::default(),
            ehlo_host: Hostname::new(input.ehlo_domain),
            iprev_ptr: input
                .iprev_result
                .ptr
                .as_ref()
                .and_then(|ptr| ptr.first())
                .map(|ptr| ptr.strip_suffix('.').unwrap_or(ptr).to_lowercase()),
            env_from_addr: Email::new(input.env_mail_from),
            from_addr: Email::new(from.and_then(|f| f.address()).unwrap_or_default()),
            from_name: from
                .and_then(|f| f.name())
                .unwrap_or_default()
                .to_lowercase(),
            subject_thread: thread_name(&subject).to_string(),
            subject,
            recipients,
        };

        SpamFilterContext { output, input }
    }
}

/*

use std::future::Future;

use common::Core;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeEhlo: Sync + Send {
    fn spam_filter_analyze_ehlo(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeEhlo for Core {
    async fn spam_filter_analyze_ehlo(&self, ctx: &mut SpamFilterContext<'_>) {
        todo!()
    }
}


*/
