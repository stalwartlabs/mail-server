use std::sync::Arc;

use jmap_proto::{
    error::request::RequestError,
    request::capability::Capability,
    response::serialize::serialize_hex,
    types::{acl::Acl, collection::Collection, id::Id},
};
use store::ahash::AHashSet;
use utils::{listener::ServerInstance, map::vec_map::VecMap, UnwrapFailure};

use crate::{auth::AclToken, JMAP};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Session {
    #[serde(rename(serialize = "capabilities"))]
    capabilities: VecMap<Capability, Capabilities>,
    #[serde(rename(serialize = "accounts"))]
    accounts: VecMap<Id, Account>,
    #[serde(rename(serialize = "primaryAccounts"))]
    primary_accounts: VecMap<Capability, Id>,
    #[serde(rename(serialize = "username"))]
    username: String,
    #[serde(rename(serialize = "apiUrl"))]
    api_url: String,
    #[serde(rename(serialize = "downloadUrl"))]
    download_url: String,
    #[serde(rename(serialize = "uploadUrl"))]
    upload_url: String,
    #[serde(rename(serialize = "eventSourceUrl"))]
    event_source_url: String,
    #[serde(rename(serialize = "state"))]
    #[serde(serialize_with = "serialize_hex")]
    state: u32,
    #[serde(skip)]
    base_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Account {
    #[serde(rename(serialize = "name"))]
    name: String,
    #[serde(rename(serialize = "isPersonal"))]
    is_personal: bool,
    #[serde(rename(serialize = "isReadOnly"))]
    is_read_only: bool,
    #[serde(rename(serialize = "accountCapabilities"))]
    account_capabilities: VecMap<Capability, Capabilities>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum Capabilities {
    Core(CoreCapabilities),
    Mail(MailCapabilities),
    Submission(SubmissionCapabilities),
    VacationResponse(VacationResponseCapabilities),
    WebSocket(WebSocketCapabilities),
    Sieve(SieveCapabilities),
}

#[derive(Debug, Clone, serde::Serialize)]
struct CoreCapabilities {
    #[serde(rename(serialize = "maxSizeUpload"))]
    max_size_upload: usize,
    #[serde(rename(serialize = "maxConcurrentUpload"))]
    max_concurrent_upload: usize,
    #[serde(rename(serialize = "maxSizeRequest"))]
    max_size_request: usize,
    #[serde(rename(serialize = "maxConcurrentRequests"))]
    max_concurrent_requests: usize,
    #[serde(rename(serialize = "maxCallsInRequest"))]
    max_calls_in_request: usize,
    #[serde(rename(serialize = "maxObjectsInGet"))]
    max_objects_in_get: usize,
    #[serde(rename(serialize = "maxObjectsInSet"))]
    max_objects_in_set: usize,
    #[serde(rename(serialize = "collationAlgorithms"))]
    collation_algorithms: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WebSocketCapabilities {
    #[serde(rename(serialize = "url"))]
    url: String,
    #[serde(rename(serialize = "supportsPush"))]
    supports_push: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SieveCapabilities {
    #[serde(rename(serialize = "implementation"))]
    implementation: &'static str,
    #[serde(rename(serialize = "maxSizeScriptName"))]
    max_script_name: usize,
    #[serde(rename(serialize = "maxSizeScript"))]
    max_script_size: usize,
    #[serde(rename(serialize = "maxNumberScripts"))]
    max_scripts: usize,
    #[serde(rename(serialize = "maxNumberRedirects"))]
    max_redirects: usize,
    #[serde(rename(serialize = "sieveExtensions"))]
    extensions: Vec<String>,
    #[serde(rename(serialize = "notificationMethods"))]
    notification_methods: Option<Vec<String>>,
    #[serde(rename(serialize = "externalLists"))]
    ext_lists: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct MailCapabilities {
    #[serde(rename(serialize = "maxMailboxesPerEmail"))]
    max_mailboxes_per_email: Option<usize>,
    #[serde(rename(serialize = "maxMailboxDepth"))]
    max_mailbox_depth: usize,
    #[serde(rename(serialize = "maxSizeMailboxName"))]
    max_size_mailbox_name: usize,
    #[serde(rename(serialize = "maxSizeAttachmentsPerEmail"))]
    max_size_attachments_per_email: usize,
    #[serde(rename(serialize = "emailQuerySortOptions"))]
    email_query_sort_options: Vec<String>,
    #[serde(rename(serialize = "mayCreateTopLevelMailbox"))]
    may_create_top_level_mailbox: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SubmissionCapabilities {
    #[serde(rename(serialize = "maxDelayedSend"))]
    max_delayed_send: usize,
    #[serde(rename(serialize = "submissionExtensions"))]
    submission_extensions: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct VacationResponseCapabilities {}

#[derive(Default)]
pub struct BaseCapabilities {
    capabilities: VecMap<Capability, Capabilities>,
}

impl JMAP {
    pub async fn handle_session_resource(
        &self,
        instance: &ServerInstance,
        acl_token: Arc<AclToken>,
    ) -> Result<Session, RequestError> {
        let mut session = Session::new(&instance.data, &self.config.capabilities);
        session.set_state(acl_token.state());
        let account_name = self
            .get_account_login(acl_token.primary_id())
            .await
            .unwrap_or_else(|| Id::from(acl_token.primary_id()).to_string());
        session.set_primary_account(
            acl_token.primary_id().into(),
            account_name.to_string(),
            account_name,
            None,
        );

        // Add secondary accounts
        for id in acl_token.secondary_ids() {
            let is_personal = !acl_token.is_member(*id);
            let is_readonly = is_personal
                && self
                    .shared_documents(&acl_token, *id, Collection::Mailbox, Acl::AddItems)
                    .await
                    .map_or(true, |ids| ids.is_empty());

            session.add_account(
                (*id).into(),
                self.get_account_login(*id)
                    .await
                    .unwrap_or_else(|| Id::from(*id).to_string()),
                is_personal,
                is_readonly,
                Some(&[Capability::Core, Capability::Mail, Capability::WebSocket]),
            );
        }

        Ok(session)
    }
}

impl crate::Config {
    pub fn add_capabilites(&mut self, settings: &utils::config::Config) {
        self.capabilities.capabilities.append(
            Capability::Core,
            Capabilities::Core(CoreCapabilities::new(self)),
        );
        self.capabilities.capabilities.append(
            Capability::Mail,
            Capabilities::Mail(MailCapabilities::new(self)),
        );
        self.capabilities.capabilities.append(
            Capability::Sieve,
            Capabilities::Sieve(SieveCapabilities::new(self, settings)),
        );
    }
}

impl Session {
    pub fn new(base_url: &str, base_capabilities: &BaseCapabilities) -> Session {
        let mut capabilities = base_capabilities.capabilities.clone();
        capabilities.append(
            Capability::WebSocket,
            Capabilities::WebSocket(WebSocketCapabilities::new(base_url)),
        );

        Session {
            capabilities,
            accounts: VecMap::new(),
            primary_accounts: VecMap::new(),
            username: "".to_string(),
            api_url: format!("{}/jmap/", base_url),
            download_url: format!(
                "{}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}",
                base_url
            ),
            upload_url: format!("{}/jmap/upload/{{accountId}}/", base_url),
            event_source_url: format!(
                "{}/jmap/eventsource/?types={{types}}&closeafter={{closeafter}}&ping={{ping}}",
                base_url
            ),
            base_url: base_url.to_string(),
            state: 0,
        }
    }

    pub fn set_primary_account(
        &mut self,
        account_id: Id,
        username: String,
        name: String,
        capabilities: Option<&[Capability]>,
    ) {
        self.username = username;

        if let Some(capabilities) = capabilities {
            for capability in capabilities {
                self.primary_accounts.append(*capability, account_id);
            }
        } else {
            for capability in self.capabilities.keys() {
                self.primary_accounts.append(*capability, account_id);
            }
        }

        self.accounts.set(
            account_id,
            Account::new(name, true, false).add_capabilities(capabilities, &self.capabilities),
        );
    }

    pub fn add_account(
        &mut self,
        account_id: Id,
        name: String,
        is_personal: bool,
        is_read_only: bool,
        capabilities: Option<&[Capability]>,
    ) {
        self.accounts.set(
            account_id,
            Account::new(name, is_personal, is_read_only)
                .add_capabilities(capabilities, &self.capabilities),
        );
    }

    pub fn set_state(&mut self, state: u32) {
        self.state = state;
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Account {
    pub fn new(name: String, is_personal: bool, is_read_only: bool) -> Account {
        Account {
            name,
            is_personal,
            is_read_only,
            account_capabilities: VecMap::new(),
        }
    }

    pub fn add_capabilities(
        mut self,
        capabilities: Option<&[Capability]>,
        core_capabilities: &VecMap<Capability, Capabilities>,
    ) -> Account {
        if let Some(capabilities) = capabilities {
            for capability in capabilities {
                self.account_capabilities.append(
                    *capability,
                    core_capabilities.get(capability).unwrap().clone(),
                );
            }
        } else {
            self.account_capabilities = core_capabilities.clone();
        }
        self
    }
}

impl CoreCapabilities {
    pub fn new(config: &crate::Config) -> Self {
        CoreCapabilities {
            max_size_upload: config.upload_max_size,
            max_concurrent_upload: config.upload_max_concurrent,
            max_size_request: config.request_max_size,
            max_concurrent_requests: config.request_max_concurrent as usize,
            max_calls_in_request: config.request_max_calls,
            max_objects_in_get: config.get_max_objects,
            max_objects_in_set: config.set_max_objects,
            collation_algorithms: vec![
                "i;ascii-numeric".to_string(),
                "i;ascii-casemap".to_string(),
                "i;unicode-casemap".to_string(),
            ],
        }
    }
}

impl WebSocketCapabilities {
    pub fn new(base_url: &str) -> Self {
        WebSocketCapabilities {
            url: format!("ws{}/jmap/ws", base_url.strip_prefix("http").unwrap()),
            supports_push: true,
        }
    }
}

impl SieveCapabilities {
    pub fn new(config: &crate::Config, settings: &utils::config::Config) -> Self {
        let mut notification_methods = Vec::new();

        for (_, uri) in settings.values("jmap.sieve.notification-uris") {
            notification_methods.push(uri.to_string());
        }
        if notification_methods.is_empty() {
            notification_methods.push("mailto".to_string());
        }

        let mut capabilities: AHashSet<sieve::compiler::grammar::Capability> =
            AHashSet::from_iter(sieve::compiler::grammar::Capability::all().iter().cloned());

        for (_, capability) in settings.values("jmap.sieve.disabled-capabilities") {
            capabilities.remove(&sieve::compiler::grammar::Capability::parse(capability));
        }

        let mut extensions = capabilities
            .into_iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>();
        extensions.sort_unstable();

        SieveCapabilities {
            max_script_name: config.sieve_max_script_name,
            max_script_size: settings
                .property("jmap.sieve.max-script-size")
                .failed("Invalid configuration file")
                .unwrap_or(1024 * 1024),
            max_scripts: config.sieve_max_scripts,
            max_redirects: settings
                .property("jmap.sieve.max-redirects")
                .failed("Invalid configuration file")
                .unwrap_or(1),
            extensions,
            notification_methods: if !notification_methods.is_empty() {
                notification_methods.into()
            } else {
                None
            },
            ext_lists: None,
            implementation: concat!("Stalwart JMAP v", env!("CARGO_PKG_VERSION"),),
        }
    }
}

impl MailCapabilities {
    pub fn new(config: &crate::Config) -> Self {
        MailCapabilities {
            max_mailboxes_per_email: None,
            max_mailbox_depth: config.mailbox_max_depth,
            max_size_mailbox_name: config.mailbox_name_max_len,
            max_size_attachments_per_email: config.mail_attachments_max_size,
            email_query_sort_options: [
                "receivedAt",
                "size",
                "from",
                "to",
                "subject",
                "sentAt",
                "hasKeyword",
                "allInThreadHaveKeyword",
                "someInThreadHaveKeyword",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            may_create_top_level_mailbox: true,
        }
    }
}
