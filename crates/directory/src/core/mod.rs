/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Permission;

pub mod cache;
pub mod config;
pub mod dispatch;
pub mod principal;
pub mod secret;

impl Permission {
    pub fn description(&self) -> &'static str {
        match self {
            Permission::Impersonate => "Act on behalf of another user",
            Permission::UnlimitedRequests => "Perform unlimited requests",
            Permission::UnlimitedUploads => "Upload unlimited data",
            Permission::DeleteSystemFolders => "Delete of system folders",
            Permission::MessageQueueList => "View message queue",
            Permission::MessageQueueGet => "Retrieve specific messages from the queue",
            Permission::MessageQueueUpdate => "Modify queued messages",
            Permission::MessageQueueDelete => "Remove messages from the queue",
            Permission::OutgoingReportList => "View outgoing DMARC and TLS reports",
            Permission::OutgoingReportGet => "Retrieve specific outgoing DMARC and TLS reports",
            Permission::OutgoingReportDelete => "Remove outgoing DMARC and TLS reports",
            Permission::IncomingReportList => "View incoming DMARC, TLS and ARF reports",
            Permission::IncomingReportGet => {
                "Retrieve specific incoming DMARC, TLS and ARF reports"
            }
            Permission::IncomingReportDelete => "Remove incoming DMARC, TLS and ARF reports",
            Permission::SettingsList => "View system settings",
            Permission::SettingsUpdate => "Modify system settings",
            Permission::SettingsDelete => "Remove system settings",
            Permission::SettingsReload => "Refresh system settings",
            Permission::IndividualList => "View list of user accounts",
            Permission::IndividualGet => "Retrieve specific account information",
            Permission::IndividualUpdate => "Modify user account information",
            Permission::IndividualDelete => "Remove user accounts",
            Permission::IndividualCreate => "Add new user accounts",
            Permission::GroupList => "View list of user groups",
            Permission::GroupGet => "Retrieve specific group information",
            Permission::GroupUpdate => "Modify group information",
            Permission::GroupDelete => "Remove user groups",
            Permission::GroupCreate => "Add new user groups",
            Permission::DomainList => "View list of email domains",
            Permission::DomainGet => "Retrieve specific domain information",
            Permission::DomainCreate => "Add new email domains",
            Permission::DomainUpdate => "Modify domain information",
            Permission::DomainDelete => "Remove email domains",
            Permission::TenantList => "View list of tenants",
            Permission::TenantGet => "Retrieve specific tenant information",
            Permission::TenantCreate => "Add new tenants",
            Permission::TenantUpdate => "Modify tenant information",
            Permission::TenantDelete => "Remove tenants",
            Permission::MailingListList => "View list of mailing lists",
            Permission::MailingListGet => "Retrieve specific mailing list information",
            Permission::MailingListCreate => "Create new mailing lists",
            Permission::MailingListUpdate => "Modify mailing list information",
            Permission::MailingListDelete => "Remove mailing lists",
            Permission::RoleList => "View list of roles",
            Permission::RoleGet => "Retrieve specific role information",
            Permission::RoleCreate => "Create new roles",
            Permission::RoleUpdate => "Modify role information",
            Permission::RoleDelete => "Remove roles",
            Permission::PrincipalList => "View list of principals",
            Permission::PrincipalGet => "Retrieve specific principal information",
            Permission::PrincipalCreate => "Create new principals",
            Permission::PrincipalUpdate => "Modify principal information",
            Permission::PrincipalDelete => "Remove principals",
            Permission::BlobFetch => "Retrieve arbitrary blobs",
            Permission::PurgeBlobStore => "Purge the blob storage",
            Permission::PurgeDataStore => "Purge the data storage",
            Permission::PurgeInMemoryStore => "Purge the in-memory storage",
            Permission::PurgeAccount => "Purge user accounts",
            Permission::FtsReindex => "Rebuild the full-text search index",
            Permission::Undelete => "Restore deleted items",
            Permission::DkimSignatureCreate => "Create DKIM signatures for email authentication",
            Permission::DkimSignatureGet => "Retrieve DKIM signature information",
            Permission::SpamFilterUpdate => "Modify spam filter settings",
            Permission::WebadminUpdate => "Modify web admin interface settings",
            Permission::LogsView => "Access system logs",
            Permission::SpamFilterTrain => "Train the spam filter",
            Permission::SpamFilterClassify => "Classify emails with the spam filter",
            Permission::Restart => "Restart the email server",
            Permission::TracingList => "View stored traces",
            Permission::TracingGet => "Retrieve specific trace information",
            Permission::TracingLive => "Perform real-time tracing",
            Permission::MetricsList => "View stored metrics",
            Permission::MetricsLive => "View real-time metrics",
            Permission::Authenticate => "Authenticate",
            Permission::AuthenticateOauth => "Authenticate via OAuth",
            Permission::EmailSend => "Send emails",
            Permission::EmailReceive => "Receive emails",
            Permission::ManageEncryption => "Manage encryption-at-rest settings",
            Permission::ManagePasswords => "Manage account passwords",
            Permission::JmapEmailGet => "Retrieve emails via JMAP",
            Permission::JmapMailboxGet => "Retrieve mailboxes via JMAP",
            Permission::JmapThreadGet => "Retrieve email threads via JMAP",
            Permission::JmapIdentityGet => "Retrieve user identities via JMAP",
            Permission::JmapEmailSubmissionGet => "Retrieve email submission info via JMAP",
            Permission::JmapPushSubscriptionGet => "Retrieve push subscriptions via JMAP",
            Permission::JmapSieveScriptGet => "Retrieve Sieve scripts via JMAP",
            Permission::JmapVacationResponseGet => "Retrieve vacation responses via JMAP",
            Permission::JmapPrincipalGet => "Retrieve principal information via JMAP",
            Permission::JmapQuotaGet => "Retrieve quota information via JMAP",
            Permission::JmapBlobGet => "Retrieve blobs via JMAP",
            Permission::JmapEmailSet => "Modify emails via JMAP",
            Permission::JmapMailboxSet => "Modify mailboxes via JMAP",
            Permission::JmapIdentitySet => "Modify user identities via JMAP",
            Permission::JmapEmailSubmissionSet => "Modify email submission settings via JMAP",
            Permission::JmapPushSubscriptionSet => "Modify push subscriptions via JMAP",
            Permission::JmapSieveScriptSet => "Modify Sieve scripts via JMAP",
            Permission::JmapVacationResponseSet => "Modify vacation responses via JMAP",
            Permission::JmapEmailChanges => "Track email changes via JMAP",
            Permission::JmapMailboxChanges => "Track mailbox changes via JMAP",
            Permission::JmapThreadChanges => "Track thread changes via JMAP",
            Permission::JmapIdentityChanges => "Track identity changes via JMAP",
            Permission::JmapEmailSubmissionChanges => "Track email submission changes via JMAP",
            Permission::JmapQuotaChanges => "Track quota changes via JMAP",
            Permission::JmapEmailCopy => "Copy emails via JMAP",
            Permission::JmapBlobCopy => "Copy blobs via JMAP",
            Permission::JmapEmailImport => "Import emails via JMAP",
            Permission::JmapEmailParse => "Parse emails via JMAP",
            Permission::JmapEmailQueryChanges => "Track email query changes via JMAP",
            Permission::JmapMailboxQueryChanges => "Track mailbox query changes via JMAP",
            Permission::JmapEmailSubmissionQueryChanges => {
                "Track email submission query changes via JMAP"
            }
            Permission::JmapSieveScriptQueryChanges => "Track Sieve script query changes via JMAP",
            Permission::JmapPrincipalQueryChanges => "Track principal query changes via JMAP",
            Permission::JmapQuotaQueryChanges => "Track quota query changes via JMAP",
            Permission::JmapEmailQuery => "Perform email queries via JMAP",
            Permission::JmapMailboxQuery => "Perform mailbox queries via JMAP",
            Permission::JmapEmailSubmissionQuery => "Perform email submission queries via JMAP",
            Permission::JmapSieveScriptQuery => "Perform Sieve script queries via JMAP",
            Permission::JmapPrincipalQuery => "Perform principal queries via JMAP",
            Permission::JmapQuotaQuery => "Perform quota queries via JMAP",
            Permission::JmapSearchSnippet => "Retrieve search snippets via JMAP",
            Permission::JmapSieveScriptValidate => "Validate Sieve scripts via JMAP",
            Permission::JmapBlobLookup => "Look up blobs via JMAP",
            Permission::JmapBlobUpload => "Upload blobs via JMAP",
            Permission::JmapEcho => "Perform JMAP echo requests",
            Permission::ImapAuthenticate => "Authenticate via IMAP",
            Permission::ImapAclGet => "Retrieve ACLs via IMAP",
            Permission::ImapAclSet => "Set ACLs via IMAP",
            Permission::ImapMyRights => "Retrieve own rights via IMAP",
            Permission::ImapListRights => "List rights via IMAP",
            Permission::ImapAppend => "Append messages via IMAP",
            Permission::ImapCapability => "Retrieve server capabilities via IMAP",
            Permission::ImapId => "Retrieve server ID via IMAP",
            Permission::ImapCopy => "Copy messages via IMAP",
            Permission::ImapMove => "Move messages via IMAP",
            Permission::ImapCreate => "Create mailboxes via IMAP",
            Permission::ImapDelete => "Delete mailboxes or messages via IMAP",
            Permission::ImapEnable => "Enable IMAP extensions",
            Permission::ImapExpunge => "Expunge deleted messages via IMAP",
            Permission::ImapFetch => "Fetch messages or metadata via IMAP",
            Permission::ImapIdle => "Use IMAP IDLE command",
            Permission::ImapList => "List mailboxes via IMAP",
            Permission::ImapLsub => "List subscribed mailboxes via IMAP",
            Permission::ImapNamespace => "Retrieve namespaces via IMAP",
            Permission::ImapRename => "Rename mailboxes via IMAP",
            Permission::ImapSearch => "Search messages via IMAP",
            Permission::ImapSort => "Sort messages via IMAP",
            Permission::ImapSelect => "Select mailboxes via IMAP",
            Permission::ImapExamine => "Examine mailboxes via IMAP",
            Permission::ImapStatus => "Retrieve mailbox status via IMAP",
            Permission::ImapStore => "Modify message flags via IMAP",
            Permission::ImapSubscribe => "Subscribe to mailboxes via IMAP",
            Permission::ImapThread => "Thread messages via IMAP",
            Permission::Pop3Authenticate => "Authenticate via POP3",
            Permission::Pop3List => "List messages via POP3",
            Permission::Pop3Uidl => "Retrieve unique IDs via POP3",
            Permission::Pop3Stat => "Retrieve mailbox statistics via POP3",
            Permission::Pop3Retr => "Retrieve messages via POP3",
            Permission::Pop3Dele => "Mark messages for deletion via POP3",
            Permission::SieveAuthenticate => "Authenticate for Sieve script management",
            Permission::SieveListScripts => "List Sieve scripts",
            Permission::SieveSetActive => "Set active Sieve script",
            Permission::SieveGetScript => "Retrieve Sieve scripts",
            Permission::SievePutScript => "Upload Sieve scripts",
            Permission::SieveDeleteScript => "Delete Sieve scripts",
            Permission::SieveRenameScript => "Rename Sieve scripts",
            Permission::SieveCheckScript => "Validate Sieve scripts",
            Permission::SieveHaveSpace => "Check available space for Sieve scripts",
            Permission::OauthClientRegistration => "Register OAuth clients",
            Permission::OauthClientOverride => "Override OAuth client settings",
            Permission::ApiKeyList => "View API keys",
            Permission::ApiKeyGet => "Retrieve specific API keys",
            Permission::ApiKeyCreate => "Create new API keys",
            Permission::ApiKeyUpdate => "Modify API keys",
            Permission::ApiKeyDelete => "Remove API keys",
            Permission::OauthClientList => "View OAuth clients",
            Permission::OauthClientGet => "Retrieve specific OAuth clients",
            Permission::OauthClientCreate => "Create new OAuth clients",
            Permission::OauthClientUpdate => "Modify OAuth clients",
            Permission::OauthClientDelete => "Remove OAuth clients",
            Permission::AiModelInteract => "Interact with AI models",
            Permission::Troubleshoot => "Perform troubleshooting",
            Permission::DavSyncCollection => "Synchronize collection changes with client",
            Permission::DavPrincipalAcl => "Set principal properties for access control",
            Permission::DavPrincipalMatch => "Match principals based on specified criteria",
            Permission::DavPrincipalSearch => "Search for principals by property values",
            Permission::DavPrincipalSearchPropSet => "Define property sets for principal searches",
            Permission::DavExpandProperty => "Expand properties that reference other resources",
            Permission::DavPrincipalList => "List available principals in the system",
            Permission::DavFilePropFind => "Retrieve properties of file resources",
            Permission::DavFilePropPatch => "Modify properties of file resources",
            Permission::DavFileGet => "Download file resources",
            Permission::DavFileMkCol => "Create new file collections or directories",
            Permission::DavFileDelete => "Remove file resources",
            Permission::DavFilePut => "Upload or modify file resources",
            Permission::DavFileCopy => "Copy file resources to new locations",
            Permission::DavFileMove => "Move file resources to new locations",
            Permission::DavFileLock => "Lock file resources to prevent concurrent modifications",
            Permission::DavFileAcl => "Manage access control lists for file resources",
            Permission::DavCardPropFind => "Retrieve properties of address book entries",
            Permission::DavCardPropPatch => "Modify properties of address book entries",
            Permission::DavCardGet => "Download address book entries",
            Permission::DavCardMkCol => "Create new address book collections",
            Permission::DavCardDelete => "Remove address book entries or collections",
            Permission::DavCardPut => "Upload or modify address book entries",
            Permission::DavCardCopy => "Copy address book entries to new locations",
            Permission::DavCardMove => "Move address book entries to new locations",
            Permission::DavCardLock => {
                "Lock address book entries to prevent concurrent modifications"
            }
            Permission::DavCardAcl => "Manage access control lists for address book entries",
            Permission::DavCardQuery => "Search for address book entries matching criteria",
            Permission::DavCardMultiGet => {
                "Retrieve multiple address book entries in a single request"
            }
            Permission::DavCalPropFind => "Retrieve properties of calendar entries",
            Permission::DavCalPropPatch => "Modify properties of calendar entries",
            Permission::DavCalGet => "Download calendar entries",
            Permission::DavCalMkCol => "Create new calendar collections",
            Permission::DavCalDelete => "Remove calendar entries or collections",
            Permission::DavCalPut => "Upload or modify calendar entries",
            Permission::DavCalCopy => "Copy calendar entries to new locations",
            Permission::DavCalMove => "Move calendar entries to new locations",
            Permission::DavCalLock => "Lock calendar entries to prevent concurrent modifications",
            Permission::DavCalAcl => "Manage access control lists for calendar entries",
            Permission::DavCalQuery => "Search for calendar entries matching criteria",
            Permission::DavCalMultiGet => "Retrieve multiple calendar entries in a single request",
            Permission::DavCalFreeBusyQuery => "Query free/busy time information for scheduling",
            Permission::CalendarAlarms => "Receive calendar alarms via e-mail",
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Permission;

    #[test]
    #[ignore]
    fn print_permissions() {
        const CHECK: &str = ":white_check_mark:";

        let mut permissions = Permission::all().collect::<Vec<_>>();
        permissions.sort_by(|a, b| a.name().cmp(b.name()));

        for permission in permissions {
            println!(
                "|`{}`|{}|{}|{}|{}|",
                permission.name(),
                permission.description(),
                CHECK,
                permission
                    .is_tenant_admin_permission()
                    .then_some(CHECK)
                    .unwrap_or_default(),
                permission
                    .is_user_permission()
                    .then_some(CHECK)
                    .unwrap_or_default()
            );
            //println!("({:?},{:?}),", permission.name(), permission.description(),);
        }
    }
}
