/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use core::cache::CachedDirectory;
use std::{fmt::Debug, sync::Arc};

use ahash::AHashMap;
use backend::{
    imap::{ImapDirectory, ImapError},
    internal::{PrincipalField, PrincipalValue},
    ldap::LdapDirectory,
    memory::MemoryDirectory,
    smtp::SmtpDirectory,
    sql::SqlDirectory,
};
use deadpool::managed::PoolError;
use ldap3::LdapError;
use mail_send::Credentials;
use proc_macros::EnumMethods;
use store::Store;

pub mod backend;
pub mod core;

pub struct Directory {
    pub store: DirectoryInner,
    pub cache: Option<CachedDirectory>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Principal {
    pub(crate) id: u32,
    pub(crate) typ: Type,

    pub(crate) fields: AHashMap<PrincipalField, PrincipalValue>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Type {
    #[serde(rename = "individual")]
    #[default]
    Individual = 0,
    #[serde(rename = "group")]
    Group = 1,
    #[serde(rename = "resource")]
    Resource = 2,
    #[serde(rename = "location")]
    Location = 3,
    #[serde(rename = "list")]
    List = 5,
    #[serde(rename = "other")]
    Other = 6,
    #[serde(rename = "tenant")]
    Tenant = 7,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, EnumMethods,
)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    // Admin
    Impersonate,
    UnlimitedRequests,
    UnlimitedUploads,
    DeleteSystemFolders,
    MessageQueueList,
    MessageQueueGet,
    MessageQueueUpdate,
    MessageQueueDelete,
    OutgoingReportList,
    OutgoingReportGet,
    OutgoingReportDelete,
    IncomingReportList,
    IncomingReportGet,
    IncomingReportDelete,
    SettingsList,
    SettingsUpdate,
    SettingsDelete,
    SettingsReload,
    PrincipalList,
    PrincipalGet,
    PrincipalUpdate,
    PrincipalDelete,
    PrincipalCreate,
    DomainList,
    DomainGet,
    DomainCreate,
    DomainUpdate,
    DomainDelete,
    BlobFetch,
    PurgeBlobStore,
    PurgeDataStore,
    PurgeLookupStore,
    PurgeAccount,
    Undelete,
    DkimSignatureCreate,
    DkimSignatureGet,
    UpdateSpamFilter,
    UpdateWebadmin,
    LogsView,
    SieveRun,
    Restart,
    TracingList,
    TracingGet,
    TracingLive,
    MetricsList,
    MetricsLive,

    // Generic
    Authenticate,
    AuthenticateOauth,

    // Account Management
    ManageEncryption,
    ManagePasswords,

    // JMAP
    JmapEmailGet,
    JmapMailboxGet,
    JmapThreadGet,
    JmapIdentityGet,
    JmapEmailSubmissionGet,
    JmapPushSubscriptionGet,
    JmapSieveScriptGet,
    JmapVacationResponseGet,
    JmapPrincipalGet,
    JmapQuotaGet,
    JmapBlobGet,
    JmapEmailSet,
    JmapMailboxSet,
    JmapIdentitySet,
    JmapEmailSubmissionSet,
    JmapPushSubscriptionSet,
    JmapSieveScriptSet,
    JmapVacationResponseSet,
    JmapEmailChanges,
    JmapMailboxChanges,
    JmapThreadChanges,
    JmapIdentityChanges,
    JmapEmailSubmissionChanges,
    JmapQuotaChanges,
    JmapEmailCopy,
    JmapBlobCopy,
    JmapEmailImport,
    JmapEmailParse,
    JmapEmailQueryChanges,
    JmapMailboxQueryChanges,
    JmapEmailSubmissionQueryChanges,
    JmapSieveScriptQueryChanges,
    JmapPrincipalQueryChanges,
    JmapQuotaQueryChanges,
    JmapEmailQuery,
    JmapMailboxQuery,
    JmapEmailSubmissionQuery,
    JmapSieveScriptQuery,
    JmapPrincipalQuery,
    JmapQuotaQuery,
    JmapSearchSnippet,
    JmapSieveScriptValidate,
    JmapBlobLookup,
    JmapBlobUpload,
    JmapEcho,

    // IMAP
    ImapAuthenticate,
    ImapAclGet,
    ImapAclSet,
    ImapMyRights,
    ImapListRights,
    ImapAppend,
    ImapCapability,
    ImapId,
    ImapCopy,
    ImapMove,
    ImapCreate,
    ImapDelete,
    ImapEnable,
    ImapExpunge,
    ImapFetch,
    ImapIdle,
    ImapList,
    ImapLsub,
    ImapNamespace,
    ImapRename,
    ImapSearch,
    ImapSort,
    ImapSelect,
    ImapExamine,
    ImapStatus,
    ImapStore,
    ImapSubscribe,
    ImapThread,

    // SMTP
    SmtpAuthenticate,

    // POP3
    Pop3Authenticate,
    Pop3List,
    Pop3Uidl,
    Pop3Stat,
    Pop3Retr,
    Pop3Dele,

    // ManageSieve
    SieveAuthenticate,
    SieveListScripts,
    SieveSetActive,
    SieveGetScript,
    SievePutScript,
    SieveDeleteScript,
    SieveRenameScript,
    SieveCheckScript,
    SieveHaveSpace,
}

pub const PERMISSION_BITMAP_SIZE: usize =
    (Permission::COUNT + std::mem::size_of::<usize>() - 1) / std::mem::size_of::<usize>();

pub enum DirectoryInner {
    Internal(Store),
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    Imap(ImapDirectory),
    Smtp(SmtpDirectory),
    Memory(MemoryDirectory),
}

pub enum QueryBy<'x> {
    Name(&'x str),
    Id(u32),
    Credentials(&'x Credentials<String>),
}

impl Default for Directory {
    fn default() -> Self {
        Self {
            store: DirectoryInner::Internal(Store::None),
            cache: None,
        }
    }
}

impl Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory").finish()
    }
}

#[derive(Default, Clone, Debug)]
pub struct Directories {
    pub directories: AHashMap<String, Arc<Directory>>,
}

trait IntoError {
    fn into_error(self) -> trc::Error;
}

impl IntoError for PoolError<LdapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for PoolError<ImapError> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for PoolError<mail_send::Error> {
    fn into_error(self) -> trc::Error {
        match self {
            PoolError::Backend(error) => error.into_error(),
            PoolError::Timeout(_) => trc::StoreEvent::PoolError
                .into_err()
                .details("Connection timed out"),
            err => trc::StoreEvent::PoolError.reason(err),
        }
    }
}

impl IntoError for ImapError {
    fn into_error(self) -> trc::Error {
        trc::ImapEvent::Error.into_err().reason(self)
    }
}

impl IntoError for mail_send::Error {
    fn into_error(self) -> trc::Error {
        trc::SmtpEvent::Error.into_err().reason(self)
    }
}

impl IntoError for LdapError {
    fn into_error(self) -> trc::Error {
        if let LdapError::LdapResult { result } = &self {
            trc::StoreEvent::LdapError
                .ctx(trc::Key::Code, result.rc)
                .reason(self)
        } else {
            trc::StoreEvent::LdapError.reason(self)
        }
    }
}
