/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use clap::{Parser, Subcommand, ValueEnum};
use jmap_client::client::Credentials;
use mail_parser::DateTime;
use serde::Deserialize;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(name = "stalwart-cli")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
    /// Server base URL
    #[clap(short, long)]
    pub url: Option<String>,
    /// Authentication credentials
    #[clap(short, long)]
    pub credentials: Option<String>,
    /// Connection timeout in seconds
    #[clap(short, long)]
    pub timeout: Option<u64>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage user accounts
    #[clap(subcommand)]
    Account(AccountCommands),

    /// Manage domains
    #[clap(subcommand)]
    Domain(DomainCommands),

    /// Manage mailing lists
    #[clap(subcommand)]
    List(ListCommands),

    /// Manage groups
    #[clap(subcommand)]
    Group(GroupCommands),

    /// Import JMAP accounts and Maildir/mbox mailboxes
    #[clap(subcommand)]
    Import(ImportCommands),

    /// Export JMAP accounts
    #[clap(subcommand)]
    Export(ExportCommands),

    /// Manage JMAP database
    #[clap(subcommand)]
    Server(ServerCommands),

    /// Manage SMTP message queue
    #[clap(subcommand)]
    Queue(QueueCommands),

    /// Manage SMTP DMARC/TLS report queue
    #[clap(subcommand)]
    Report(ReportCommands),
}

pub struct Client {
    pub url: String,
    pub credentials: Credentials,
    pub timeout: Option<u64>,
}

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Create a new user account
    Create {
        /// Login Name
        name: String,
        /// Password
        password: String,
        /// Account description
        #[clap(short, long)]
        description: Option<String>,
        /// Quota in bytes
        #[clap(short, long)]
        quota: Option<u32>,
        /// Whether the account is an administrator
        #[clap(short, long)]
        is_admin: Option<bool>,
        /// E-mail addresses
        #[clap(short, long)]
        addresses: Option<Vec<String>>,
        /// Groups this account is a member of
        #[clap(short, long)]
        member_of: Option<Vec<String>>,
    },

    /// Update an existing user account
    Update {
        /// Account login
        name: String,
        /// Rename account login
        #[clap(short, long)]
        new_name: Option<String>,
        /// Update password
        #[clap(short, long)]
        password: Option<String>,
        /// Update account description
        #[clap(short, long)]
        description: Option<String>,
        /// Update quota in bytes
        #[clap(short, long)]
        quota: Option<u64>,
        /// Whether the account is an administrator
        #[clap(short, long)]
        is_admin: Option<bool>,
        /// Update e-mail addresses
        #[clap(short, long)]
        addresses: Option<Vec<String>>,
        /// Update groups this account is a member of
        #[clap(short, long)]
        member_of: Option<Vec<String>>,
    },

    /// Add e-mail aliases to a user account
    AddEmail {
        /// Account login
        name: String,
        /// E-mail aliases to add
        #[clap(required = true)]
        addresses: Vec<String>,
    },

    /// Remove e-mail aliases to a user account
    RemoveEmail {
        /// Account login
        name: String,
        /// E-mail aliases to remove
        #[clap(required = true)]
        addresses: Vec<String>,
    },

    /// Add a user account to groups
    AddToGroup {
        /// Account login
        name: String,
        /// Groups to add
        #[clap(required = true)]
        member_of: Vec<String>,
    },

    /// Remove a user account from groups
    RemoveFromGroup {
        /// Account login
        name: String,
        /// Groups to remove
        #[clap(required = true)]
        member_of: Vec<String>,
    },

    /// Delete an existing user account
    Delete {
        /// Account name to delete
        name: String,
    },

    /// Display an existing user account
    Display {
        /// Account name to display
        name: String,
    },

    /// List all user accounts
    List {
        /// Filter accounts by keywords
        filter: Option<String>,
        /// Maximum number of accounts to list
        limit: Option<usize>,
        /// Page number
        page: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum ListCommands {
    /// Create a new mailing list
    Create {
        /// List Name
        name: String,
        /// List email address
        email: String,
        /// Description
        #[clap(short, long)]
        description: Option<String>,
        /// Mailing list members
        #[clap(short, long)]
        members: Option<Vec<String>>,
    },

    /// Update an existing mailing list
    Update {
        /// List Name
        name: String,
        /// Rename list
        new_name: Option<String>,
        /// List email address
        email: Option<String>,
        /// Description
        #[clap(short, long)]
        description: Option<String>,
        /// Mailing list members
        #[clap(short, long)]
        members: Option<Vec<String>>,
    },

    /// Add members to a mailing list
    AddMembers {
        /// List Name
        name: String,
        /// Members to add
        #[clap(required = true)]
        members: Vec<String>,
    },

    /// Remove members from a mailing list
    RemoveMembers {
        /// List Name
        name: String,
        /// Members to remove
        #[clap(required = true)]
        members: Vec<String>,
    },

    /// Display an existing mailing list
    Display {
        /// Mailing list to display
        name: String,
    },

    /// List all mailing lists
    List {
        /// Filter mailing lists by keywords
        filter: Option<String>,
        /// Maximum number of mailing lists to list
        limit: Option<usize>,
        /// Page number
        page: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum GroupCommands {
    /// Create a group
    Create {
        /// Group Name
        name: String,
        /// Group email address
        email: Option<String>,
        /// Description
        #[clap(short, long)]
        description: Option<String>,
        /// Group members
        #[clap(short, long)]
        members: Option<Vec<String>>,
    },

    /// Update an existing group
    Update {
        /// Group Name
        name: String,
        /// Rename group
        new_name: Option<String>,
        /// Group email address
        email: Option<String>,
        /// Description
        #[clap(short, long)]
        description: Option<String>,
        /// Update groups that this group is a member of
        #[clap(short, long)]
        members: Option<Vec<String>>,
    },

    /// Add members to a group
    AddMembers {
        /// Group name
        name: String,
        /// Groups to add
        #[clap(required = true)]
        members: Vec<String>,
    },

    /// Remove members from a group
    RemoveMembers {
        /// Group name
        name: String,
        /// Groups to remove
        #[clap(required = true)]
        members: Vec<String>,
    },

    /// Display an existing group
    Display {
        /// Group name to display
        name: String,
    },

    /// List all groups
    List {
        /// Filter groups by keywords
        filter: Option<String>,
        /// Maximum number of groups to list
        limit: Option<usize>,
        /// Page number
        page: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum DomainCommands {
    /// Create a new domain
    Create {
        /// Domain name to create
        name: String,
    },

    /// Delete an existing domain
    Delete {
        /// Domain name to delete
        name: String,
    },

    /// List all domains
    List {
        /// Starting point for listing domains
        from: Option<String>,
        /// Maximum number of domains to list
        limit: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum ImportCommands {
    /// Import messages and folders
    Messages {
        #[clap(value_enum)]
        #[clap(short, long)]
        format: MailboxFormat,

        /// Number of messages to import concurrently, defaults to the number of CPUs.
        #[clap(short, long)]
        num_concurrent: Option<usize>,

        /// Account name or email to import messages into
        account: String,

        /// Path to the mailbox to import, or '-' for stdin (stdin only supported for mbox)
        path: String,
    },
    /// Import a JMAP account
    Account {
        /// Number of concurrent requests, defaults to the number of CPUs.
        #[clap(short, long)]
        num_concurrent: Option<usize>,

        /// Account name or email to import messages into
        account: String,

        /// Path to the exported account directory
        path: String,
    },
}

#[derive(Subcommand)]
pub enum ExportCommands {
    /// Export a JMAP account
    Account {
        /// Number of concurrent blob downloads to perform, defaults to the number of CPUs.
        #[clap(short, long)]
        num_concurrent: Option<usize>,

        /// Account name or email to import messages into
        account: String,

        /// Path to export the account to
        path: String,
    },
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Perform database maintenance
    DatabaseMaintenance {},

    /// Reload TLS certificates
    ReloadCertificates {},

    /// Reload configuration
    ReloadConfig {},

    /// Create a new configuration key
    AddConfig {
        /// Key to add
        key: String,
        /// Value to set
        value: Option<String>,
    },

    /// Delete a configuration key or prefix
    DeleteConfig {
        /// Configuration key or prefix to delete
        key: String,
    },

    /// List all configuration entries
    ListConfig {
        /// Prefix to filter configuration entries by
        prefix: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum MailboxFormat {
    /// Mbox format
    Mbox,
    /// Maildir and Maildir++ formats
    Maildir,
    /// Maildir with hierarchical folders (i.e. Dovecot)
    MaildirNested,
}

#[derive(Subcommand)]
pub enum QueueCommands {
    /// Shows messages queued for delivery
    List {
        /// Filter by sender address
        #[clap(short, long)]
        sender: Option<String>,
        /// Filter by recipient
        #[clap(short, long)]
        rcpt: Option<String>,
        /// Filter messages due for delivery before a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        before: Option<DateTime>,
        /// Filter messages due for delivery after a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        after: Option<DateTime>,
        /// Number of items to show per page
        #[clap(short, long)]
        page_size: Option<usize>,
    },

    /// Displays details about a queued message
    Status {
        #[clap(required = true)]
        ids: Vec<String>,
    },

    /// Reschedule delivery
    Retry {
        /// Apply to messages matching a sender address
        #[clap(short, long)]
        sender: Option<String>,
        /// Apply to a specific domain
        #[clap(short, long)]
        domain: Option<String>,
        /// Apply to messages due before a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        before: Option<DateTime>,
        /// Apply to messages due after a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        after: Option<DateTime>,
        /// Schedule delivery at a specific time
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        time: Option<DateTime>,
        // Reschedule one or multiple message ids
        ids: Vec<String>,
    },

    /// Cancel delivery
    Cancel {
        /// Apply to messages matching a sender address
        #[clap(short, long)]
        sender: Option<String>,
        /// Apply to specific recipients or domains
        #[clap(short, long)]
        rcpt: Option<String>,
        /// Apply to messages due before a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        before: Option<DateTime>,
        /// Apply to messages due after a certain datetime
        #[clap(short, long)]
        #[arg(value_parser = parse_datetime)]
        after: Option<DateTime>,
        // Cancel one or multiple message ids
        ids: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum ReportCommands {
    /// Shows reports queued for delivery
    List {
        /// Filter by report domain
        #[clap(short, long)]
        domain: Option<String>,
        /// Filter by report type
        #[clap(short, long)]
        #[clap(value_enum)]
        format: Option<ReportFormat>,
        /// Number of items to show per page
        #[clap(short, long)]
        page_size: Option<usize>,
    },

    /// Displays details about a queued report
    Status {
        #[clap(required = true)]
        ids: Vec<String>,
    },

    /// Cancel report delivery
    Cancel {
        #[clap(required = true)]
        ids: Vec<String>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Deserialize)]
pub enum ReportFormat {
    /// DMARC report
    #[serde(rename = "dmarc")]
    Dmarc,
    /// TLS report
    #[serde(rename = "tls")]
    Tls,
}

fn parse_datetime(arg: &str) -> Result<DateTime, &'static str> {
    if arg.contains('T') {
        DateTime::parse_rfc3339(arg).ok_or("Failed to parse RFC3339 datetime")
    } else {
        DateTime::parse_rfc3339(&format!("{arg}T00:00:00Z"))
            .ok_or("Failed to parse RFC3339 datetime")
    }
}
