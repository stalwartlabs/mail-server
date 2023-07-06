/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Command Line Interface.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use clap::{Parser, Subcommand, ValueEnum};
use mail_parser::DateTime;
use serde::Deserialize;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(name = "stalwart-cli")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
    /// JMAP or SMTP server base URL
    #[clap(short, long)]
    pub url: String,
    /// Authentication credentials
    #[clap(short, long)]
    pub credentials: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Import JMAP accounts and Maildir/mbox mailboxes
    #[clap(subcommand)]
    Import(ImportCommands),

    /// Export JMAP accounts
    #[clap(subcommand)]
    Export(ExportCommands),

    /// Manage JMAP database
    #[clap(subcommand)]
    Database(DatabaseCommands),

    /// Manage SMTP message queue
    #[clap(subcommand)]
    Queue(QueueCommands),

    /// Manage SMTP DMARC/TLS report queue
    #[clap(subcommand)]
    Report(ReportCommands),
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
pub enum DatabaseCommands {
    /// Delete a JMAP account
    Delete {
        /// Account name to delete
        account: String,
    },
    /// Rename a JMAP account
    Rename {
        /// Account name to rename
        account: String,

        /// New account name
        new_account: String,
    },

    /// Purge expired blobs
    Purge {},
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

impl Commands {
    pub fn is_jmap(&self) -> bool {
        !matches!(self, Commands::Queue(_) | Commands::Report(_))
    }
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
