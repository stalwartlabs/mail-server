/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MetricType;

impl MetricType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MessageIngestionTime => "message.ingestion-time",
            Self::MessageFtsIndexTime => "message.fts-index-time",
            Self::DeliveryTotalTime => "delivery.total-time",
            Self::DeliveryTime => "delivery.attempt-time",
            Self::MessageSize => "message.size",
            Self::MessageAuthSize => "message.authenticated-size",
            Self::ReportOutgoingSize => "outgoing-report.size",
            Self::StoreReadTime => "store.data-read-time",
            Self::StoreWriteTime => "store.data-write-time",
            Self::BlobReadTime => "store.blob-read-time",
            Self::BlobWriteTime => "store.blob-write-time",
            Self::DnsLookupTime => "dns.lookup-time",
            Self::HttpRequestTime => "http.request-time",
            Self::ImapRequestTime => "imap.request-time",
            Self::Pop3RequestTime => "pop3.request-time",
            Self::SmtpRequestTime => "smtp.request-time",
            Self::SieveRequestTime => "sieve.request-time",
            Self::HttpActiveConnections => "http.active-connections",
            Self::ImapActiveConnections => "imap.active-connections",
            Self::Pop3ActiveConnections => "pop3.active-connections",
            Self::SmtpActiveConnections => "smtp.active-connections",
            Self::SieveActiveConnections => "sieve.active-connections",
            Self::DeliveryActiveConnections => "delivery.active-connections",
            Self::ServerMemory => "server.memory",
            Self::QueueCount => "queue.count",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::MessageIngestionTime => "Message ingestion time",
            Self::MessageFtsIndexTime => "Message full-text indexing time",
            Self::DeliveryTotalTime => "Total message delivery time from submission to delivery",
            Self::DeliveryTime => "Message delivery time",
            Self::MessageSize => "Received message size",
            Self::MessageAuthSize => "Received message size from authenticated users",
            Self::ReportOutgoingSize => "Outgoing report size",
            Self::StoreReadTime => "Data store read time",
            Self::StoreWriteTime => "Data store write time",
            Self::BlobReadTime => "Blob store read time",
            Self::BlobWriteTime => "Blob store write time",
            Self::DnsLookupTime => "DNS lookup time",
            Self::HttpRequestTime => "HTTP request duration",
            Self::ImapRequestTime => "IMAP request duration",
            Self::Pop3RequestTime => "POP3 request duration",
            Self::SmtpRequestTime => "SMTP request duration",
            Self::SieveRequestTime => "ManageSieve request duration",
            Self::HttpActiveConnections => "Active HTTP connections",
            Self::ImapActiveConnections => "Active IMAP connections",
            Self::Pop3ActiveConnections => "Active POP3 connections",
            Self::SmtpActiveConnections => "Active SMTP connections",
            Self::SieveActiveConnections => "Active ManageSieve connections",
            Self::DeliveryActiveConnections => "Active delivery connections",
            Self::ServerMemory => "Server memory usage",
            Self::QueueCount => "Total number of messages in the queue",
        }
    }

    pub fn unit(&self) -> &'static str {
        match self {
            Self::MessageIngestionTime
            | Self::MessageFtsIndexTime
            | Self::DeliveryTotalTime
            | Self::DeliveryTime
            | Self::StoreReadTime
            | Self::StoreWriteTime
            | Self::BlobReadTime
            | Self::BlobWriteTime
            | Self::DnsLookupTime
            | Self::HttpRequestTime
            | Self::ImapRequestTime
            | Self::Pop3RequestTime
            | Self::SmtpRequestTime
            | Self::SieveRequestTime => "milliseconds",
            Self::MessageSize
            | Self::MessageAuthSize
            | Self::ReportOutgoingSize
            | Self::ServerMemory => "bytes",
            Self::HttpActiveConnections
            | Self::ImapActiveConnections
            | Self::Pop3ActiveConnections
            | Self::SmtpActiveConnections
            | Self::SieveActiveConnections
            | Self::DeliveryActiveConnections => "connections",
            Self::QueueCount => "messages",
        }
    }

    pub fn code(&self) -> u64 {
        match self {
            Self::MessageIngestionTime => 0,
            Self::MessageFtsIndexTime => 1,
            Self::DeliveryTotalTime => 2,
            Self::DeliveryTime => 3,
            Self::MessageSize => 4,
            Self::MessageAuthSize => 5,
            Self::ReportOutgoingSize => 6,
            Self::StoreReadTime => 7,
            Self::StoreWriteTime => 8,
            Self::BlobReadTime => 9,
            Self::BlobWriteTime => 10,
            Self::DnsLookupTime => 11,
            Self::HttpRequestTime => 12,
            Self::ImapRequestTime => 13,
            Self::Pop3RequestTime => 14,
            Self::SmtpRequestTime => 15,
            Self::SieveRequestTime => 16,
            Self::HttpActiveConnections => 17,
            Self::ImapActiveConnections => 18,
            Self::Pop3ActiveConnections => 19,
            Self::SmtpActiveConnections => 20,
            Self::SieveActiveConnections => 21,
            Self::DeliveryActiveConnections => 22,
            Self::ServerMemory => 23,
            Self::QueueCount => 24,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::MessageIngestionTime),
            1 => Some(Self::MessageFtsIndexTime),
            2 => Some(Self::DeliveryTotalTime),
            3 => Some(Self::DeliveryTime),
            4 => Some(Self::MessageSize),
            5 => Some(Self::MessageAuthSize),
            6 => Some(Self::ReportOutgoingSize),
            7 => Some(Self::StoreReadTime),
            8 => Some(Self::StoreWriteTime),
            9 => Some(Self::BlobReadTime),
            10 => Some(Self::BlobWriteTime),
            11 => Some(Self::DnsLookupTime),
            12 => Some(Self::HttpRequestTime),
            13 => Some(Self::ImapRequestTime),
            14 => Some(Self::Pop3RequestTime),
            15 => Some(Self::SmtpRequestTime),
            16 => Some(Self::SieveRequestTime),
            17 => Some(Self::HttpActiveConnections),
            18 => Some(Self::ImapActiveConnections),
            19 => Some(Self::Pop3ActiveConnections),
            20 => Some(Self::SmtpActiveConnections),
            21 => Some(Self::SieveActiveConnections),
            22 => Some(Self::DeliveryActiveConnections),
            23 => Some(Self::ServerMemory),
            24 => Some(Self::QueueCount),
            _ => None,
        }
    }

    pub fn try_parse(name: &str) -> Option<Self> {
        match name {
            "message.ingestion-time" => Some(Self::MessageIngestionTime),
            "message.fts-index-time" => Some(Self::MessageFtsIndexTime),
            "delivery.total-time" => Some(Self::DeliveryTotalTime),
            "delivery.attempt-time" => Some(Self::DeliveryTime),
            "message.size" => Some(Self::MessageSize),
            "message.authenticated-size" => Some(Self::MessageAuthSize),
            "outgoing-report.size" => Some(Self::ReportOutgoingSize),
            "store.data-read-time" => Some(Self::StoreReadTime),
            "store.data-write-time" => Some(Self::StoreWriteTime),
            "store.blob-read-time" => Some(Self::BlobReadTime),
            "store.blob-write-time" => Some(Self::BlobWriteTime),
            "dns.lookup-time" => Some(Self::DnsLookupTime),
            "http.request-time" => Some(Self::HttpRequestTime),
            "imap.request-time" => Some(Self::ImapRequestTime),
            "pop3.request-time" => Some(Self::Pop3RequestTime),
            "smtp.request-time" => Some(Self::SmtpRequestTime),
            "sieve.request-time" => Some(Self::SieveRequestTime),
            "http.active-connections" => Some(Self::HttpActiveConnections),
            "imap.active-connections" => Some(Self::ImapActiveConnections),
            "pop3.active-connections" => Some(Self::Pop3ActiveConnections),
            "smtp.active-connections" => Some(Self::SmtpActiveConnections),
            "sieve.active-connections" => Some(Self::SieveActiveConnections),
            "delivery.active-connections" => Some(Self::DeliveryActiveConnections),
            "server.memory" => Some(Self::ServerMemory),
            "queue.count" => Some(Self::QueueCount),
            _ => None,
        }
    }
}
