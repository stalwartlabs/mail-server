<p align="center">
    <a href="https://stalw.art">
    <img src="./img/logo-red.svg" height="150">
    </a>
</p>

<h3 align="center">
  Secure & Modern All-in-One Mail Server (IMAP, JMAP, POP3, SMTP) 🛡️
</h3>

<br>

<p align="center">
  <a href="https://github.com/stalwartlabs/mail-server/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/stalwartlabs/mail-server/build.yml?style=flat-square" alt="continuous integration"></a>
  &nbsp;
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg?label=license&style=flat-square" alt="License: AGPL v3"></a>
  &nbsp;
  <a href="https://stalw.art/docs/get-started/"><img src="https://img.shields.io/badge/read_the-docs-red?style=flat-square" alt="Documentation"></a>
</p>
<p align="center">
  <a href="https://mastodon.social/@stalwartlabs"><img src="https://img.shields.io/mastodon/follow/109929667531941122?style=flat-square&logo=mastodon&color=%236364ff&label=Follow%20on%20Mastodon" alt="Mastodon"></a>
  &nbsp;
  <a href="https://twitter.com/stalwartlabs"><img src="https://img.shields.io/twitter/follow/stalwartlabs?style=flat-square&logo=x&label=Follow%20on%20Twitter" alt="Twitter"></a>
</p>
<p align="center">
  <a href="https://discord.gg/jtgtCNj66U"><img src="https://img.shields.io/discord/923615863037390889?label=Join%20Discord&logo=discord&style=flat-square" alt="Discord"></a>
  &nbsp;
  <a href="https://www.reddit.com/r/stalwartlabs/"><img src="https://img.shields.io/reddit/subreddit-subscribers/stalwartlabs?label=Join%20%2Fr%2Fstalwartlabs&logo=reddit&style=flat-square" alt="Reddit"></a>
</p>

## Features

**Stalwart Mail Server** is an open-source mail server solution with JMAP, IMAP4, POP3, and SMTP support and a wide range of modern features. It is written in Rust and designed to be secure, fast, robust and scalable.

Key features:

- **JMAP**, **IMAP4**, **POP3** and **ManageSieve** server:
  - [JMAP](https://datatracker.ietf.org/doc/html/rfc8621) server with
   [Sieve Scripts](https://www.ietf.org/archive/id/draft-ietf-jmap-sieve-22.html), [WebSocket](https://datatracker.ietf.org/doc/html/rfc8887), [Blob Management](https://www.rfc-editor.org/rfc/rfc9404.html) and [Quotas](https://www.rfc-editor.org/rfc/rfc9425.html) extensions.
  - [IMAP4rev2](https://datatracker.ietf.org/doc/html/rfc9051) and [IMAP4rev1](https://datatracker.ietf.org/doc/html/rfc3501) server with support for [numerous extensions](https://stalw.art/docs/development/rfcs#imap4-and-extensions).
  - [POP3](https://datatracker.ietf.org/doc/html/rfc1939) server with [extensions](https://datatracker.ietf.org/doc/html/rfc2449), [STLS](https://datatracker.ietf.org/doc/html/rfc2595) and [SASL](https://datatracker.ietf.org/doc/html/rfc5034) support.
  - [ManageSieve](https://datatracker.ietf.org/doc/html/rfc5804) server for managing Sieve scripts.
- **SMTP** server:
  - Built-in [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), [SPF](https://datatracker.ietf.org/doc/html/rfc7208) and [ARC](https://datatracker.ietf.org/doc/html/rfc8617) support for message authentication.
  - Strong transport security through [DANE](https://datatracker.ietf.org/doc/html/rfc6698), [MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461) and [SMTP TLS](https://datatracker.ietf.org/doc/html/rfc8460) reporting.
  - Inbound throttling and filtering with granular configuration rules, sieve scripting, MTA hooks and milter integration.
  - Distributed virtual queues with delayed delivery, priority delivery, quotas, routing rules and throttling support.
  - Envelope rewriting and message modification.
- Built-in **Spam and Phishing** filter:
  - Comprehensive set of filtering **rules** on par with popular solutions.
  - LLM-driven spam filtering and message analysis.
  - Statistical **spam classifier** with automatic training capabilities.
  - DNS Blocklists (**DNSBLs**) checking of IP addresses, domains, and hashes.
  - Collaborative digest-based spam filtering with **Pyzor**.
  - **Phishing** protection against homographic URL attacks, sender spoofing and other techniques.
  - Trusted **reply** tracking to recognize and prioritize genuine e-mail replies.
  - Sender **reputation** monitoring by IP address, ASN, domain and email address.
  - **Greylisting** to temporarily defer unknown senders.
  - **Spam traps** to set up decoy email addresses that catch and analyze spam.
- **Flexible and scalable**:
  - Pluggable storage backends with **RocksDB**, **FoundationDB**, **PostgreSQL**, **mySQL**, **SQLite**, **S3-Compatible**, **Azure**, **Redis** and **ElasticSearch** support.
  - **Clustering** support with node autodiscovery and partition-tolerant failure detection.
  - Full-text search available in 17 languages.
  - Sieve scripting language with support for all [registered extensions](https://www.iana.org/assignments/sieve-extensions/sieve-extensions.xhtml).
  - Email aliases, mailing lists, subaddressing and catch-all addresses support.
  - Automatic account configuration and discovery with [autoconfig](https://www.ietf.org/id/draft-bucksch-autoconfig-02.html) and [autodiscover](https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover?view=exchserver-2019). 
  - Multi-tenancy support with domain and tenant isolation.
  - Disk quotas per user and tenant.
- **Secure and robust**:
  - Encryption at rest with **S/MIME** or **OpenPGP**.
  - Automatic TLS certificate provisioning with [ACME](https://datatracker.ietf.org/doc/html/rfc8555) using `TLS-ALPN-01`, `DNS-01` or `HTTP-01` challenges.
  - Automated blocking of IP addresses that attack, abuse or scan the server for exploits.
  - Rate limiting.
  - Security audited (read the [report](https://stalw.art/blog/security-audit)).
  - Memory safe (thanks to Rust).
- **Authentication and Authorization**:
  - **OpenID Connect** authentication.
  - OAuth 2.0 authorization with [authorization code](https://www.rfc-editor.org/rfc/rfc8628) and [device authorization](https://www.rfc-editor.org/rfc/rfc8628) flows.
  - **LDAP**, **OIDC**, **SQL** or built-in authentication backend support.
  - Two-factor authentication with Time-based One-Time Passwords (`2FA-TOTP`) 
  - Application passwords (App Passwords).
  - Roles and permissions.
  - Access Control Lists (ACLs).
- **Observability**:
  - Logging and tracing with **OpenTelemetry**, journald, log files and console support.
  - Metrics with **OpenTelemetry** and **Prometheus** integration.
  - Webhooks for event-driven automation.
  - Alerts with email and webhook notifications.
  - Live tracing and metrics.
- **Web-based administration**:
  - Dashboard with real-time statistics and monitoring.
  - Account, domain, group and mailing list management.
  - SMTP queue management for messages and outbound DMARC and TLS reports.
  - Report visualization interface for received DMARC, TLS-RPT and Failure (ARF) reports.
  - Configuration of every aspect of the mail server.
  - Log viewer with search and filtering capabilities.
  - Self-service portal for password reset and encryption-at-rest key management.

## Screenshots

<img src="./img/screencast-setup.gif">

## Get Started

Install Stalwart Mail Server on your server by following the instructions for your platform:

- [Linux / MacOS](https://stalw.art/docs/install/linux)
- [Windows](https://stalw.art/docs/install/windows)
- [Docker](https://stalw.art/docs/install/docker)

All documentation is available at [stalw.art/docs/get-started](https://stalw.art/docs/get-started).

## Support

If you are having problems running Stalwart Mail Server, you found a bug or just have a question,
do not hesitate to reach us on [GitHub Discussions](https://github.com/stalwartlabs/mail-server/discussions),
[Reddit](https://www.reddit.com/r/stalwartlabs) or [Discord](https://discord.gg/aVQr3jF8jd).
Additionally you may purchase an [premium support](https://stalw.art/support) to obtain priority support from Stalwart Labs LLC.

## Sponsorship

Your support is crucial in helping us continue to improve the project, add new features, and maintain the highest level of quality. By becoming a sponsor on [Open Collective](https://opencollective.com/stalwart), you help fund the development and future of Stalwart Mail Server. As a thank-you, sponsors who contribute $10 per month or more will automatically receive a [Small Business Edition](https://stalw.art/small-business/) license, which includes all the powerful features of the [Enterprise edition](https://stalw.art/enterprise/).

These are some of our open-source sponsors:

<!-- sponsors --><a href="https://github.com/kbjr"><img src="https:&#x2F;&#x2F;github.com&#x2F;kbjr.png" width="60px" alt="User avatar: James Brumond" /></a><a href="https://github.com/EliRibble"><img src="https:&#x2F;&#x2F;github.com&#x2F;EliRibble.png" width="60px" alt="User avatar: Eli Ribble" /></a><a href="https://github.com/MailRoute"><img src="https:&#x2F;&#x2F;github.com&#x2F;MailRoute.png" width="60px" alt="User avatar: MailRoute, Inc." /></a><a href="https://github.com/JAMflow-Cloud"><img src="https:&#x2F;&#x2F;github.com&#x2F;JAMflow-Cloud.png" width="60px" alt="User avatar: JAMflow Cloud" /></a><a href="https://github.com/starsong-consulting"><img src="https:&#x2F;&#x2F;github.com&#x2F;starsong-consulting.png" width="60px" alt="User avatar: Starsong GmbH" /></a><a href="https://github.com/Vie-eco"><img src="https:&#x2F;&#x2F;github.com&#x2F;Vie-eco.png" width="60px" alt="User avatar: Vie.eco" /></a><a href="https://github.com/mingfu-design"><img src="https:&#x2F;&#x2F;github.com&#x2F;mingfu-design.png" width="60px" alt="User avatar: Ming Fu Design Ltd. 明孚設計有限公司" /></a><a href="https://github.com/tamwuff"><img src="https:&#x2F;&#x2F;github.com&#x2F;tamwuff.png" width="60px" alt="User avatar: Tamino" /></a><!-- sponsors -->

<br/>If you would like to support our work, please consider [becoming a sponsor](https://opencollective.com/stalwart).

## Roadmap

- [ ] CalDAV, CardDAV and WebDAV support
- [ ] JMAP Calendar, Contacts and Tasks support
- [ ] ActiveSync support

See the [enhancement requests](https://github.com/stalwartlabs/mail-server/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc+label%3Aenhancement) page for a full list of proposed features by the community.

## Funding

Part of the development of this project was funded through the [NGI0 Entrust Fund](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 101069594.

If you find the project useful you can help by [becoming a sponsor](https://opencollective.com/stalwart). Thank you!

## License

This project is dual-licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0; as published by the Free Software Foundation) and the **Stalwart Enterprise License v1 (SELv1)**:

- The [GNU Affero General Public License v3.0](./LICENSES/AGPL-3.0-only.txt) is a free software license that ensures your freedom to use, modify, and distribute the software, with the condition that any modified versions of the software must also be distributed under the same license. 
- The [Stalwart Enterprise License v1 (SELv1)](./LICENSES/LicenseRef-SEL.txt) is a proprietary license designed for commercial use. It offers additional features and greater flexibility for businesses that do not wish to comply with the AGPL-3.0 license requirements. 

Each file in this project contains a license notice at the top, indicating the applicable license(s). The license notice follows the [REUSE guidelines](https://reuse.software/) to ensure clarity and consistency. The full text of each license is available in the [LICENSES](./LICENSES/) directory.

## Copyright

Copyright (C) 2024, Stalwart Labs Ltd.
