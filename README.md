# Stalwart Mail Server

[![Test](https://github.com/stalwartlabs/mail-server/actions/workflows/test.yml/badge.svg)](https://github.com/stalwartlabs/mail-server/actions/workflows/test.yml)
[![Build](https://github.com/stalwartlabs/mail-server/actions/workflows/build.yml/badge.svg)](https://github.com/stalwartlabs/mail-server/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![](https://img.shields.io/discord/923615863037390889?label=Chat)](https://discord.gg/jtgtCNj66U)
[![](https://img.shields.io/twitter/follow/stalwartlabs?style=flat)](https://twitter.com/stalwartlabs)

**Stalwart Mail Server** is an open-source mail server solution with JMAP, IMAP4, and SMTP support and a wide range of modern features. It is written in Rust and designed to be secure, fast, robust and scalable.

_Caveat emptor_: This repository is currently under active development and is not yet ready for production use. Please refer to the JMAP, IMAP and SMTP repositories if you would like to 
try each of these servers individually:

* [Stalwart JMAP Server](https://github.com/stalwartlabs/jmap-server/)
* [Stalwart IMAP Server](https://github.com/stalwartlabs/imap-server/)
* [Stalwart SMTP Server](https://github.com/stalwartlabs/smtp-server/)

## Why choose Stalwart?

Within the field of mail servers, established names like Postfix, Courier and Dovecot have long been the go-to solutions. However, the landscape of internet messaging is evolving, with a need for more efficient, easy to maintain, reliable, and secure systems. Here's why you might consider making the switch to Stalwart Mail Server:

- Designed with the latest internet messaging protocols in mind - JMAP and IMAP4rev2, along with the conventional SMTP. 
- Leverages the performance and security benefits of the Rust programming language. This statically typed, compiled language is known for its memory safety and concurrency support, reducing the likelihood of typical security issues like buffer overflows.
- Thanks to its native FoundationDB and S3 storage support, it can be scaled across many servers, accommodating millions of users.
- Available as a single, integrated package that includes JMAP, IMAP, and SMTP servers. This means that you don't have to install, configure and maintain multiple servers to get a complete solution.
- Designed to be easy to install and maintain, with a single configuration file and a simple command-line interface.

## License

Licensed under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html) as published by
the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
See [LICENSE](LICENSE) for more details.

You can be released from the requirements of the AGPLv3 license by purchasing
a commercial license. Please contact licensing@stalw.art for more details.
  
## Copyright

Copyright (C) 2020, Stalwart Labs Ltd.
