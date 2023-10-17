# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [0.3.10] - 2023-10-17

## Added
- Option to allow invalid certificates on outbound SMTP connections.
- Option to disable ansi colors on `stdout`.

### Changed
- SMTP reject messages are now logged as `info` rather than `debug`.

### Fixed

## [0.3.9] - 2023-10-07

## Added
- Support for reading environment variables from the configuration file using the `!ENV_VAR_NAME` special keyword.
- Option to disable ANSI color codes in logs.

### Changed
- Querying directories from a Sieve script is now done using the `query()` method from `eval`. Your scripts will need to be updated, please refer to the [new syntax](https://stalw.art/docs/smtp/filter/sieve#directory-queries).

### Fixed
- IPrev lookups of IPv4 mapped to IPv6 addresses.

## [0.3.8] - 2023-09-19

## Added
- Journal logging support
- IMAP support for UTF8 APPEND

### Changed
- Replaced `rpgp` with `sequoia-pgp` due to rpgp bug.

### Fixed
- Fix: IMAP folders that contain a & can't be used (#90) 
- Fix: Ignore empty lines in IMAP requests

## [0.3.7] - 2023-09-05

## Added
- Option to disable IMAP All Messages folder (#68).
- Option to allow unencrypted SMTP AUTH (#72)
- Support for `rcpt-domain` key in `rcpt.relay` SMTP rule evaluation.

### Changed
 
### Fixed
- SMTP strategy `Ipv6thenIpv4` returns only IPv6 addresses (#70)
- Invalid IMAP `FETCH` responses for non-UTF-8 messages (#70)
- Allow `STATUS` and `ACL` IMAP operations on virtual mailboxes.
- IMAP `SELECT QRESYNC` without specifying a UID causes panic (#67)
- Milter `DATA` command is sent after headers which causes ClamAV to hang.
- Sieve `redirect` of unmodified messages does not work.

## [0.3.6] - 2023-08-29

## Added
- Arithmetic and logical expression evaluation in Sieve scripts.
- Support for storing query results in Sieve variables.
- Results of SPF, DKIM, ARC, DMARC and IPREV checks available as environment variables in Sieve scripts.
- Configurable protocol flags for Milter filters.
- Fall-back to plain text when `STARTTLS` fails and `starttls` is set to `optional`.

### Changed
 
### Fixed
- Do not panic when `hash = 0` in reports. (#60)
- JMAP Session resource returns `EmailSubmission` capabilities using arrays rather than objects.
- ManageSieve `PUTSCRIPT` should replace existing scripts.

## [0.3.5] - 2023-08-18

## Added
- TCP listener option `nodelay`.
 
### Changed
 
### Fixed
- SMTP: Allow disabling `STARTTLS`.
- JMAP: Support for `OPTIONS` HTTP method.

## [0.3.4] - 2023-08-09

## Added
- JMAP: Support for setting custom HTTP response headers (#52)
 
### Changed
 
### Fixed
- SMTP: Missing envelope keys in rewrite rules (#25) 
- SMTP: Remove CRLF from Milter headers
- JMAP/IMAP: Successful authentication requests should not count when rate limiting
- IMAP: Case insensitive Inbox selection
- IMAP: Automatically create Inbox for group accounts

## [0.3.3] - 2023-08-02

### Added
- Encryption at rest with **S/MIME** or **OpenPGP**.
- Support for referencing context variables from dynamic values.
 
### Changed
 
### Fixed
- Support for PKCS8v1 ED25519 keys (#20).
- Automatic retry for import/export blob downloads (#14)

## [0.3.2] - 2023-07-28

### Added
- Sender and recipient address rewriting using regular expressions and sieve scripts.
- Subaddressing and catch-all addresses using regular expressions (#10).
- Dynamic variables in SMTP rules.
 
### Changed
- Added CLI to Docker container (#19).
 
### Fixed
- Workaround for a bug in `sqlx` that caused SQL time-outs (#15).
- Support for ED25519 certificates in PEM files (#20). 
- Better handling of concurrent IMAP UID map modifications (#17).
- LDAP domain lookups from SMTP rules.

## [0.3.1] - 2023-07-22

### Added
- Milter filter support.
- Match IP address type using /0 mask (#16).
 
### Changed
 
### Fixed
- Support for OpenLDAP password hashing schemes between curly brackets (#8). 
- Add CA certificates to Docker runtime (#5).

## [0.3.0] - 2023-07-16

### Added
- **LDAP** and **SQL** authentication.
- **subaddressing** and **catch-all** addresses.
- **S3-compatible** storage.

### Changed
- Merged the `stalwart-jmap`, `stalwart-imap` and `stalwart-smtp` repositories into
  `stalwart-mail`.
- Removed clustering module and replaced it with a **FoundationDB** backend option.
- Integrated Stalwart SMTP into Stalwart JMAP.
- Rewritten JMAP protocol parser.
- Rewritten store backend.
- Rewritten IMAP server to have direct access to the message store (no more IMAP proxy).
- Replaced `actix` with `hyper`.
 
### Fixed

