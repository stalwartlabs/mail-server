# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [0.8.4] - 2024-07-03

To upgrade replace the `stalwart-mail` binary.

## Added

### Changed

### Fixed
- Fix TOTP validation order.
- Increase Jemalloc page size on armv7 builds.

## [0.8.3] - 2024-07-01

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

## Added
- Two-factor authentication with Time-based One-Time Passwords (#436)
- Application passwords (#479).
- Option to disable user accounts.

### Changed
- DANE success on EndEntity match regardless of TrustAnchor validation.

### Fixed
- Fix ManageSieve GETSCRIPT response: Add missing CRLF (#563)
- Do not return CAPABILITIES after ManageSieve AUTH=PLAIN SASL exchange (#548)
- POP3 QUIT must write a response (#568)

## [0.8.2] - 2024-06-22

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin and spam filter versions.

## Added
- Webhooks support (#480)
- MTA Hooks (like milter but over HTTP)
- Manually train and test spam classifier (#473 #264 #257 #471)
- Allow configuring default mailbox names, roles and subscriptions (#125 #290 #458 #498)
- Include `robots.txt` (#542)

### Changed
- Milter support on all SMTP stages (#183)
- Do not announce `STARTTLS` if the listener does not support it.

### Fixed
- Incoming reports stored in the wrong subspace (#543)
- Return `OK` after a successful ManageSieve SASL authentication flow (#187)
- Case-insensitive search in settings API (#487)
- Fix `session.rcpt.script` default variable name (#502)

## [0.8.1] - 2024-05-23

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin and spam filter versions.

## Added
- POP3 support.
- DKIM signature length exploit protection.
- Faster email deletion.
- Junk/Trash folder auto-expunge and changelog auto-expiry (#403)
- IP allowlists.
- HTTP Strict Transport Security option.
- Add TLS Reporting DNS entry (#464).

### Changed
- Use separate account for master user.
- Include server hostname in SMTP greetings (#448).

### Fixed
- IP addresses trigger `R_SUSPICIOUS_URL` false positive (#461 #419).
- JMAP identities should not return null signatures.
- Include authentication headers and check queue quotas on Sieve message forwards.
- ARC seal using just one signature.
- Remove technical subdomains from MTA-STS policies and TLS records (#429).

## [0.8.0] - 2024-05-13

This version uses a different database layout which is incompatible with previous versions. Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

## Added
- Clustering support with node auto-discovery and partition-tolerant failure detection.
- Autoconfig and MS Autodiscover support (#336)
- New variables `retry_num`, `notify_num`, `last_error` add `last_status` available in queue expressions.
- Performance improvements, in particular for FoundationDB.
- Improved full-text indexing with lower disk space usage.
- MTA-STS policy management.
- TLSA Records generation for DANE (#397)
- Queued message visualization from the web-admin.
- Master user support.

### Changed
- Make `certificate.*` local keys by default.
- Removed `server.run-as.*` settings.
- Add Microsoft Office Macro types to bad mime types (#391)

### Fixed
- mySQL TLS support (#415)
- Resolve file macros after dropping root privileges.
- Updated order of SPF Records (#395).
- Avoid duplicate accountIds when using case insensitive external directories (#399)
- `authenticated_as` variable not usable for must-match-sender (#372)
- Remove `StandardOutput`, `StandardError` in service (#390)
- SMTP `AUTH=LOGIN` compatibility issues with Microsoft Outlook (#400)

## [0.7.3] - 2024-05-01

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin version.

## Added
- Full database export and import functionality
- Add --help and --version command line arguments (#365)
- Allow catch-all addresses when validating must match sender

### Changed
- Add `groupOfUniqueNames` to the list of LDAP object classes

### Fixed
- Trim spaces in DNS-01 ACME secrets (#382)
- Allow only one journald tracer (#375)
- `authenticated_as` variable not usable for must-match-sender (#372)
- Fixed `BOGUS_ENCRYPTED_AND_TEXT` spam filter rule
- Fixed parsing of IPv6 DNS server addresses

## [0.7.2] - 2024-04-17

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin version.

## Added
- Support for `DNS-01` and `HTTP-01` ACME challenges (#226)
- Configurable external resources (#355)

### Changed

### Fixed
- Startup failure when Elasticsearch is down/starting up (#334)
- URL decode path elements in REST API.

## [0.7.1] - 2024-04-12

To upgrade replace the `stalwart-mail` binary.

## Added
- Make initial admin password configurable via env (#311)

### Changed
- WebAdmin download URL.

### Fixed
- Remove ASN.1 DER structure from DKIM ED25519 public keys.
- Filter out invalid timestamps on log entries.

## [0.7.0] - 2024-04-09

This version uses a different database layout and introduces multiple breaking changes in the configuration files. Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

## Added
- Web-based administration interface.
- REST API for management and configuration.
- Automatic RSA and ED25519 DKIM key generation.
- Support for compressing binaries in the blob store (#227).
- Improved performance accessing IMAP mailboxes with a large number of messages.
- Support for custom DNS resolvers.
- Support for multiple loggers with different levels and outputs.

### Changed

### Fixed
- Store quotas as `u64` rather than `u32`.
- Second IDLE connections disconnects the first one (#280).
- Use relaxed DNS parsing, allowing underscores in DNS labels (#172).
- Escape regexes within `matches()` expressions (#155).
- ManageSieve LOGOUT should reply with `OK` instead of `BYE`.

## [0.6.0] - 2024-02-14

This version introduces breaking changes in the configuration file. Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

## Added
- Distributed and fault-tolerant SMTP message queues.
- Distributed rate-limiting and fail2ban.
- Expressions in configuration files.

### Changed

### Fixed
- Do not include `STATUS` in IMAP `NOOP` responses (#234).
- Allow multiple SMTP `HELO` commands.
- Redirect OAuth using a `301` instead of a `307` code.

## [0.5.3] - 2024-01-14

Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

## Added
- Built-in [fail2ban](https://stalw.art/docs/server/fail2ban) and IP address/mask blocking (#164).
- CLI: Read URL and credentials from environment variables (#88).
- mySQL driver: Add `max-allowed-packet` setting (#201).

### Changed
- Unified storage settings for all services (read the [UPGRADING.md](UPGRADING.md) for details)

### Fixed
- IMAP retrieval of auto-encrypted emails (#203).
- mySQL driver: Parse `timeout.wait` property as duration (#202).
- `X-Forwarded-For` header on JMAP Rate-Limit does not work (#208).
- Use timeouts in install script (#138).

## [0.5.2] - 2024-01-07

Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

## Added
- [ACME](https://stalw.art/docs/server/tls/acme) support for automatic TLS certificate generation and renewal (#160).
- TLS certificate [hot-reloading](https://stalw.art/docs/management/database/maintenance#tls-certificate-reloading).
- [HAProxy protocol](https://stalw.art/docs/server/proxy) support (#36).

### Changed

### Fixed
- IMAP command `SEARCH <seqnum>` is using UIDs rather than sequence numbers.
- IMAP responses to `APPEND` and `EXPUNGE` should include `HIGHESTMODSEQ` when `CONDSTORE` is enabled.

## [0.5.1] - 2024-01-02

## Added
- SMTP smuggling protection: Sanitization of outgoing messages that do not use `CRLF` as line endings.
- SMTP sender validation for authenticated users: Added the `session.auth.must-match-sender` configuration option to enforce that the sender address used in the `MAIL FROM` command matches the authenticated user or any of their associated e-mail addresses.

### Changed

### Fixed
- Invalid DKIM signatures for empty message bodies.
- IMAP command `SEARCH BEFORE` is not properly parsed.
- IMAP command `FETCH` fails to parse single arguments without parentheses.
- IMAP command `ENABLE QRESYNC` should also enable `CONDSTORE` extension.
- IMAP response to `ENABLE` command does not include enabled capabilities list.
- IMAP response to `FETCH ENVELOPE` should not return `NIL` when the `From` header is missing.

## [0.5.0] - 2023-12-27

This version requires a database migration and introduces breaking changes in the configuration file. Please read the [UPGRADING.md](UPGRADING.md) file for more information.

## Added
- Performance enhancements:
  - Messages are parsed only once and their offsets stored in the database, which avoids having to parse them on every `FETCH` request.
  - Background full-text indexing.
  - Optimization of database access functions.
- Storage layer improvements:
  - In addition to `FoundationDB` and `SQLite`, now it is also possible to use `RocksDB`, `PostgreSQL` and `mySQL` as a storage backend.
  - Blobs can now be stored in any of the supported data stores, it is no longer limited to the file system or S3/MinIO. 
  - Full-text searching con now be done internally or delegated to `ElasticSearch`.
  - Spam databases can now be stored in any of the supported data stores or `Redis`. It is no longer necessary to have an SQL server to use the spam filter.
- Internal directory: 
  - User account, groups and mailing lists can now be managed directly from Stalwart without the need of an external LDAP or SQL directory.
  - HTTP API to manage users, groups, domains and mailing lists.
- IMAP4rev1 `Recent` flag support, which improves compatibility with old IMAP clients.
- LDAP bind authentication, to support some LDAP servers such as `lldap` which do not expose the userPassword attribute.
- Messages marked a spam by the spam filter can now be automatically moved to the account's `Junk Mail` folder.
- Automatic creation of JMAP identities.

### Changed

### Fixed
- Spamhaus DNSBL return codes.
- CLI tool reports authentication errors rather than a parsing error.

## [0.4.2] - 2023-11-01

## Added
- JMAP for Quotas support ([RFC9425](https://www.rfc-editor.org/rfc/rfc9425.html))
- JMAP Blob Management Extension support ([RFC9404](https://www.rfc-editor.org/rfc/rfc9404.html))
- Spam Filter - Empty header rules.

### Changed

### Fixed
- Daylight savings time support for crontabs.
- JMAP `oldState` doesn’t reflect in `*/changes` (#56)

## [0.4.1] - 2023-10-26

## Added

### Changed

### Fixed
- Dockerfile entrypoint script.
- `bayes_is_balanced` function.

## [0.4.0] - 2023-10-25

This version introduces some breaking changes in the configuration file. Please read the [UPGRADING.md](UPGRADING.md) file for more information.

## Added
- Built-in Spam and Phishing filter.
- Scheduled queries on some directory types.
- In-memory maps and lists containing glob or regex patterns.
- Remote retrieval of in-memory list/maps with fallback mechanisms.
- Macros and support for including files from TOML config files.

### Changed
- `config.toml` is now split in multiple TOML files for better organization.
- **BREAKING:** Configuration key prefix `jmap.sieve` (JMAP Sieve Interpreter) has been renamed to `sieve.untrusted`.
- **BREAKING:** Configuration key prefix `sieve` (SMTP Sieve Interpreter) has been renamed to `sieve.trusted`.

### Fixed

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

