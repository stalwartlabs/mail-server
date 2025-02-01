# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [0.11.5] - 2025-02-01

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added

### Changed
- Open source third party OIDC support.

### Fixed
- Case insensitive flag parsing (#1138).
- BCC not removed from JMAP EmailSubmissions (#618).
- Group pipelined IMAP FETCH and STATUS operations (#1096).

## [0.11.4] - 2025-01-29

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- RFC 9208 - IMAP QUOTA Extension (#484).

### Changed
- `session.throttle.*` is now `queue.limiter.inbound.*`.
- `queue.throttle.*` is now `queue.limiter.outbound.*`.
- Changed DNSBL error level to debug (#1107).

### Fixed
- Creating a mailbox in a shared folder results in wrong hierarchy (#1128).
- IMAP LIST-STATUS (RFC 5819) returns items in wrong order (#1129).
- Avoid non-RFC SMTP status codes (#1109).
- Do not DNSBL check invalid domains (#1107).
- Sieve message flag parser (#1059).
- Sieve script import case insensitivity (#962).
- `mailto:` parsing in HTMLs.

## [0.11.2] - 2025-01-17

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Automatic revoking of access tokens when secrets, permissions, ACLs or group memberships change (#649).
- Increased concurrency for local message delivery (configurable via `queue.threads.local`).
- Cluster node roles.
- `config_get` expression function.

### Changed
- `queue.outbound.concurrency` is now `queue.threads.remote`.
- `lookup.default.hostname` is now `server.hostname`.
- `lookup.default.domain` is now `report.domain`.

### Fixed
- Distributed locking issues in non-Redis stores (#1066).
- S3 incorrect backoff wait time after failures.
- Panic parsing broken HTMLs.
- Update CLI response serializer to v0.11.x (#1082).
- Histogram bucket counts (#1079).
- Do not rate limit trusted IPs (#1078).
- Avoid double encrypting PGP parts encoded as plain text (#1083).
- Return empty SASL challenge rather than "" (#1064).

## [0.11.0] - 2025-01-06

This version includes breaking changes to the configuration file, please read [UPGRADING.md](UPGRADING.md) for details.
To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Spam filter rewritten in Rust for a significant performance improvement.
- Multiple spam filter improvements (#947) such as training spam/ham when moving between inbox and spam folders (#819).
- Improved distributed locking and handling of large distributed SMTP queues.
- ASN and GeoIP lookups.
- Bulk operations REST endpoints (#925).
- Faster S3-FIFO caching.
- Support adding the `Delivered-To` header (#916).
- Semver compatibility checks when upgrading (#844).
- Sharded In-Memory Store.

### Changed
- Removed authentication rate limit (no longer necessary since there is fail2ban).
- Pipes have been deprecated in favor of MTA hooks.

### Fixed
- OpenPGP EOF error (#1024).
- Convert emails obtained from external directories to lowercase (#1004).
- LDAP: Support both name and email fields to be mapped to the same attribute.
- Admin role can't be assigned if an account with the same name exists.
- Fix macro detection in DNS record generation (#978).
- Use host FQDN in install script (#1003).

## [0.10.7] - 2024-12-04

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Delivery and DMARC Troubleshooting (#420).
- Support for external email addresses on mailing lists (#152).
- Azure blob storage support.

### Changed

### Fixed
- Some mails can't be moved out of the junk folder (#670).
- Out of bound index error on Sieve script (#941).
- Missing `User-Agent` header for ACME (#937).
- UTF8 support in IMAP4rev1 (#948).
- Account alias owner leak on autodiscover.
- Include all events in OTEL traces + Include spanId in webhooks.
- Implement `todo!()` causing panic on concurrency and rate limits.
- Mark SQL store as active if used as a telemetry store.
- Discard empty form submissions.

## [0.10.6] - 2024-11-07

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Enterprise license automatic renewals before expiration (disabled by default).
- Allow to LDAP search using bind dn instead of auth bind connection when bind auth is enabled (#873)

### Changed

### Fixed
- Include `preferred_username` and `email` in OIDC `id_token`.
- Verify roles and permissions when creating or modifying accounts (#874)

## [0.10.5] - 2024-10-15

To upgrade replace the `stalwart-mail` binary. 

### Added
- Data store CLI.

### Changed

### Fixed
- Tokenizer performance issue (#863)
- Incorrect AI model endpoint setting.

## [0.10.4] - 2024-10-08

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin. 

### Added
- Detect and ban port scanners as well as other forms of abuse (#820).
- ACME External Account Binding support (#379).

### Changed
- The settings `server.fail2ban.*` have been moved to `server.auto-ban.*`.
- The event `security.brute-force-ban` is now `security.abuse-ban`.

### Fixed
- Do not send SPF failures reports to local domains.
- Allow `nonce` in OAuth code requests.
- Warn when there are errors migrating domains rather than aborting migration.

## [0.10.3] - 2024-10-07

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin. Enterprise users wishing to use the new LLM-powered spam filter should also upgrade the spam filter rules.

### Added
- AI-powered Spam filtering and Sieve scripting (Enterprise feature).

### Changed
- The untrusted Sieve interpreter now has the `vnd.stalwart.expressions` extension enabled by default. This allows Sieve users to use the `eval` function to evaluate expressions in their scripts. If you would like to disable this extension, you can do so by adding `vnd.stalwart.expressions` to `sieve.untrusted.disabled-capabilities`.

### Fixed
- S3-compatible backends: Retry on `5xx` errors.
- OIDC: Include `nonce` parameter in `id_token` response.

## [0.10.2] - 2024-10-02

To upgrade first upgrade the webadmin and then replace the `stalwart-mail` binary. If you read these instructions too late, you can upgrade to the latest web-admin using `curl -k -u admin:yourpass https://yourserver/api/update/webadmin`.

### Added
- OpenID Connect server (#298).
- OpenID Connect backend support (Enterprise feature).
- OpenID Connect Dynamic Client Registration (#4)
- OAuth 2.0 Dynamic Client Registration Protocol ([RFC7591](https://datatracker.ietf.org/doc/html/rfc7591)) (#136)
- OAuth 2.0 Token Introspection ([RFC7662](https://datatracker.ietf.org/doc/html/rfc7662)).
- Contact form submission handling.
- `webadmin.path` setting to override unpack directory (#792).

### Changed

### Fixed
- Missing `LIST-STATUS` from RFC5819 in IMAP capability responses (#816).
- Do not allow tenant domains to be deleted if they have members (#812).
- Tenant principal limits (#810).

## [0.10.1] - 2024-09-26

To upgrade replace the `stalwart-mail` binary.

### Added
- `OAUTHBEARER` SASL support in all services (#627).

### Changed

### Fixed
- Fixed `migrate_directory` range scan (#784).

## [0.10.0] - 2024-09-21

This version includes breaking changes to how accounts are stored. Please read [UPGRADING.md](UPGRADING.md) for details.

### Added
- Multi-tenancy (Enterprise feature).
- Branding (Enterprise feature).
- Roles and permissions.
- Full-text search re-indexing.
- Partial database backups (#497).

### Changed

### Fixed
- IMAP `IDLE` support for command pipelining, aka the Apple Mail iOS 18 bug (#765).
- Case insensitive INBOX `fileinto` (#763).
- Properly decode undelete account name (#761).

## [0.9.4] - 2024-09-09

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Support for global Sieve scripts that can be used by users to filter their incoming mail.
- Allow localhost to override HTTP access controls to prevent lockouts.

### Changed
- Sieve runtime error default log level is now `debug`.

### Fixed
- Ignore INBOX case on Sieve's `fileinto` (#725)
- Local keys parsing and retrieval issues.
- Lookup reload does not include database settings.
- Account count is incorrect.

## [0.9.3] - 2024-08-29

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Dashboard (Enterprise feature)
- Alerts (Enterprise feature)
- SYN Flood (session "loitering") attack protection (#482)
- Mailbox brute force protection (#688)
- Mail from is allowed (`session.mail.is-allowed`) expression (#609)

### Changed
- `authentication.fail2ban` setting renamed to `server.fail2ban.authentication`.
- Added elapsed times to message filtering events.

### Fixed
- Include queueId in MTA Hooks (#708)
- Do not insert empty keywords in FTS index.

## [0.9.2] - 2024-08-21

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Message delivery history (Enterprise feature)
- Live tracing and logging (Enterprise feature)
- SQL Read Replicas (Enterprise feature)
- Distributed S3 Blob Store (Enterprise feature)

### Changed

### Fixed
- Autodiscover request parser issues.
- Do not create tables when using SQL as an external directory (fixes #291)
- Do not hardcode logger id (fixes #348)
- Include `Forwarded-For IP` address in `http.request-url` event (fixes #682)

## [0.9.1] - 2024-08-08

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
- Metrics support (closes #478)
  - OpenTelemetry Push Exporter
  - Prometheus Pull Exporter (closes #275)
- HTTP endpoint access controls (closes #266 #329 #542)
- Add `options` setting to PostgreSQL driver (closes #662)
- Add `isActive` property to defaults on Sieve/get JMAP method (closes #624)

### Changed
- Perform `must-match-sender` checks after sender rewriting (closes #394)
- Only perform email ingest duplicate check on the target mailbox (closes #632)

### Fixed
- Properly parse `Forwarded` and `X-Forwarded-For` headers (fixes #669)
- Resolve DKIM macros when generating DNS records (fixes #666)
- Fixed `is_local_domain` Sieve function (fixes #622)

## [0.9.0] - 2024-08-01

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin. This version includes breaking changes to the Webhooks configuration and produces a slightly different log output, read [UPGRADING.md](UPGRADING.md) for details.

### Added
- Improved and faster tracing and logging.
- Customizable event logging levels.

### Changed

### Fixed
- ManageSieve: Return capabilities after successful `STARTTLS`
- Do not provide `{auth_authen}` Milter macro unless the user is authenticated

## [0.8.5] - 2024-07-07

To upgrade replace the `stalwart-mail` binary.

### Added
- Restore deleted e-mails (Enterprise Edition only)
- Kubernetes (K8S) livenessProbe and readinessProbe endpoints.

### Changed
- Avoid sending reports for DMARC/delivery reports (#173)

### Fixed
- Refresh old FoundationDB read transactions (#520)
- Subscribing shared mailboxes doesn't work (#251)

## [0.8.4] - 2024-07-03

To upgrade replace the `stalwart-mail` binary.

### Added

### Changed

### Fixed
- Fix TOTP validation order.
- Increase Jemalloc page size on armv7 builds.

## [0.8.3] - 2024-07-01

To upgrade replace the `stalwart-mail` binary and then upgrade to the latest web-admin.

### Added
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

### Added
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

### Added
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

### Added
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

### Added
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

### Added
- Support for `DNS-01` and `HTTP-01` ACME challenges (#226)
- Configurable external resources (#355)

### Changed

### Fixed
- Startup failure when Elasticsearch is down/starting up (#334)
- URL decode path elements in REST API.

## [0.7.1] - 2024-04-12

To upgrade replace the `stalwart-mail` binary.

### Added
- Make initial admin password configurable via env (#311)

### Changed
- WebAdmin download URL.

### Fixed
- Remove ASN.1 DER structure from DKIM ED25519 public keys.
- Filter out invalid timestamps on log entries.

## [0.7.0] - 2024-04-09

This version uses a different database layout and introduces multiple breaking changes in the configuration files. Please read the [UPGRADING.md](UPGRADING.md) file for more information on how to upgrade from previous versions.

### Added
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

### Added
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

### Added
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

### Added
- [ACME](https://stalw.art/docs/server/tls/acme) support for automatic TLS certificate generation and renewal (#160).
- TLS certificate [hot-reloading](https://stalw.art/docs/management/database/maintenance#tls-certificate-reloading).
- [HAProxy protocol](https://stalw.art/docs/server/proxy) support (#36).

### Changed

### Fixed
- IMAP command `SEARCH <seqnum>` is using UIDs rather than sequence numbers.
- IMAP responses to `APPEND` and `EXPUNGE` should include `HIGHESTMODSEQ` when `CONDSTORE` is enabled.

## [0.5.1] - 2024-01-02

### Added
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

### Added
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

### Added
- JMAP for Quotas support ([RFC9425](https://www.rfc-editor.org/rfc/rfc9425.html))
- JMAP Blob Management Extension support ([RFC9404](https://www.rfc-editor.org/rfc/rfc9404.html))
- Spam Filter - Empty header rules.

### Changed

### Fixed
- Daylight savings time support for crontabs.
- JMAP `oldState` doesn’t reflect in `*/changes` (#56)

## [0.4.1] - 2023-10-26

### Added

### Changed

### Fixed
- Dockerfile entrypoint script.
- `bayes_is_balanced` function.

## [0.4.0] - 2023-10-25

This version introduces some breaking changes in the configuration file. Please read the [UPGRADING.md](UPGRADING.md) file for more information.

### Added
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

### Added
- Option to allow invalid certificates on outbound SMTP connections.
- Option to disable ansi colors on `stdout`.

### Changed
- SMTP reject messages are now logged as `info` rather than `debug`.

### Fixed

## [0.3.9] - 2023-10-07

### Added
- Support for reading environment variables from the configuration file using the `!ENV_VAR_NAME` special keyword.
- Option to disable ANSI color codes in logs.

### Changed
- Querying directories from a Sieve script is now done using the `query()` method from `eval`. Your scripts will need to be updated, please refer to the [new syntax](https://stalw.art/docs/smtp/filter/sieve#directory-queries).

### Fixed
- IPrev lookups of IPv4 mapped to IPv6 addresses.

## [0.3.8] - 2023-09-19

### Added
- Journal logging support
- IMAP support for UTF8 APPEND

### Changed
- Replaced `rpgp` with `sequoia-pgp` due to rpgp bug.

### Fixed
- Fix: IMAP folders that contain a & can't be used (#90) 
- Fix: Ignore empty lines in IMAP requests

## [0.3.7] - 2023-09-05

### Added
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

### Added
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

### Added
- TCP listener option `nodelay`.
 
### Changed
 
### Fixed
- SMTP: Allow disabling `STARTTLS`.
- JMAP: Support for `OPTIONS` HTTP method.

## [0.3.4] - 2023-08-09

### Added
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

