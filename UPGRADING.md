Upgrading from `v0.5.3` to `v0.6.0`
-----------------------------------

- In order to support [expressions](https://stalw.art/docs/configuration/expressions/overview), version `0.6.0` introduces multiple breaking changes in the SMTP server configuration file. It is recommended to download the new SMTP configuration files from the [repository](https://github.com/stalwartlabs/mail-server/tree/main/resources/config/smtp), make any necessary changes and replace the old files under `INSTALL_DIR/etc/smtp` with the new ones.
- Message queues are now distributed and stored in the backend specified by the `storage.data` and `storage.blob` settings. Make sure to flush your SMTP message queue before upgrading to `0.6.0` to avoid losing any outgoing messages pending delivery.
- Replace the binary with the new version.
- Restart the service.

Upgrading from `v0.5.2` to `v0.5.3`
-----------------------------------

- The following configuration attributes have been renamed, see [store.toml](https://github.com/stalwartlabs/mail-server/blob/main/resources/config/common/store.toml) for an example:
  - `jmap.store.data` -> `storage.data`
  - `jmap.store.fts` -> `storage.fts`
  - `jmap.store.blob` -> `storage.blob`
  - `jmap.encryption.*` -> `storage.encryption.*`
  - `jmap.spam.header` -> `storage.spam.header`
  - `jmap.fts.default-language` -> `storage.fts.default-language`
  - `jmap.cluster.node-id` -> `storage.cluster.node-id`
  - `management.directory` and `sieve.trusted.default.directory` -> `storage.directory`
  - `sieve.trusted.default.store` -> `storage.lookup`
- Proxy networks are now configured under `server.proxy.trusted-networks` rather than `server.proxy-trusted-networks`. IP addresses/masks have to be defined within a set (`{}`) rather than a list (`[]`), see [server.toml](https://github.com/stalwartlabs/mail-server/blob/main/resources/config/common/server.toml) for an example.


Upgrading from `v0.5.1` to `v0.5.2`
-----------------------------------

- Make sure that implicit TLS is enabled for the JMAP [listener](https://stalw.art/docs/server/listener) configured under `ets/jmap/listener.toml`:
  ```toml
  [server.listener."jmap".tls]
  implicit = true
  ```
- Optional: Enable automatic TLS with [ACME](https://stalw.art/docs/server/tls/acme).
- Replace the binary with the new version.
- Restart the service.

Upgrading from `v0.5.0` to `v0.5.1`
-----------------------------------

- Replace the binary with the new version.
- Restart the service.

Upgrading from `v0.4.x` to `v0.5.0`
-----------------------------------

## What's changed

- **Database Layout**: Version 0.5.0 utilizes a different database layout which is more efficient and allows multiple backends to be supported. For this reason, the database must be migrated to the new layout.
- **Configuration file changes**: The configuration file has been updated to support multiple stores, most configuration attributes starting with `store.*` and `directory.*` need to be reviewed.
- **SPAM filter**: Sieve scripts that interact with databases need to be updated. The functions `lookup` and `lookup_map` has been renamed to `key_exists` and `key_get`. It is recommended to replace all scripts with the new versions rather than updating them manually. Additionally, the SPAM database no longer requires an SQL server, it can now be stored in Redis or any of the supported databases.
- **Directory superusers**: Due to problems and confusion with the `superuser-group` attribute, the concept of a superuser group has been removed. Instead, a new attribute `type` has been added to external directories. The value of this attribute can be `individual`, `group` or `admin`. The `admin` type is equivalent to the old superuser group. The `type` attribute is required for all principals in the directory, it defaults to `individual` if not specified.
- **Purge schedules**: The attributes `jmap.purge.schedule.db` and `jmap.purge.schedule.blobs` have been removed. Instead, the purge frequency is now specified per store in `store.<name>.purge.frequency`. The attribute `jmap.purge.schedule.sessions` has been renamed to `jmap.purge.sessions.frequency`.

## What's been added

- **Multiple stores**: The server now supports multiple stores to be defined in the configuration file under `store.<name>`. Which store to use is defined in the `jmap.store.data`, `jmap.store.fts` and `jmap.store.blob` settings.
- **More backend options**: It is now possible to use `RocksDB`, `PostgreSQL` and `MySQL` as data stores. It is also now possible to store blobs in any of the supported databases instead of being limited to the filesystem or an S3-compatible storage. Full-text indexing can now be done using `Elasticsearch` and the Spam database stored in `Redis`.
- **Internal Directory**: The server now has an internal directory that can be used to store user accounts, passwords and group membership. This directory can be used instead of an external directory such as LDAP or SQL.
- **New settings**: When running Stalwart in a cluster, `jmap.cluster.node-id` allows to specify a unique identifier for each node. Messages containing the SPAM headers defined in `jmap.spam.header` are moved automatically to the user's Junk Mail folder.
- **Default Sieve stores**: For Sieve scripts such as the Spam filter that require access to a directory and a lookup store, it is now possible to configure the default lookup store and directory using the `sieve.trusted.default.directory` and `sieve.trusted.default.store` settings.

## Migration Steps

Rather than manually updating the configuration file, it is recommended to start with a fresh configuration file and update it with the necessary settings:

- Install `v0.5.0` in a distinct directory. You now have the option to use an [internal directory](https://stalw.art/docs/directory/types/internal), which will allow you to manage users and groups directly from Stalwart Mail server. Alternatively, you can continue to use an external directory such as LDAP or SQL.
- Update the configuration files with your previous settings. All configuration attributes are backward compatible, except those starting with `store.*`, `directory.*` and `jmap.purge.*`.
- Export each account following the procedure described in the [migration guide](https://stalw.art/docs/management/database/migrate).
- Stop the old `v0.4.x` server.
- If there are messages pending to be delivered in the SMTP queue, move the `queue` directory to the new installation.
- Start the new `v0.5.0` server.
- Import each account following the procedure described in the [migration guide](https://stalw.art/docs/management/database/migrate).


Once again, we apologize for the lack of an automated migration tool for this upgrade. However, we are planning on introducing an automated migration tool once the web-admin is released in Q1 2024. Thank you for your understanding and patience.

Upgrading from `v0.4.0` to `v0.4.x`
-----------------------------------

- Replace the binary with the new version.
- Restart the service.


Upgrading from `v0.3.x` to `v0.4.0`
-----------------------------------

## What's changed

- **Configuration File Split:** While the `config.toml` configuration file format hasn't changed much, the new version has divided it into multiple sub-files. These sub-files are now included from the new `config.toml`. This division was implemented because the config file had grown significantly, and splitting it improves organization.

- **Changes in the Sieve Interpreter Attribute Names:** 
  - The configuration key prefix `jmap.sieve` (JMAP Sieve Interpreter) has been renamed to `sieve.untrusted`.
  - The configuration key prefix `sieve` (SMTP Sieve Interpreter) has been renamed to `sieve.trusted`.

## What's been added

- **SPAM Filter Module:** The most notable addition in this version is the SPAM filter module. It comprises:
  - A TOML configuration file located at `etc/smtp/spamfilter.toml`.
  - A set of Sieve scripts in `etc/spamfilter/scripts`.
  - Lookup maps in `etc/spamfilter/maps`.

- **New Configuration Key:** A new key `resolver.public-suffix` has been added. This specifies the URL of the list of public suffixes.

## Migration Steps

1. **Backup:** Ensure you have a backup of your current `config.toml` file.
2. **Download Configuration Bundle:** Fetch the new configuration bundle from [this link](https://get.stalw.art/resources/config.zip). Unpack it under `BASE_DIR/etc` (for example `/opt/stalwart-mail/etc`).
3. **Update Configuration Files:** Modify the following files with your domain name, host name, certificate paths, DKIM signatures, and so on:
   - `etc/config.toml`
   - `etc/jmap/store.toml`
   - `etc/jmap/oauth.toml`
   - `etc/smtp/signature.toml`
   - `etc/common/tls.toml`
4. **Adjust included files:** If you are using an LDAP directory for authentication, edit `etc/config.toml` and replace the `etc/directory/sql.toml` include with `etc/directory/ldap.toml`.
5. **Configure the SPAM Filter Database:** Set up and configure the SPAM filter database. More details can be found [here](https://stalw.art/docs/spamfilter/settings/database).
6. **Review All TOML Files:** Navigate to every TOML file under the `etc/` directory and make necessary changes.
7. **Update Binary:** Download and substitute the v0.4.0 binary suitable for your platform from [here](https://github.com/stalwartlabs/mail-server/releases/tag/v0.4.0).
8. **Restart Service:** Conclude by restarting the Stalwart Mail Server service.

### Alternative Method:

1. **Separate Installation:** Install v0.4.0 in a distinct directory. This will auto-update all configuration files and establish the spam filter database in SQLite format.
2. **Move Configuration Files:** Transfer the configuration files from `etc/` and the SQLite spam filter database from `data/` to your current installation's directory.
3. **Replace Binary:** Move the binary from the `bin/` directory to your current installation's `data/` directory.
4. **Restart Service:** Finally, restart the Stalwart Mail Server service.


We apologize for the lack of an automated migration tool for this upgrade. However, we are planning on introducing an automated migration tool in the near future. Thank you for your understanding and patience.
