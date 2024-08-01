Upgrading from `v0.8.x` to `v0.9.0`
-----------------------------------

Version `0.9.0` introduces significant internal improvements while maintaining compatibility with existing database layouts and configuration file formats from version `0.8.0`. As a result, no data or configuration migration is necessary. This release focuses on enhancing performance and functionality, particularly in logging and tracing capabilities.

To upgrade to Stalwart Mail Server version `0.9.0` from `0.8.x`, begin by downloading the latest version of the `stalwart-mail` binary. Once downloaded, replace the existing binary with the new version. Additionally, it's important to update the WebAdmin interface to the latest version to ensure compatibility and to access new features introduced in this release.

In terms of breaking changes, this release brings significant updates to webhooks. All webhook event names have been modified, requiring a thorough review and adjustment of existing webhook configurations. Furthermore, the update introduces hundreds of new event types, enhancing the granularity and specificity of event handling capabilities. Users should familiarize themselves with these changes to effectively integrate them into their systems.

The reason for this release being classified as a major version, despite the absence of changes to the database or configuration formats, is the complete rewrite of the logging and tracing layer. This overhaul substantially improves the efficiency and speed of generating detailed tracing and logging events, making the system more robust and facilitating easier debugging and monitoring.

Upgrading from `v0.7.3` to `v0.8.0`
-----------------------------------

Version `0.8.0` includes both performance and security enhancements that require your data to be migrated to a new database layout. Luckily version `0.7.3` includes a migration tool which should make this process much easier than previous upgrades. In addition to the new layout, you will have to change the systemd service file to use the `CAP_NET_BIND_SERVICE` capability.

## Preparation
- Upgrade to version `0.7.3` if you haven't already. If you are on a version previous to `0.7.0`, you will have to do a manual migration of your data using the Command-line Interface.
- Create a directory where your data will be exported to, for example `/opt/stalwart-mail/export`.

## Systemd service upgrade (Linux only)
- Stop the `v0.7.3` installation:
  ```bash
  $ sudo systemctl stop stalwart-mail
  ```
- Update your systemd file to include the `CAP_NET_BIND_SERVICE` capability. Open the file `/etc/systemd/system/stalwart-mail.service` in a text editor and add the following lines under the `[Service]` section:
  ```
  User=stalwart-mail
  Group=stalwart-mail
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  ```
- Reload the daemon:
  ```bash
  $ systemctl daemon-reload
  ```
- Do not start the service yet.

## Data migration
- Stop Stalwart and export your data:

  ```bash
  $ sudo systemctl stop stalwart-mail
  $ sudo /opt/stalwart-mail/bin/stalwart-mail --config /opt/stalwart-mail/etc/config.toml --export /opt/stalwart-mail/export
  $ sudo chown -R stalwart-mail:stalwart-mail /opt/stalwart-mail/export
  ```

  or, if you are using the Docker image:

  ```bash
  $ docker stop stalwart-mail
  $ docker run --rm -v <STALWART_DIR>:/opt/stalwart-mail -it stalwart-mail /opt/stalwart-mail/bin/stalwart-mail --config /opt/stalwart-mail/etc/config.toml --export /opt/stalwart-mail/export
  ```
- Backup your `v0.7.3` installation:
  - If you are using RocksDB or SQLite, simply rename the `data` directory to `data-backup`, for example:
    ```bash
    $ mv /opt/stalwart-mail/data /opt/stalwart-mail/data-backup
    $ mkdir /opt/stalwart-mail/data
    $ chown stalwart-mail:stalwart-mail /opt/stalwart-mail/data
    ```
  - If you are using PostgreSQL, rename the database and create a blank database with the same name, for example:
    ```sql
    ALTER DATABASE stalwart RENAME TO stalwart_old; 
    CREATE database stalwart;
    ```
  - If you are using MySQL, rename the database and create a blank database with the same name, for example:
    ```sql
    CREATE DATABASE stalwart_old;
    RENAME TABLE stalwart.b TO stalwart_old.b;
    RENAME TABLE stalwart.v TO stalwart_old.v;
    RENAME TABLE stalwart.l TO stalwart_old.l;
    RENAME TABLE stalwart.i TO stalwart_old.i;
    RENAME TABLE stalwart.t TO stalwart_old.t;
    RENAME TABLE stalwart.c TO stalwart_old.c;
    DROP DATABASE stalwart;
    CREATE database stalwart;
    ```
  - If you are using FoundationDB, backup your database and clean the entire key range.
- Download the `v0.8.0` mail-server for your platform from the [releases page](https://github.com/stalwartlabs/mail-server/releases/latest/) and replace the binary in `/opt/stalwart-mail/bin`. If you are using the Docker image, pull the latest image.
- Import your data:

  ```bash
  $ sudo -u stalwart-mail /opt/stalwart-mail/bin/stalwart-mail --config /opt/stalwart-mail/etc/config.toml --import /opt/stalwart-mail/export
  ```

  or, if you are using the Docker image:
  
  ```bash
  $ docker run --rm -v <STALWART_DIR>:/opt/stalwart-mail -it stalwart-mail /opt/stalwart-mail/bin/stalwart-mail --config /opt/stalwart-mail/etc/config.toml --import /opt/stalwart-mail/export
  ```
- Start the service:
  ```bash
  $ sudo systemctl start stalwart-mail
  ```

  Or, if you are using the Docker image:
  ```bash
  $ docker start stalwart-mail
  ```

Upgrading from `v0.6.0` to `v0.7.0`
-----------------------------------

Version `0.7.0` of Stalwart Mail Server introduces significant improvements and features that enhance performance and functionality. However, it also comes with multiple breaking changes in the configuration files and a revamped database layout optimized for accessing large mailboxes. Additionally, Stalwart now supports compression for binaries stored in the blob store, further increasing efficiency.
Due to these extensive changes, the recommended approach for upgrading is to perform a clean reinstallation of Stalwart and manually migrate your accounts to the new version.

## Pre-Upgrade Steps
- Download the `v0.7.0` mail-server and CLI binaries for your platform from the [releases page](https://github.com/stalwartlabs/mail-server/releases/latest/).
- Initialize the setup on a distinct directory using the command `sudo ./stalwart-mail --init /path/to/new-install`. This command will print the administrator password required to access the web-admin.
- Create the `bin` directory using `mkdir /path/to/new-install/bin`.
- Move the downloaded binaries to the `bin` directory using the command `mv stalwart-mail stalwart-cli /path/to/new-install/bin`.
- Open `/path/to/new-install/etc/config.toml` in a text editor and comment out all listeners except the HTTP listener for port `8080`.
- Start the new installation from the terminal using the command `sudo /path/to/new-install/bin/stalwart-mail --config /path/to/new-install/etc/config.toml`.
- Point your browser to the web-admin at `http://yourserver.org:8080` and login using the auto-generated administrator password. 
- Configure the new installation with your domain, hostname, certificates, and other settings following the instructions at [stalw.art/docs/get-started](https://stalw.art/docs/get-started). Ignore the part about using the installation script, we are performing a manual installation.
- Add your user accounts.
- Configure Stalwart to run as the `stalwart-mail` user and `stalwart-mail` group from `Settings` > `Server` > `System`. This is not necessary if you are using Docker.
- Stop the new installation by pressing `Ctrl+C` in the terminal.

## Upgrade Steps
- On your `v0.6.0` installation, open in a text editor the `smtp/listener.toml`, `imap/listener.toml` files and comment out all listeners except the JMAP/HTTP listener (we are going to need it to export the user accounts) and then restart the service.
- If you are using an external store, backup the database using the appropriate method for your database system.
- Create the `~/exports` directory, here we will store the exported accounts.
- Using the existing CLI tool (not the one you just downloaded as it is not compatible), export each user account using the command `./stalwart-cli -u https://your-old-server.org -c <ADMIN_PASSWORD> export account <ACCOUNT_NAME> ~/exports`.
- Stop the `v0.6.0` installation using the command `sudo systemctl stop stalwart-mail`.
- Move the old `v0.6.0` installation to a backup directory, for example `mv /opt/stalwart-mail /opt/stalwart-mail-backup`.
- Move the new `v0.7.0` installation to the old installation directory, for example `mv /path/to/new-install /opt/stalwart-mail`.
- Set the right permissions for the new installation using the command `sudo chown -R stalwart-mail:stalwart-mail /opt/stalwart-mail`.
- Start the new installation using the command `sudo systemctl start stalwart-mail`.
- Import the accounts using the new CLI tool with the command `./stalwart-cli -u http://yourserver.org:8080 -c <ADMIN_PASSWORD> import account <ACCOUNT> ~/exports/<ACCOUNT>`.
- Using the admin tool, reactivate all the necessary listener (SMTP, IMAP, etc.)
- Restart the service using the command `sudo systemctl restart stalwart-mail`.

We apologize for the complexity of the upgrade process associated with this version of Stalwart. We understand the challenges and inconveniences that the requirement for a clean reinstallation and manual account migration poses. Moving forward, an automated migration tool will be included in any future releases that necessitate changes to the database layout, aiming to streamline the upgrade process for you. Furthermore, as we approach the milestone of version 1.0.0, we anticipate that such foundational changes will become increasingly infrequent, leading to more straightforward updates. We appreciate your patience and commitment to Stalwart during this upgrade.

Upgrading from `v0.5.3` to `v0.6.0`
-----------------------------------

- In order to support [expressions](https://stalw.art/docs/configuration/expressions/overview), version `0.6.0` introduces multiple breaking changes in the SMTP server configuration file. It is recommended to download the new SMTP configuration files from the [repository](https://github.com/stalwartlabs/mail-server/tree/main/resources/config/smtp), make any necessary changes and replace the old files under `INSTALL_DIR/etc/smtp` with the new ones.
- If you are using custom subaddressing of catch-all rules, you'll need to replace these rules with expressions. Check out the updated [syntax](https://stalw.art/docs/directory/addresses).
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
