Upgrading from `v0.3.x` to `v0.4.0`
-----------------------------------

## What's Changed

- **Configuration File Split:** While the `config.toml` configuration file format hasn't changed much, the new version has divided it into multiple sub-files. These sub-files are now included from the new `config.toml`. This division was implemented because the config file had grown significantly, and splitting it improves organization.

- **Changes in the Sieve Interpreter Attribute Names:** 
  - The configuration key prefix `jmap.sieve` (JMAP Sieve Interpreter) has been renamed to `sieve.untrusted`.
  - The configuration key prefix `sieve` (SMTP Sieve Interpreter) has been renamed to `sieve.trusted`.

## New Additions

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
