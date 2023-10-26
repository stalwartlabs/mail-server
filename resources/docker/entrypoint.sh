#!/usr/bin/env sh
# shellcheck shell=dash

# If the configuration file does not exist wait until it does.
while [ ! -f /opt/stalwart-mail/etc/config.toml ] || grep -q "__CERT_PATH__" /opt/stalwart-mail/etc/common/tls.toml; do
    sleep 1
done

# If the configuration file exists, start the server.
exec /usr/local/bin/__B__ --config /opt/stalwart-mail/etc/config.toml
