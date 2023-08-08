#!/usr/bin/env sh
# shellcheck shell=dash

# If the configuration file does not exist wait until it does.
while [ ! -f /opt/stalwart-mail/etc/config.toml ]; do
    sleep 1
done

# If the configuration file exists, start the server.
exec /usr/local/bin/__B__ --config /opt/stalwart-mail/etc/config.toml
