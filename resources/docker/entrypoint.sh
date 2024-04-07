#!/usr/bin/env sh
# shellcheck shell=dash

# If the configuration file does not exist initialize it.
if [ ! -f /opt/stalwart-mail/etc/config.toml ]; then
    /usr/local/bin/stalwart-mail --init /opt/stalwart-mail
fi

# If the configuration file exists, start the server.
exec /usr/local/bin/stalwart-mail --config /opt/stalwart-mail/etc/config.toml
