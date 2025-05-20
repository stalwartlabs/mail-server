#!/usr/bin/env sh
# shellcheck shell=dash

# If the configuration file does not exist initialize it.
if [ ! -f /opt/stalwart/etc/config.toml ]; then
    /usr/local/bin/stalwart --init /opt/stalwart
fi

# If the configuration file exists, start the server.
exec /usr/local/bin/stalwart --config /opt/stalwart/etc/config.toml
