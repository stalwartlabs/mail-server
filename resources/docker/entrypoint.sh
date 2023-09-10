#!/usr/bin/env sh
# shellcheck shell=dash

CONFIG="$1"
shift

# If the configuration file does not exist wait until it does.

while [ ! -f "${CONFIG}" ] || grep -q "__CERT_PATH__" /opt/stalwart-mail/etc/common/tls.toml; do
    sleep 1
done

# If the configuration file exists, start the server.
exec "$@" --config "${CONFIG}"
