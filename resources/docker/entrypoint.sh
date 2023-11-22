#!/usr/bin/env sh
# shellcheck shell=dash

set -eu

confdir="$1"
shift

echo Waiting for configuration...

# If the configuration file does not exist wait until it does.
while [ ! -f "${confdir}/config.toml" ] || grep -q "__CERT_PATH__" "${confdir}/common/tls.toml"; do
    sleep 1
done

# If the configuration file exists, start the server.
exec "$@" --config "${confdir}/config.toml"
