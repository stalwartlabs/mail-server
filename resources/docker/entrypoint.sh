#!/usr/bin/env sh
# shellcheck shell=dash

CONFIG="$1"
shift

# If the configuration file does not exist wait until it does.

loop_count=0
while [ ! -f "${CONFIG}" ] || grep -q "__CERT_PATH__" /opt/stalwart-mail/etc/common/tls.toml; do
    sleep 1
    if [ $(($loop_count % 30)) -eq 0 ]; then
        if [ ! -f "${CONFIG}" ]; then
            echo "ERROR: Configuration file ${CONFIG} not found."
            echo "Please execute 'docker exec -it $HOSTNAME stalwart-install' to fix and start service"
        fi
        if grep -q "__CERT_PATH__" /opt/stalwart-mail/etc/common/tls.toml; then
            echo "ERROR: TLS not configured."
            echo "Please check etc/common/tls.toml file in your configuration volume"
        fi
        echo "ERROR: Service will wait for configuration to be fixed before startup"
    fi
    loop_count=$(($loop_count+1))
done

# If the configuration file exists, start the server.
exec "$@" --config "${CONFIG}"
