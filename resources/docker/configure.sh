#!/usr/bin/env sh
# shellcheck shell=dash

exec /usr/local/bin/stalwart-install --docker --component "$STALWART_COMPONENT" --path /opt/stalwart-mail "$@"
