#!/usr/bin/env sh
# shellcheck shell=dash

set -xe

exec /usr/local/bin/stalwart-install --docker --component "$STALWART_COMPONENT" --path /opt/stalwart-mail "$@"
