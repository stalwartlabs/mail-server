#!/usr/bin/env bash
# shellcheck shell=bash

# Usage: `./heredoc-bundler.sh <install.sh`
# This program processes a script that contains `<`-input redirections.
# Redirections that literally start with `$EMBED_DIR` are embedded as heredoc.
# The file names of such redirections must not contain other variables or
# any quotes, because the parsing isn't very robust.
# Lines containing `EMBED_DIR=` are grepped out, because the output script
# should not depend on this directory.

EMBED_DIR=resources

# Use newline as delimiter because that cannot occur in the input line.
IFS='
'

grep -v "EMBED_DIR=" | while read -r line; do
    line="${line/ <\$EMBED_DIR/$IFS}"
    set -- $line
    if [ -n "$2" ]; then
        line="${2/ /$IFS}"
        set -- "$1" $line
        echo "$1 <<'EOF'${3+ }$3"
        cat "$EMBED_DIR/$2"
        echo EOF
    else
        echo "$1"
    fi
done
