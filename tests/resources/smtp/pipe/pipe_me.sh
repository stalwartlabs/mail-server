#!/bin/bash

if [[ $1 == "hello" ]] && [[ $2 == "world" ]]; then
    echo "X-My-Header: true"
    while read line
    do
    echo "$line"
    done < /dev/stdin
    exit 0;
else
    echo "Invalid parameters!"
    exit 1;
fi

