#!/bin/sh
set -eu

strict=${1:-}

check_tool() {
    tool=$1
    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi
    if [ "$strict" = "--strict" ]; then
        echo "$tool is required for strict formal verification" >&2
        exit 1
    fi
    echo "skipping $tool verification: compiler not installed" >&2
    return 1
}

if check_tool idris2; then
    (cd native/idris && idris2 --total --check Protocol.idr)
fi

if check_tool agda; then
    (cd native/agda && agda --safe --no-libraries Severity.agda)
fi
