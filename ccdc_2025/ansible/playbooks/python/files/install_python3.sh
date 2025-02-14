#!/usr/bin/env bash

# Detect the package manager and install python3 accordingly
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            apt update && apt install -y python3
            exit $?
            ;;
        rocky|centos|rhel)
            yum install -y python3
            exit $?
            ;;
        arch)
            pacman -Sy --noconfirm python
            exit $?
            ;;
        alpine)
            apk add --no-cache python3
            exit $?
            ;;
        *)
            echo "Unsupported distribution: $ID"
            exit 1
            ;;
    esac
elif command -v freebsd-version >/dev/null 2>&1; then
    # FreeBSD
    pkg install -y python3
    exit $?
else
    echo "Cannot detect operating system. Unsupported distribution."
    exit 1
fi
