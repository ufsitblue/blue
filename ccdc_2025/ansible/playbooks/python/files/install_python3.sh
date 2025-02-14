#!/usr/bin/env bash

# Detect the package manager and install python3 accordingly
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian|kali)
            apt update && apt install -y python3
            exit $?
            ;;
        rocky|centos|rhel|fedora)
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
        opensuse|sles|opensuse-leap)
            zypper install -y python3
            exit $?
            ;;
        gentoo)
            emerge --ask dev-lang/python
            exit $?
            ;;
        void)
            xbps-install -Sy python3
            exit $?
            ;;
        slackware)
            slackpkg install python3
            exit $?
            ;;
        nixos)
            nix-env -iA nixpkgs.python3
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
