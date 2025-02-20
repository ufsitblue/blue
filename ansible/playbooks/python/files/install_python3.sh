#!/usr/bin/env bash

# Detect the package manager and install python3 accordingly
install_python_linux() {
    case "$1" in
    ubuntu | debian | kali)
        apt update && apt install -y python3
        ;;
    rocky | centos | rhel | fedora)
        yum install -y python3
        ;;
    arch)
        pacman -Sy --noconfirm python
        ;;
    alpine)
        apk add --no-cache python3
        ;;
    opensuse | sles | opensuse-leap)
        zypper install -y python3
        ;;
    gentoo)
        emerge --ask dev-lang/python
        ;;
    void)
        xbps-install -Sy python3
        ;;
    slackware)
        slackpkg install python3
        ;;
    nixos)
        nix-env -iA nixpkgs.python3
        ;;
    *)
        return 1
        ;;
    esac
    return $?
}

if [ -f /etc/os-release ]; then
    . /etc/os-release
    install_python_linux "$ID" || {
        for alt_id in $ID_LIKE; do
            install_python_linux "$alt_id" && exit 0
        done
        echo "Unsupported distribution: $ID"
        exit 1
    }
    exit 0
elif command -v freebsd-version >/dev/null 2>&1; then
    # FreeBSD
    pkg install -y python3
    exit $?
else
    echo "Cannot detect operating system. Unsupported distribution."
    exit 1
fi
