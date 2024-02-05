#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald

RHEL(){
    # Fix config
    if command -v authconfig >/dev/null; then
        authconfig --updateall

        # Fix modules
        # /usr/lib64/security
        yum -y reinstall pam 
    else
        echo "No authconfig, cannot fix pam here"
    fi

}

DEBIAN(){
    # Fix config
    DEBIAN_FRONTEND=noninteractive 
    pam-auth-update --force

    # Fix modules
    # /lib/x86_64-linux-gnu/security
    # /usr/lib/x86_64-linux-gnu/security
    apt-get -y --reinstall install libpam-runtime libpam-modules
}

UBUNTU(){
    DEBIAN
}

ALPINE(){
    if [ ! -d /etc/pam.d ]; then
        echo "PAM is not installed"
    else
        # Fix modules and config
        # /lib/security
        apk fix --purge linux-pam
        for file in $( find /etc/pam.d -name *.apk-new | xargs -0 echo ); do
            mv $file $( echo $file | sed 's/.apk-new//g' )
        done
    fi
}

SLACK(){
    echo "Bro I wish I knew how"
}

ARCH(){

    # "Fix" configurations
    # Actual dogshit distro. This will prob take a long ass time
    #mv /etc/pam.d /etc/pam.d.backup
    #deps=$( pacman -Qi pam | grep 'Required By' | awk -F ':' '{print $2}' )
    #for dep in $deps; do
    #    pacman -Syy polkit --noconfirm $dep
    #done

    if [ -z "$BACKUPDIR" ]; then
        echo "Yeah bruh I ain't doing the configs"
    else
        mv /etc/pam.d /etc/pam.d.backup
        cp -R $BACKUPDIR /etc/pam.d
    fi
    # Fix modules
    # /usr/lib/security
    pacman -S pam --noconfirm
}

if command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if $( cat /etc/os-release | grep -qi Ubuntu ); then
        UBUNTU
    else
        DEBIAN
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
elif command -v pacman >/dev/null ; then
    ARCH
else
    echo "Unknown OS, not fixing PAM"
fi
