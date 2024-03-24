FROM ubuntu

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
    git tmux build-essential zlib1g zlib1g-dev \
    libxml2 libxml2-dev libxslt-dev locate \
    libreadline6-dev libcurl4-openssl-dev git-core \
    libssl-dev libyaml-dev openssl autoconf libtool \
    ncurses-dev bison curl wget xsel postgresql \
    postgresql-contrib postgresql-client libpq-dev \
    libapr1 libaprutil1 libsvn1 \
    libpcap-dev libsqlite3-dev libgmp3-dev \
    nasm vim nmap ntpdate sudo golang

RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /opt/msfinstall && chmod 755 /opt/msfinstall && /opt/msfinstall

RUN adduser ccdc

USER ccdc
ENTRYPOINT [ "bash" ]