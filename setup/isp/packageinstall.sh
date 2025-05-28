apt-get update
apt-get install postgresql postgresql-contrib caddy nodejs npm -y

wget https://github.com/binwiederhier/ntfy/releases/download/v2.11.0/ntfy_2.11.0_linux_amd64.deb
dpkg -i ntfy_*.deb
rm ntfy_2.11.0_linux_amd64.deb
