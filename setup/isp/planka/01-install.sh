cd /tmp
sudo -u postgres createuser -s planka
sudo -u postgres createdb planka
cd -
adduser --comment planka --disabled-password planka
mkdir -p /var/www/planka
chown -R planka:planka /var/www/planka
