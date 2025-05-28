cd /tmp
psql -c "ALTER USER planka PASSWORD 'DB_PASSWORD_CHANGE_ME';"
curl -fsSL -O https://github.com/plankanban/planka/releases/latest/download/planka-prebuild.zip
unzip planka-prebuild.zip -d /var/www/
cd /var/www/planka
rm /tmp/planka-prebuild.zip
npm install
