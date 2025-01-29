#!/bin/bash
apt install apache2 -y
systemctl enable apache2
systemctl start apache2
ufw allow 'Apache Full'
echo "<html>
        <head>
                <title>apache page</title>
        </head>
        <body>
                <p>hello world</p>
        </body>
</html>" > /var/www/html/index.html
chown www-data:www-data /var/www/html/index.html
systemctl restart apache2
