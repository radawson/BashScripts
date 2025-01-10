#!/bin/bash
# (c) 2025 Rick Dawson
# Usage: ./setup_keycloak.sh <version> <domain>
# Example: ./setup_keycloak.sh 26.0.7 keycloak.example.com

VERSION="${1}"
DOMAIN="${2}"

# Update system
sudo apt-get update
sudo apt-get remove certbot -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y

## Install postgres 17
PASSWORD=$(openssl rand -base64 32)
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt-get -y install postgresql

sudo -u postgres createuser -s -i -d -r -l -w keycloak
sudo -u postgres psql -c "ALTER ROLE keycloak WITH PASSWORD '${PASSWORD}';"
sudo -u postgres psql -c 'create database keycloak;'
sudo -u postgres psql -c 'grant all privileges on database keycloak to keycloak;'
echo ${PASSWORD} > ~/postgres.pwd

## Install OpenJDK 21
sudo apt-get -y install openjdk-21-jdk

cat <<EOF >> ~/.bashrc
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export PATH=\$PATH:\$JAVA_HOME/bin
EOF

sudo tee -a /etc/skel/.bashrc <<EOF
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export PATH=\$PATH:\$JAVA_HOME/bin
EOF

# Certbot (snap)
sudo apt-get install -y snapd
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Install nginx
sudo apt-get install nginx -y

# Set up nginx proxy
sudo tee /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    # Accept all server names
    server_name _;

    # Basic timeouts for security
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 5s 5s;
    send_timeout 10s;

    location / {
        # Proper IP forwarding
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $http_host;
        
        # Security headers
        proxy_hide_header X-Powered-By;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";
        
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8080;
    }
}
EOF

sudo systemctl restart nginx

## Open firewall (temporary)
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 8080
sudo ufw --force enable

## Install keycloak
sudo apt-get install -y unzip
wget https://github.com/keycloak/keycloak/releases/download/${VERSION}/keycloak-${VERSION}.zip
unzip keycloak-${VERSION}.zip
rm keycloak-${VERSION}.zip

# Create initial user
PASSWORD=$(openssl rand 18 | base64 | tr -dc 'A-Za-z0-9')
echo "Admin password: ${PASSWORD}" > ~/keycloak.pwd
export KC_BOOTSTRAP_ADMIN_USERNAME="admin"
export KC_BOOTSTRAP_ADMIN_PASSWORD="${PASSWORD}"

## Configure keycloak:
sed -i 's|#db=postgres|db=postgres|' ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i 's|#db-username=keycloak|db-username=keycloak|' ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i "s|#db-password=password|db-password=${PASSWORD}|" ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i 's|#db-url=jdbc:postgresql://localhost/keycloak|db-url=jdbc:postgresql://localhost/keycloak|' ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i 's|#https-certificate-file=${kc.home.dir}conf/server.crt.pem|https-certificate-file=${kc.home.dir}conf/server.crt.pem|' ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i 's|#https-certificate-key-file=${kc.home.dir}conf/server.key.pem|https-certificate-key-file=${kc.home.dir}conf/server.key.pem|' ~/keycloak-${VERSION}/conf/keycloak.conf
sed -i 's|#proxy=reencrypt|proxy=reencrypt|' ~/keycloak-${VERSION}/conf/keycloak.conf

# add LE certificates
sudo certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m webmaster@${DOMAIN}
(
    sudo crontab -l 2>/dev/null
    echo "0 12 * * * /usr/bin/certbot renew --quiet"
) | sudo crontab -

## Copy certificates
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ~/keycloak-${VERSION}/conf/server.crt.pem
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ~/keycloak-${VERSION}/conf/server.key.pem
sudo chown $USER:$USER ~/keycloak-${VERSION}/conf/server.*.pem
sudo chmod 640 ~/keycloak-${VERSION}/conf/server.*.pem

sudo bash -c "cat <<EOF > /etc/systemd/system/keycloak.service
[Unit]
Description=Keycloak Service
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=/home/{$USER}/keycloak-${VERSION}
ExecStart=/home/${USER}/keycloak-${VERSION}/bin/kc.sh start-dev
Restart=always

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable keycloak
sudo systemctl start keycloak

# Remove or comment out the manual start-dev call below
# ./keycloak-${VERSION}/bin/kc.sh start-dev