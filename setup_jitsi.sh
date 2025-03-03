#!/bin/bash
# (c) 2025 Rick Dawson
# Usage: ./setup_jitsi.sh <domain>
# Example: ./setup_jitsi.sh jitsi.example.com
# v1.0.0

#VERSION="${1}"
DOMAIN="${1}"

# Update system
sudo apt-get update
sudo apt-get remove certbot -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y

## Set hostname
sudo hostnamectl set-hostname meet.${DOMAIN}

## Install postgres 17
DB_PASSWORD=$(openssl rand 18 | base64 | tr -dc 'A-Za-z0-9')
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt-get -y install postgresql

sudo -u postgres createuser -s -i -d -r -l -w keycloak
sudo -u postgres psql -c "ALTER ROLE keycloak WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c 'create database keycloak;'
sudo -u postgres psql -c 'grant all privileges on database keycloak to keycloak;'
echo "Database password: ${DB_PASSWORD}" > ~/startup.txt

## Install OpenJDK 11
sudo apt-get -y install openjdk-11-jdk

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

# Install Openfire
wget https://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4.9.2_all.deb
sudo dpkg -i openfire_4.9.2_all.deb

## Open firewall (temporary)
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 10000/udp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw --force enable

## Install jitsi
curl -sL https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" | sudo tee /etc/apt/sources.list.d/jitsi-stable.list
sudo apt-get update
sudo apt-get install -y jitsi-meet

## Configure jitsi
sudo cp /etc/jitsi/meet/meet.${DOMAIN}-config.js /etc/jitsi/meet/meet.${DOMAIN}-config.js.bak
sudo cp /etc/jitsi/meet/meet.${DOMAIN}-config.js.example /etc/jitsi/meet/meet.${DOMAIN}-config.js

# add LE certificates
sudo certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m webmaster@${DOMAIN}
(
    sudo crontab -l 2>/dev/null
    echo "0 12 * * * /usr/bin/certbot renew --quiet"
) | sudo crontab -

## Copy certificates
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem /etc/jitsi/meet/meet.${DOMAIN}-cert.pem
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem /etc/jitsi/meet/meet.${DOMAIN}-key.pem
sudo chown $USER:$USER /etc/jitsi/meet/meet.${DOMAIN}-cert.pem
sudo chown $USER:$USER /etc/jitsi/meet/meet.${DOMAIN}-key.pem
sudo chmod 640 /etc/jitsi/meet/meet.${DOMAIN}-cert.pem
sudo chmod 640 /etc/jitsi/meet/meet.${DOMAIN}-key.pem

