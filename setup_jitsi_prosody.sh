#!/bin/bash
#v1.0.5
# This script sets up a Jitsi Meet server with Prosody XMPP server as the XMPP backend.

# Stop on errors
set -Eeuo pipefail
trap 'echo "❌  error in $BASH_SOURCE:$LINENO: $BASH_COMMAND"' ERR

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <DNS DOMAIN> [IP]"
    echo "Example: $0 example.com 192.168.1.1"
    echo "meet. will be added to the domain"
    exit 1
fi

# Function to wait for apt locks to be released
wait_for_apt() {
  echo "Checking for apt/dpkg locks:"
  while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    printf "Waiting for other apt/dpkg processes to complete..."
    sleep 5
    printf "."
  done
  echo -e "\n\nLocks released, proceeding with installation."
}

# Function to wait for Prosody to be available
wait_for_service() {
  service=$1; shift
  for i in {1..30}; do
    systemctl is-active --quiet "$service" && return 0
    sleep 5
  done
  echo "$service did not start" >&2
  return 1
}

# Check if the domain is valid
if [[ ! "$1" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "Invalid domain name. Please use only letters, numbers, and hyphens."
    exit 1
fi

DOMAIN=${1}

if [[ $# -eq 2 ]]; then
    IP=${2}
else
    IP=$(ip -o -4 addr | grep -E ' (en|eth)[^ ]+' | head -n1 | awk '{print $4}' | cut -d/ -f1)
fi
if [[ -z "${IP}" ]]; then
    echo "Unable to determine IP address. Please provide it as the second argument."
    exit 1
fi

echo "Setting up Jitsi with domain ${DOMAIN} and IP ${IP}"

# Generate a secure random-ish password (16 chars, alphanumeric only)
DB_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

if [[ "${DOMAIN}" == meet.* ]]; then
    FQDN="${DOMAIN}"
else
    FQDN="meet.${DOMAIN}"
fi

if ! dig +short A "$FQDN" | grep -q "$IP"; then
    echo "❌ $FQDN does not resolve to $IP" >&2
    exit 1
fi || true          #  ← allow the pipeline to fail politely

# Export variables for use in other scripts
export FQDN=${FQDN}
export ADMIN_MAIL="admin@${DOMAIN}"
export DEBIAN_FRONTEND=noninteractive

## System Preparation
# Update and upgrade the system
echo "Updating and upgrading the system"
wait_for_apt
sudo apt update
wait_for_apt
sudo apt-get -y dist-upgrade
wait_for_apt
sudo apt-get -y autoremove

# Set hostname in two locations
echo "Setting hostname"
sudo hostnamectl hostname ${FQDN}
echo "${IP} ${FQDN}" | sudo tee -a /etc/hosts

# Configure Firewall
echo "Configuring firewall"
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3478/udp  # Jitsi videobridge
sudo ufw allow 4443/tcp  # Jitsi videobridge (SSL)
sudo ufw allow 5222/tcp  # XMPP client connections
#sudo ufw allow 5223/tcp  # XMPP client connections (SSL)
sudo ufw allow 5269/tcp  # XMPP server-to-server connections
#sudo ufw allow 5349/tcp  # XMPP server-to-server connections (SSL)
sudo ufw allow 7777/tcp  # File transfer
sudo ufw allow 10000/udp # Jitsi media traffic
sudo ufw --force enable

## Repository Preparation
# Ensure support for apt repositories served via HTTPS
echo "Installing apt-transport-https"
wait_for_apt
sudo apt-get install -y apt-transport-https 

# Install debconf-utils
echo "Installing debconf-utils"
wait_for_apt
sudo apt-get install -y debconf-utils

# Add Ubuntu universe repository
echo "Adding Ubuntu universe repository"
wait_for_apt
sudo apt-add-repository -y universe

# Add PostgreSQL repository
echo "Adding PostgreSQL repository"
wait_for_apt
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y

# Update package list
wait_for_apt
sudo apt-get update

## Software Installation
# Install CertBot
echo "Installing CertBot (snap)"
wait_for_apt
sudo apt-get remove -y certbot --purge
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Install PostgreSQL
echo "Installing PostgreSQL"
sudo apt-get -y install postgresql

# Install jitsi
echo "Installing Jitsi"
curl -sL https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" | sudo tee /etc/apt/sources.list.d/jitsi-stable.list
wait_for_apt
sudo apt-get update

sudo debconf-set-selections <<EOF
jitsi-videobridge jitsi-videobridge/jvb-hostname string ${FQDN}
jitsi-meet-web-config jitsi-meet/cert-choice select \
  "Generate a new self-signed certificate (You will later get a chance to obtain a Let's encrypt certificate)"
jitsi-meet-web-config jitsi-meet/letsencrypt-email string ${ADMIN_MAIL}
jitsi-meet-web-config jitsi-meet/jaas-choice boolean false
EOF

sudo apt-get -y install jicofo jitsi-meet jitsi-meet-turnserver jitsi-meet-web jitsi-meet-web-config jitsi-videobridge2 lua-dbi-postgresql lua-cjson lua-zlib

## Software Configuration

# Configure PostgreSQL
echo "Configuring PostgreSQL"
sudo -u postgres psql -c "CREATE USER prosody WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE prosody;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE prosody TO prosody;"
sudo -u postgres psql -c "ALTER USER prosody WITH SUPERUSER;"

# Configure Prosody
echo "Configuring Prosody"
sudo mkdir -p /etc/prosody/conf.d

# Create the main configuration file
cat <<EOF | sudo tee /etc/prosody/conf.d/90-pgsql-storage.cfg.lua
-- Global switch-over to PostgreSQL
storage = "sql"

sql = {
    driver   = "PostgreSQL";
    host     = "127.0.0.1";
    database = "prosody";
    username = "prosody";
    password = "${DB_PASSWORD}";
}
EOF



# Restart nginx to apply the new configuration
echo "Restarting Nginx"
sudo systemctl restart nginx
# Restart Prosody to apply the new plugins
echo "Restarting Prosody"  
sudo prosodyctl migrator migrate --from=internal --to=sql \
           postgres://prosody:${DB_PASSWORD}@127.0.0.1/prosody || true

sudo systemctl restart prosody

## Write Configuration to File
# Save host data to file for reference
echo "Saving host data"
cat <<EOF > ~/server_config.txt
-- Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}
Prosody Database:
    Database Type: PostgreSQL
    Database Name: prosody
    Database User: prosody
    Database Password: ${DB_PASSWORD}
EOF

sudo -u postgres psql -d prosody -c "\dt" >> ~/server_config.txt

### Optimization
# Set recommended system properties for Jitsi integration

# sudo sed -i 's/DefaultLimitNOFILE=65000/DefaultLimitNOFILE=65000/' /etc/systemd/system.conf
# sudo sed -i 's/DefaultLimitNPROC=65000/DefaultLimitNPROC=65000/' /etc/systemd/system.conf
# sudo sed -i 's/DefaultTasksMax=65000/DefaultTasksMax=65000/' /etc/systemd/system.conf

echo "Setting recommended Prosody system properties"
sudo sed -i 's/authentication *=.*/authentication = "internal_hashed"/' \
        /etc/prosody/conf.avail/${FQDN}.cfg.lua

cat <<EOS | sudo tee -a /etc/prosody/conf.avail/${FQDN}.cfg.lua

-- Guests wait here until a moderator joins
VirtualHost "guest.${FQDN}"
    authentication = "anonymous"
    c2s_require_encryption = true
EOS

sudo tee -a /etc/jitsi/jicofo/jicofo.conf >/dev/null <<EOF

authentication: {
  enabled: true
  type: XMPP
  login-url: XMPP:${FQDN}
}
EOF

sudo sed -i \
  "s~^ *// *anonymousdomain:.*~    anonymousdomain: 'guest.${FQDN}',~" \
  /etc/jitsi/meet/${FQDN}-config.js

sudo systemctl daemon-reload
sudo systemctl restart prosody jicofo jitsi-videobridge2