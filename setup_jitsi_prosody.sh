#!/bin/bash
#v1.0.10
# This script sets up a Jitsi Meet server with Prosody XMPP server as the XMPP backend.

# Stop on errors
set -Eeuo pipefail
trap 'echo "❌  error in $BASH_SOURCE:$LINENO: $BASH_COMMAND"' ERR

# Initialize variables
SKIP_CERTBOT=false
DOMAIN=""
IP=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-certbot)
            SKIP_CERTBOT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 <DNS DOMAIN> [IP] [--skip-certbot]"
            echo "Example: $0 example.com 192.168.1.1"
            echo "Example: $0 example.com 192.168.1.1 --skip-certbot"
            echo "meet. will be added to the domain"
            exit 0
            ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            elif [[ -z "$IP" ]]; then
                IP="$1"
            else
                echo "❌ Too many arguments" >&2
                echo "Usage: $0 <DNS DOMAIN> [IP] [--skip-certbot]"
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate required arguments
if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 <DNS DOMAIN> [IP] [--skip-certbot]"
    echo "Example: $0 example.com 192.168.1.1"
    echo "Example: $0 example.com 192.168.1.1 --skip-certbot"
    echo "meet. will be added to the domain"
    exit 1
fi

# Validate domain name format
if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
    echo "❌ Invalid domain name format. Domain must:" >&2
    echo "   - Start and end with a letter or number" >&2
    echo "   - Contain only letters, numbers, dots, and hyphens" >&2
    echo "   - Not contain consecutive dots or hyphens" >&2
    echo "   - Not start or end with hyphens" >&2
    exit 1
fi

# Auto-detect IP if not provided
if [[ -z "$IP" ]]; then
    IP=$(ip -o -4 addr | grep -E ' (en|eth)[^ ]+' | head -n1 | awk '{print $4}' | cut -d/ -f1)
    if [[ -z "${IP}" ]]; then
        echo "❌ Unable to determine IP address. Please provide it as the second argument." >&2
        exit 1
    fi
else
    # Validate provided IP address
    if [[ ! "${IP}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "❌ Invalid IP address format. Must be in format: xxx.xxx.xxx.xxx" >&2
        exit 1
    fi
    
    # Validate each octet is between 0-255
    IFS='.' read -r -a ip_octets <<< "${IP}"
    for octet in "${ip_octets[@]}"; do
        if [[ ${octet} -lt 0 || ${octet} -gt 255 ]]; then
            echo "❌ Invalid IP address. Each octet must be between 0 and 255" >&2
            exit 1
        fi
    done
fi

echo "Setting up Jitsi with domain ${DOMAIN} and IP ${IP}"
if [[ "$SKIP_CERTBOT" == "true" ]]; then
    echo "Skipping Let's Encrypt (using existing certificates)"
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

# Generate a secure random-ish password (16 chars, alphanumeric only)
DB_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
# Generate random app_id and app_secret
APP_ID=$(openssl rand -hex 16)
APP_SECRET=$(openssl rand -hex 32)

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

# Add Jitsi repository
echo "Adding Jitsi repository"
wait_for_apt
curl -sL https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" | sudo tee /etc/apt/sources.list.d/jitsi-stable.list

# Add PostgreSQL repository
echo "Adding PostgreSQL repository"
wait_for_apt
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y

# Add prosody repository
echo "Adding prosody repository"
wait_for_apt
sudo wget https://packages.prosody.im/debian/pubkey-new.asc -O /etc/apt/trusted.gpg.d/prosody-new.asc
echo "deb https://packages.prosody.im/debian $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/prosody.list

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

# Install lua packages and dependencies
echo "Installing lua packages and OpenSSL development headers"
wait_for_apt
sudo apt-get install -y lua5.4 liblua5.4-dev libssl-dev openssl build-essential

# Install jitsi
echo "Installing Jitsi"
wait_for_apt
sudo apt-get update

# Clear any existing debconf cache
sudo debconf-communicate <<EOF
PURGE
EOF

# Install packages in correct dependency order
echo "Installing Jitsi packages in dependency order..."

# Stage 1: Install core Jitsi Meet first (this creates base Prosody config)
echo "Stage 1: Installing core Jitsi Meet..."
sudo debconf-set-selections <<EOF
jitsi-videobridge jitsi-videobridge/jvb-hostname string ${FQDN}
jitsi-meet-web-config jitsi-meet/cert-choice select "Generate a new self-signed certificate (You will later get a chance to obtain a Let's encrypt certificate)"
jitsi-meet-web-config jitsi-meet/letsencrypt-email string ${ADMIN_MAIL}
jitsi-meet-web-config jitsi-meet/jaas-choice boolean false
EOF

sudo DEBIAN_FRONTEND=noninteractive apt-get -y install jitsi-meet lua-dbi-postgresql lua-cjson lua-zlib

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

# Now get LetsEncrypt certificates
if [[ "$SKIP_CERTBOT" == "true" ]]; then
    echo "Skipping Let's Encrypt certificate generation (using existing certificates)"
    
    # Verify certificates exist
    if [[ ! -f "/etc/letsencrypt/live/${FQDN}/privkey.pem" ]] || [[ ! -f "/etc/letsencrypt/live/${FQDN}/fullchain.pem" ]]; then
        echo "❌ Certificates not found!" >&2
        echo "Expected:" >&2
        echo "  /etc/letsencrypt/live/${FQDN}/privkey.pem" >&2
        echo "  /etc/letsencrypt/live/${FQDN}/fullchain.pem" >&2
        echo "" >&2
        echo "💡 Copy your certificates there or run without --skip-certbot" >&2
        exit 1
    fi
    echo "✅ Found existing certificates for ${FQDN}"
    sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy/
else
    echo "Getting Let's Encrypt certificates"
    sudo systemctl stop nginx
    sudo certbot certonly --standalone -d ${FQDN} --agree-tos -m ${ADMIN_MAIL} --non-interactive
fi

sudo cp /etc/letsencrypt/live/${FQDN}/privkey.pem /etc/jitsi/meet/${FQDN}.key
sudo cp /etc/letsencrypt/live/${FQDN}/fullchain.pem /etc/jitsi/meet/${FQDN}.crt

# Create refresh script for certificates
cat <<'EOF' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/20-jitsi.sh
#!/usr/bin/env bash
set -e
DOMAIN="${RENEWED_LINEAGE##*/}"   # " /etc/letsencrypt/live/<domain>"

install -o root -g ssl-cert -m 640 "${RENEWED_LINEAGE}/privkey.pem" \
        "/etc/jitsi/meet/${DOMAIN}.key"
install -o root -g ssl-cert -m 644 "${RENEWED_LINEAGE}/fullchain.pem" \
        "/etc/jitsi/meet/${DOMAIN}.crt"

# Let Prosody import the cert for XMPP
prosodyctl --root cert import "${RENEWED_LINEAGE}" || true

systemctl reload nginx
systemctl restart prosody jicofo jitsi-videobridge2
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/20-jitsi.sh

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
APP_ID: ${APP_ID}
APP_SECRET: ${APP_SECRET}
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

# Check if guest domain exists, if not add it
if ! sudo grep -q "guest\.${FQDN}" /etc/prosody/conf.avail/${FQDN}.cfg.lua; then
    echo "Adding guest domain for anonymous users..."
    cat <<EOF | sudo tee -a /etc/prosody/conf.avail/${FQDN}.cfg.lua

-- Guests domain for anonymous users
VirtualHost "guest.${FQDN}"
    authentication = "anonymous"
    c2s_require_encryption = false
EOF
fi

# Update Jitsi Meet configuration to support anonymous domain
echo "Updating Jitsi Meet frontend configuration..."
# First try to uncomment existing anonymousdomain line
if sudo grep -q "// *anonymousdomain:" /etc/jitsi/meet/${FQDN}-config.js; then
    sudo sed -i "s~^ *// *anonymousdomain:.*~    anonymousdomain: 'guest.${FQDN}',~" /etc/jitsi/meet/${FQDN}-config.js
elif ! sudo grep -q "anonymousdomain:" /etc/jitsi/meet/${FQDN}-config.js; then
    # If no anonymousdomain line exists, add it after domain line
    sudo sed -i "/domain: '${FQDN}',/a\\    anonymousdomain: 'guest.${FQDN}'," /etc/jitsi/meet/${FQDN}-config.js
fi

sudo sed -i \
  "s~^ *// *anonymousdomain:.*~    anonymousdomain: 'guest.${FQDN}',~" \
  /etc/jitsi/meet/${FQDN}-config.js

sudo systemctl daemon-reload
sudo systemctl restart prosody jicofo jitsi-videobridge2

# Verify services are running
echo "✅ Verifying services..."
for service in prosody jicofo jitsi-videobridge2 nginx; do
    if sudo systemctl is-active --quiet $service; then
        echo "✅ $service is running"
    else
        echo "❌ $service is not running"
        sudo systemctl status $service
    fi
done
