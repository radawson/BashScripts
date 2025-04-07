#!/bin/bash
#v1.0.0
# (c) 2025 Richard Dawson, Technical Operations Group
# This script sets up a CDN server with NGINX, PowerDNS, and PostgreSQL backend.

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "Usage: $0 <CDN NUMBER> [DOMAIN] [IP]"
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

# Set variables and validate CDN number
CDN_NUMBER=${1}
if [[ ! "${CDN_NUMBER}" =~ ^[0-9]+$ ]]; then
    echo "Error: CDN NUMBER must be a positive integer."
    exit 1
fi

# Ensure CDN_NUMBER is between 1 and 254 (valid IP range)
if [[ "${CDN_NUMBER}" -lt 1 || "${CDN_NUMBER}" -gt 254 ]]; then
    echo "Error: CDN NUMBER must be between 1 and 254."
    exit 1
fi

# Format CDN_NUMBER with leading zeros for hostname
CDN_NUMBER_PADDED=$(printf "%03d" ${CDN_NUMBER})

# Set domain name
if [[ $# -ge 2 ]]; then
    DOMAIN=${2}
    if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9.-]+$ ]]; then
      echo "Error: Invalid domain name format."
      exit 1
    fi
else
    DOMAIN="techopsgroup.com"
    echo "No domain provided, using default: ${DOMAIN}"
fi

# Set IP address
if [[ $# -eq 3 ]]; then
    IP=${3}
else
    IP=$(ip -o -4 addr | grep -E ' (en|eth)[^ ]+' | head -n1 | awk '{print $4}' | cut -d/ -f1)
fi
if [[ -z "${IP}" ]]; then
    echo "Unable to determine IP address. Please provide it as the third argument."
    exit 1
fi

FQDN="cdn${CDN_NUMBER_PADDED}.${DOMAIN}"

echo "Setting up CDN server with FQDN ${FQDN} and IP ${IP}"
echo "This server will use WireGuard IP 10.10.0.${CDN_NUMBER}"

# Generate a secure random-ish password (16 chars, alphanumeric only)
DB_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

## System Preparation
# Update and upgrade the system
echo "Updating and upgrading the system"
wait_for_apt
sudo apt update
wait_for_apt
sudo apt-get -y dist-upgrade
wait_for_apt
sudo apt-get -y autoremove

# Set hostname
echo "Setting hostname"
sudo hostnamectl hostname ${FQDN}
echo "${IP} ${FQDN}" | sudo tee -a /etc/hosts

# Configure Firewall
echo "Configuring firewall"
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 53/tcp    # DNS TCP
sudo ufw allow 53/udp    # DNS UDP
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 51822/udp # WireGuard
sudo ufw --force enable

## Repository Preparation
# Ensure support for apt repositories served via HTTPS
echo "Installing apt-transport-https"
sudo apt-get install -y apt-transport-https

# Add PostgreSQL repository
echo "Adding PostgreSQL repository"
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y

# Update package list
sudo apt-get update

## Software Installation
# Install CertBot
echo "Installing CertBot (snap)"
sudo apt-get remove -y certbot --purge
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Install NGINX
echo "Installing NGINX"
wait_for_apt
sudo apt-get -y install nginx

# Install PostgreSQL
echo "Installing PostgreSQL"
wait_for_apt
sudo apt-get -y install postgresql 

# Install PowerDNS
echo "Installing PowerDNS and dependencies"
wait_for_apt
sudo apt-get -y install pdns-server pdns-backend-pgsql

# Install tools for GeoIP database download
echo "Installing curl and unzip for GeoIP database download"
wait_for_apt
sudo apt-get -y install curl unzip

# Download GeoIP databases from P3TERX GitHub repo
echo "Downloading GeoIP databases from P3TERX GitHub repository"
sudo mkdir -p /usr/share/GeoIP
sudo curl -L https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb -o /usr/share/GeoIP/GeoLite2-City.mmdb
sudo curl -L https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb -o /usr/share/GeoIP/GeoLite2-Country.mmdb
sudo chmod 644 /usr/share/GeoIP/*.mmdb

# Install WireGuard
echo "Installing WireGuard"
wait_for_apt
sudo apt-get -y install wireguard wireguard-tools

## Software configuration
# Configure PostgreSQL
echo "Configuring PostgreSQL"
sudo -u postgres psql -c "CREATE USER pdns WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE pdns OWNER pdns;"

# Create PowerDNS schema
sudo -u postgres psql pdns < /usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql

# Configure PowerDNS
echo "Configuring PowerDNS"
sudo tee /etc/powerdns/pdns.conf > /dev/null <<EOF
# Basic settings
setuid=pdns
setgid=pdns
launch=gpgsql
socket-dir=/var/run/pdns

# PostgreSQL backend settings
gpgsql-host=localhost
gpgsql-user=pdns
gpgsql-password=${DB_PASSWORD}
gpgsql-dbname=pdns

# GeoIP settings
geoip-database-files=/usr/share/GeoIP/GeoLite2-Country.mmdb
geoip-zones-file=/etc/powerdns/geo-zones.yaml

# Allow zone transfers from primary DNS
# Replace with your internal DNS IP
allow-axfr-ips=YOUR_INTERNAL_DNS_IP
EOF

# Create empty geo-zones file (to be configured later)
sudo tee /etc/powerdns/geo-zones.yaml > /dev/null <<EOF
# GeoIP Configuration
# Example:
# zones:
#   cdn.example.com:
#     - domain: cdn.example.com
#       ttl: 300
#       records:
#         usa:
#           - content: 203.0.113.1
#             type: A
#         europe: 
#           - content: 203.0.113.2
#             type: A
#         asia:
#           - content: 203.0.113.3
#             type: A
EOF

# Restart PowerDNS to apply configuration
echo "Restarting PowerDNS"
sudo systemctl restart pdns

# Get SSL certificate
echo "Obtaining SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# Configure NGINX with caching for CDN
if [ ! -f /etc/letsencrypt/live/${FQDN}/fullchain.pem ]; then
    echo "Certificate generation failed!"
else
    # Create cache directories
    sudo mkdir -p /var/cache/nginx/cdn_cache
    sudo chown -R www-data:www-data /var/cache/nginx/cdn_cache
    
    # Create NGINX SSL configuration with caching
    echo "Creating NGINX SSL configuration for ${FQDN}"
    sudo tee /etc/nginx/sites-available/${FQDN} > /dev/null <<EOF 
server {
    listen 80;
    server_name ${FQDN};

    location ~ /\.well-known/acme-challenge {
        allow all;
    }

    return 301 https://\$host\$request_uri; # Redirect all HTTP to HTTPS
}

server {
    listen 443 ssl http2;
    server_name ${FQDN};

    ssl_certificate /etc/letsencrypt/live/${FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${FQDN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'HIGH:!aNULL:!MD5';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # CDN Cache configuration
    proxy_cache_path /var/cache/nginx/cdn_cache levels=1:2 keys_zone=cdn_cache:10m max_size=10g inactive=60m;
    proxy_temp_path /var/cache/nginx/cdn_temp;
    proxy_cache_key "\$scheme\$request_method\$host\$request_uri";
    
    # Add cache headers
    add_header X-Cache-Status \$upstream_cache_status;
    add_header X-CDN-Node "${FQDN}";
    
    # Root web content
    location / {
      proxy_pass https://10.10.0.1;  # WireGuard IP of origin server
      proxy_cache cdn_cache;
      proxy_cache_valid 200 302 60m;
      proxy_cache_valid 404 5m;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
    
      # Avoid redirect loops
      proxy_redirect off;
    }

    location ~ /\.well-known/acme-challenge {
        allow all;
    }
    
    # Static content caching (adjust paths as needed)
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg)$ {
        proxy_pass https://10.10.0.1;
        proxy_cache cdn_cache;
        proxy_cache_valid 200 302 7d;
        expires 30d;
        add_header Cache-Control "public, max-age=2592000";
        access_log off;
    }
}
EOF

    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/${FQDN} /etc/nginx/sites-enabled/
fi

# Create basic index.html
sudo mkdir -p /var/www/html
sudo tee /var/www/html/index.html > /dev/null <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CDN Node - ${FQDN}</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
    </style>
</head>
<body>
    <h1>CDN Node: ${FQDN}</h1>
    <p>Technical Operations Group CDN network.</p>
    <p>IP Address: ${IP}</p>
</body>
</html>
EOF

# Restart NGINX to apply the new configuration
echo "Restarting NGINX"
sudo systemctl restart nginx

# Configure WireGuard
echo "Configuring WireGuard"

# Generate client private key
wg genkey | sudo tee /etc/wireguard/client_private.key
sudo chmod 600 /etc/wireguard/client_private.key

# Generate client public key (share this with the server)
sudo cat /etc/wireguard/client_private.key | wg pubkey | sudo tee /etc/wireguard/client_public.key

# Create client configuration
WG_CONFIG="/etc/wireguard/wg0.conf"
PRIVATE_KEY=$(sudo cat /etc/wireguard/client_private.key)
if [ -z "${PRIVATE_KEY}" ]; then
    echo "Error: Failed to generate WireGuard private key."
    exit 1
fi
WG_IP="10.10.0.${CDN_NUMBER}/24"

echo "Creating WireGuard configuration file"
sudo tee "${WG_CONFIG}" > /dev/null <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${WG_IP}
ListenPort = 51822
SaveConfig = true

[Peer]
PublicKey = <server_public_key>
Endpoint = origin.techopsgroup.com:51822
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF

# Enable WireGuard
sudo systemctl enable wg-quick@wg0
# Don't start WireGuard yet as the server public key needs to be filled in

## Write Configuration to File
# Save configuration data and WireGuard public key
PUBLIC_KEY=$(cat /etc/wireguard/client_public.key)
echo "Saving configuration data"
cat <<EOF >~/cdn_server_config.txt
-- CDN Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}
WireGuard Public Key: ${PUBLIC_KEY}

PowerDNS Database:
    Database Type: PostgreSQL
    Database Name: pdns
    Database User: pdns
    Database Password: ${DB_PASSWORD}

Certificate Path: /etc/letsencrypt/live/${FQDN}/

Configuration Files:
    PowerDNS: /etc/powerdns/pdns.conf
    GeoIP Zones: /etc/powerdns/geo-zones.yaml
    NGINX: /etc/nginx/sites-available/${FQDN}
    WireGuard: /etc/wireguard/wg0.conf
EOF

echo "CDN server setup complete!"
echo "Next steps:"
echo "1. Edit /etc/wireguard/wg0.conf to add the server's public key and correct endpoint IP"
echo "2. Start WireGuard with: sudo systemctl start wg-quick@wg0"
echo "3. Configure zone transfers from your main DNS server"
echo "4. Update the GeoIP zones file at /etc/powerdns/geo-zones.yaml"