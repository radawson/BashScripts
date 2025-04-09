#!/bin/bash
#v1.1.2
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
CDN_IP="10.10.0.${CDN_NUMBER}"

FQDN="cdn${CDN_NUMBER_PADDED}.${DOMAIN}"

echo "Setting up CDN server with FQDN ${FQDN} and IP ${IP}"
echo "This server will use WireGuard IP ${CDN_IP}"

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
sudo systemctl stop nginx

# Install PostgreSQL
echo "Installing PostgreSQL"
wait_for_apt
sudo apt-get -y install postgresql 

# Install PowerDNS
echo "Installing PowerDNS and dependencies"
wait_for_apt
sudo apt-get -y install pdns-server pdns-backend-pgsql pdns-backend-geoip

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

# Install YAML Linter
echo "Installing YAML Linter"
wait_for_apt
sudo apt-get -y install yamllint

## Software configuration
# Configure PostgreSQL
echo "Configuring PostgreSQL"
sudo -u postgres psql -c "CREATE USER pdns_user WITH SUPERUSER PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE pdns OWNER pdns_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pdns_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pdns_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO pdns_user;"

# Create PowerDNS schema
sudo -u postgres psql pdns < /usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql

# Configure PowerDNS
echo "Configuring PowerDNS"
sudo tee /etc/powerdns/pdns.conf > /dev/null <<EOF
# Basic settings
setuid=pdns
setgid=pdns
#launch=gpgsql,reoip

# Network settings for PowerDNS
local-address=${IP},${CDN_IP}
local-port=53

# PostgreSQL backend settings
#gpgsql-host=localhost
#gpgsql-user=pdns_user
#gpgsql-password=${DB_PASSWORD}
#gpgsql-dbname=pdns
#gpgsql-dnssec=yes

# GeoIP backend - using correct settings for PowerDNS 4.8
launch=geoip
geoip-database-files=/usr/share/GeoIP/GeoLite2-Country.mmdb
geoip-zones-file=/etc/powerdns/geo-zones.yaml

# Allow zone transfers from primary DNS
allow-axfr-ips=10.10.0.1
EOF

# Create a comprehensive geo-zones.yaml file 
sudo tee /etc/powerdns/geo-zones.yaml > /dev/null <<EOF
---
# GeoIP Configuration for techopsgroup.com CDN
zones:
  cdn.techopsgroup.com:
    domain: cdn.techopsgroup.com
    ttl: 300
    records:
      # CDN node records with public IPs
      cdn001:
        - content: 149.154.27.178
          type: A
      cdn002:
        - content: 155.138.211.253
          type: A
      cdn003:
        - content: 104.156.231.127
          type: A
      cdn004:
        - content: 80.240.29.48
          type: A
      cdn005:
        - content: 139.84.194.171
          type: A


      # Geographic routing - Countries
      us:
        - content: 155.138.211.253
          type: A
      au:
        - content: 139.84.194.171
          type: A
      de:
        - content: 80.240.29.48
          type: A

      # Geographic routing - Continents
      north-america:
        - content: 155.138.211.253
          type: A
      europe:
        - content: 80.240.29.48
          type: A
      australia:
        - content: 139.84.194.171
          type: A

      # Default fallback
      default:
        - content: 149.154.27.178
          type: A

    # Service mappings
    services:
      # Main CDN hostname
      "cdn.techopsgroup.com":
        - "%co.origin.techopsgroup.com"
        - "%cn.origin.techopsgroup.com"
        - "default.origin.techopsgroup.com"

      # All subdomains
      "*.cdn.techopsgroup.com":
        - "%co.origin.techopsgroup.com"
        - "%cn.origin.techopsgroup.com"
        - "default.origin.techopsgroup.com"
ghostrider@origin:~$ sudo nano /etc/powerdns/geo-zones.yaml
ghostrider@origin:~$ yamllint /etc/powerdns/geo-zones.yaml
ghostrider@origin:~$ sudo cat /etc/powerdns/geo-zones.yaml
---
# GeoIP Configuration for techopsgroup.com CDN
zones:
  cdn.techopsgroup.com:
    domain: cdn.techopsgroup.com
    ttl: 300
    records:
      # CDN node records with public IPs
      cdn001:
        - content: 149.154.27.178
          type: A
      cdn002:
        - content: 155.138.211.253
          type: A
      cdn003:
        - content: 104.156.231.127
          type: A
      cdn004:
        - content: 80.240.29.48
          type: A
      cdn005:
        - content: 139.84.194.171
          type: A

      # US Regional routing
      us-east:
        - content: 155.138.211.253  # ATL server
          type: A
      us-west:
        - content: 104.156.231.127  # SF server
          type: A

      # Geographic routing - Countries
      us:
        - content: 155.138.211.253  # Default US to East Coast
          type: A
      ca:
        - content: 155.138.211.253  # Canada to East Coast
          type: A
      mx:
        - content: 104.156.231.127  # Mexico to West Coast
          type: A
      au:
        - content: 139.84.194.171  # Australia
          type: A
      de:
        - content: 80.240.29.48     # Germany
          type: A
      fr:
        - content: 80.240.29.48     # France to EU server
          type: A
      gb:
        - content: 80.240.29.48     # UK to EU server
          type: A

      # Geographic routing - Continents
      north-america:
        - content: 155.138.211.253  # Default North America to East Coast
          type: A
      europe:
        - content: 80.240.29.48     # Europe
          type: A
      australia:
        - content: 139.84.194.171   # Australia/Oceania
          type: A
      asia:
        - content: 139.84.194.171   # Asia to Australia server (closest option)
          type: A

      # Default fallback
      default:
        - content: 149.154.27.178   # Origin server
          type: A

    # Service mappings
    services:
      # Main CDN hostname
      "cdn.techopsgroup.com":
        - "%co.cdn.techopsgroup.com"        # First try country match
        - "%cn.cdn.techopsgroup.com"        # Then try continent match
        - "default.cdn.techopsgroup.com"    # Default fallback

      # All subdomains
      "*.cdn.techopsgroup.com":
        - "%co.cdn.techopsgroup.com"
        - "%cn.cdn.techopsgroup.com"
        - "default.cdn.techopsgroup.com"
EOF

# Restart PowerDNS to apply configuration
echo "Restarting PowerDNS"
sudo systemctl restart pdns

# Get SSL certificate
echo "Obtaining SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# Configure NGINX with caching for CDN
# Create Cache Directory
sudo mkdir -p /var/cache/nginx/cdn_cache
sudo chown -R www-data:www-data /var/cache/nginx/cdn_cache


if sudo test -f /etc/letsencrypt/live/${FQDN}/fullchain.pem; then
    echo "Certificate generated successfully!"   
else
    echo "Error: Certificate generation failed. Please check the logs."

fi

# Create a cache config file
sudo tee /etc/nginx/conf.d/proxy-cache.conf > /dev/null <<EOF
proxy_cache_path /var/cache/nginx/cdn_cache levels=1:2 keys_zone=cdn_cache:10m max_size=10g inactive=60m;
proxy_temp_path /var/cache/nginx/cdn_temp;
EOF

# Create the site configuration 
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
    
    # Add cache headers
    add_header X-Cache-Status \$upstream_cache_status;
    add_header X-CDN-Node "${FQDN}";
    
    # Health check endpoint for HAProxy
    location = /health {
        access_log off;
        add_header Content-Type text/plain;
        return 200 'OK';
    }
    
    # Root web content
    location / {
      proxy_pass http://10.10.0.1;
      proxy_cache cdn_cache;
      proxy_cache_valid 200 302 60m;
      proxy_cache_valid 404 5m;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto \$scheme;
      
      # Increase timeouts
      proxy_connect_timeout 60s;
      proxy_send_timeout 60s;
      proxy_read_timeout 60s;
    
      # Avoid redirect loops
      proxy_redirect off;
    }

    # For testing purposes, return client information as JSON
    location = /remote-info {
        default_type application/json;
        
        # Create JSON with client information
        return 200 '{"ip": "\$remote_addr", "server": "\$hostname", "headers": {"User-Agent": "\$http_user_agent", "Accept-Language": "\$http_accept_language", "Host": "\$host", "Referer": "\$http_referer", "X-Forwarded-For": "\$http_x_forwarded_for", "X-Real-IP": "\$http_x_real_ip", "Via": "\$http_via", "X-Cache-Status": "\$upstream_cache_status"}}';
    }

    location ~ /\.well-known/acme-challenge {
        allow all;
    }
    
    # Static content caching
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

sudo mkdir -p /var/cache/nginx/cdn_cache /var/cache/nginx/cdn_temp
sudo chown -R www-data:www-data /var/cache/nginx/cdn_cache /var/cache/nginx/cdn_temp
sudo ln -sf /etc/nginx/sites-available/${FQDN} /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

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
sudo systemctl start nginx

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

# Create directory for origin server certificates
sudo mkdir -p /etc/ssl/private/origin.${DOMAIN}

# Create WireGuard configuration file
echo "Creating WireGuard configuration file"
sudo tee "${WG_CONFIG}" > /dev/null <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${WG_IP}
ListenPort = 51822
SaveConfig = true
# Additional security parameters
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
# MTU settings for optimal performance
MTU = 1420

EOF

# Start WireGuard interface
echo "Starting WireGuard interface wg0"
sudo wg-quick up wg0

# Create a script to update WireGuard configuration with origin server key
sudo tee /usr/local/bin/update-wireguard-config >/dev/null <<EOF
#!/bin/bash
# Script to update WireGuard configuration with origin server key

if [[ \$# -ne 1 ]]; then
    echo "Usage: \$0 <ORIGIN_PUBLIC_KEY>"
    exit 1
fi

ORIGIN_KEY=\$1

# Update the WireGuard configuration
sudo wg set wg0 peer \${ORIGIN_KEY} endpoint origin.${DOMAIN}:51822 allowed-ips 10.10.0.0/24 persistent-keepalive 25

echo "WireGuard configuration updated with origin server key"
EOF

sudo chmod +x /usr/local/bin/update-wireguard-config

# Create a script to create a certificate request
sudo tee /usr/local/bin/req-ssl-certs >/dev/null <<EOF2
#!/bin/bash
# Usage: \$0 <CDN_NUMBER> [DOMAIN]

# Validate arguments
if [[ \$# -lt 1 || \$# -gt 2 ]]; then
    echo "Usage: \$0 <CDN_NUMBER> [DOMAIN]"
    exit 1
fi

# Set variables
CDN_NUMBER=\${1}
CDN_NUMBER_PADDED=\$(printf "%03d" \${CDN_NUMBER})

if [[ \$# -eq 2 ]]; then
    DOMAIN=\${2}
else
    DOMAIN="techopsgroup.com"
fi

# Get IP address
IP=\$(ip -o -4 addr | grep -E ' (en|eth)[^ ]+' | head -n1 | awk '{print \$4}' | cut -d/ -f1)
FQDN="cdn\${CDN_NUMBER_PADDED}.\${DOMAIN}"
CDN_DOMAIN="cdn.\${DOMAIN}"
CDN_IP="10.10.0.\${CDN_NUMBER}"

echo "Creating certificate request for ${FQDN} with SANs for ${CDN_DOMAIN}"

# Create directory for certificates
sudo mkdir -p /etc/ssl/private/cdn

# Generate private key and CSR
openssl req -new -sha256 -nodes -out \${FQDN}.csr -newkey rsa:4096 -keyout \${FQDN}.key -config <(
cat <<-EOF
[req]
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[ dn ]
C=US
ST=North Carolina
L=Fayetteville
O=Technical Operations Group
OU=CDN
CN = \${FQDN}
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = \${FQDN}
DNS.2 = \${CDN_DOMAIN}
IP.1 = \${IP}
EOF
)

# Set permissions
sudo chmod 400 \${FQDN}.key
sudo chmod 644 \${FQDN}.csr

sudo cp \${FQDN}* /etc/ssl/private/cdn
sudo chown -R www-data:www-data /etc/ssl/private/cdn

echo "Certificate request generated:"
echo "Private key: /etc/ssl/private/cdn/\${FQDN}.key"
echo "CSR: /etc/ssl/private/cdn/\${FQDN}.csr"
echo ""
echo "To obtain a certificate with Let's Encrypt, use:"
echo "sudo certbot certonly --standalone --csr /etc/ssl/private/cdn/\${FQDN}.csr \\"
echo "  --key-path /etc/ssl/private/cdn/\${FQDN}.key \\"
echo "  --fullchain-path /etc/ssl/certs/\${FQDN}.crt"
echo ""
echo "Note that this will fail because of the IP address in the request."
echo "Certificate information:"
openssl req -text -noout -in \${FQDN}.csr | grep -A 5 "Subject Alternative Name"

EOF2

# Make the script executable
sudo chmod +x /usr/local/bin/pull-ssl-certs

# Create Certificate Request
sudo /usr/local/bin/req-ssl-certs ${CDN_NUMBER}

# Create the pull script for geo-zones
sudo tee /usr/local/bin/pull-geozones.sh >/dev/null <<EOF
#!/bin/bash
# Script to pull geo-zones.yaml from origin server

# Log file
LOG_FILE="/var/log/cdn-pull.log"

# Origin server WireGuard IP
ORIGIN="10.10.0.1"

# Source and destination files
SOURCE_FILE="/etc/powerdns/geo-zones.yaml"
TEMP_FILE="/tmp/geo-zones.yaml"
DEST_FILE="/etc/powerdns/geo-zones.yaml"

# Ensure log file exists and has correct permissions
sudo touch \$LOG_FILE
sudo chmod 644 \$LOG_FILE
sudo chown root:root \$LOG_FILE

echo "\$(date): Starting geo-zones.yaml pull from \$ORIGIN" >> \$LOG_FILE

# Pull the file using rsync
rsync -av -e "ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no" --rsync-path="sudo rsync" root@\$ORIGIN:\$SOURCE_FILE \$TEMP_FILE

if [ \$? -eq 0 ]; then
  echo "\$(date): Successfully pulled geo-zones.yaml" >> \$LOG_FILE

  if yamllint ${TEMP_FILE} 2>&1 | grep -q "error"; then
    echo "\$(date): Warning: YAML file has errors. Please check manually." >> \$LOG_FILE
    exit 1
  else
    echo "\$(date): YAML validation passed." >> \$LOG_FILE
  fi

  # Move the temp file to the destination
  sudo mv \$TEMP_FILE \$DEST_FILE

  # Fix permissions
  sudo chown pdns:pdns \$DEST_FILE
  sudo chmod 644 \$DEST_FILE
  
  # Restart PowerDNS to apply changes
  sudo systemctl restart pdns
  
  if [ \$? -eq 0 ]; then
    echo "\$(date): Successfully restarted PowerDNS" >> \$LOG_FILE
  else
    echo "\$(date): Failed to restart PowerDNS" >> \$LOG_FILE
  fi
else
  echo "\$(date): Failed to pull geo-zones.yaml from \$ORIGIN" >> \$LOG_FILE
fi

echo "\$(date): Pull operation completed" >> \$LOG_FILE
EOF

# Make the script executable
sudo chmod +x /usr/local/bin/pull-geozones.sh

# Add origin SSH key to root's authorized keys
sudo mkdir -p /root/.ssh
sudo tee -a /root/.ssh/authorized_keys > /dev/null <<EOF
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEGjjryTFSewSfNc8bn6vqrs1YAi5qgBjBM7p5exfwO root@origin.techopsgroup.com
EOF

# Set up SSH key for root user if it doesn't exist
if [ ! -f /root/.ssh/id_ed25519 ]; then
  sudo -u root ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
  sudo cp /root/.ssh/id_ed25519 ~/.ssh/id_ed25519
  echo "SSH key generated. You need to copy this public key to the origin server:"
  echo "--------------------------------------------------------"
  sudo cat /root/.ssh/id_ed25519.pub
  echo "--------------------------------------------------------"
  echo "On the origin server, add this key to /root/.ssh/authorized_keys"
else
  echo "SSH key already exists at /root/.ssh/id_ed25519"
fi

# Create the cron job file directly
sudo tee /etc/cron.d/cdn-maintenance >/dev/null <<EOF
# Pull geo-zones.yaml from origin server hourly
0 * * * * root /usr/local/bin/pull-geozones.sh
EOF

# Set proper permissions on cron file
sudo chmod 644 /etc/cron.d/cdn-maintenance

# Create log file with proper permissions
sudo touch /var/log/cdn-pull.log
sudo chmod 644 /var/log/cdn-pull.log

## Write Configuration to File
# Save configuration data and WireGuard public key
PUBLIC_KEY=$(sudo cat /etc/wireguard/client_public.key)
echo "Saving configuration data"
cat <<EOF >~/cdn_server_config.txt
-- CDN Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}
WireGuard Public Key: ${PUBLIC_KEY}
SSH Key: $(sudo cat /root/.ssh/id_ed25519.pub)

PowerDNS Database:
    Database Type: PostgreSQL
    Database Name: pdns
    Database User: pdns
    Database Password: ${DB_PASSWORD}

Certificate Paths:
    Let's Encrypt Certificate: /etc/letsencrypt/live/${FQDN}/
    Origin Server Certificate: /etc/ssl/private/origin.${DOMAIN}/
    Certificate Request (CSR): /etc/ssl/private/cdn/${FQDN}.csr
    Private Key for CSR: /etc/ssl/private/cdn/${FQDN}.key
    Target Path for Signed Cert: /etc/ssl/certs/${FQDN}.crt

Configuration Files:
    PowerDNS: /etc/powerdns/pdns.conf
    GeoIP Zones: /etc/powerdns/geo-zones.yaml
    NGINX: /etc/nginx/sites-available/${FQDN}
    WireGuard: /etc/wireguard/wg0.conf

Management Scripts:
    Update WireGuard Config: /usr/local/bin/update-wireguard-config <ORIGIN_PUBLIC_KEY>
    Pull SSL Certificates: /usr/local/bin/pull-ssl-certs
    Pull GeoIP Zones: /usr/local/bin/pull-geozones.sh
EOF

echo "CDN server setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy your SSH public key to the origin server:"
echo "   ssh-copy-id -i /root/.ssh/id_ed25519.pub root@origin.${DOMAIN}"
echo ""
echo "2. On the origin server, add your CDN node using your WireGuard public key:"
echo "   /usr/local/bin/add-cdn-node ${CDN_NUMBER} ${PUBLIC_KEY}"
echo ""
echo "3. Configure WireGuard with the origin server's public key:"
echo "   /usr/local/bin/update-wireguard-config <ORIGIN_PUBLIC_KEY>"
echo ""
echo "4. Certificate management:"
echo "   - A CSR has been generated at: /etc/ssl/private/cdn/${FQDN}.csr"
echo "   - Submit this CSR to your certificate authority for signing"
echo "   - Once signed, place the certificate at: /etc/ssl/certs/${FQDN}.crt"
echo "   - Update the NGINX configuration to use the new certificate"
echo ""
echo "5. Download GeoIP configuration from the origin server:"
echo "   /usr/local/bin/pull-geozones.sh"
echo ""
echo "6. Verify connections and services:"
echo "   - PowerDNS service: systemctl status pdns"
echo "   - WireGuard connection: wg show"
echo "   - NGINX configuration: nginx -t"
echo ""
echo "All configuration details have been saved to: ~/cdn_server_config.txt"