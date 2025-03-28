#!/bin/bash
v3.0.1
# This script sets up a Jitsi Meet server with OpenFire as the XMPP backend.

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <DNS DOMAIN> [IP]"
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

# Function to wait for OpenFire admin interface to be available
wait_for_openfire() {
  local attempts=0
  echo "Waiting for OpenFire admin interface..."
  while ! curl -s -o /dev/null http://localhost:9090; do
    attempts=$((attempts+1))
    if [ $attempts -gt 30 ]; then
      echo "OpenFire admin interface not available after 5 minutes"
      return 1
    fi
    echo "Waiting for OpenFire to start... ($attempts/30)"
    sleep 10
  done
  echo "OpenFire admin interface is responding"
  return 0
}

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
FOCUS_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
JVB_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
FQDN="meet.${DOMAIN}"

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
echo "${IP} ${OF_FQDN}" | sudo tee -a /etc/hosts

# Configure Firewall
echo "Configuring firewall"
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3478/udp  # Jitsi videobridge
sudo ufw allow 5222/tcp  # XMPP client connections
sudo ufw allow 5223/tcp  # XMPP client connections (SSL)
sudo ufw allow 5269/tcp  # XMPP server-to-server connections
sudo ufw allow 5349/tcp  # XMPP server-to-server connections (SSL)
sudo ufw allow 7777/tcp  # File transfer
sudo ufw allow 9090/tcp  # OpenFire admin console direct
sudo ufw allow 9091/tcp  # OpenFire admin console secure
sudo ufw allow 10000/udp # Jitsi media traffic
sudo ufw --force enable

## Repository Preparation
# Ensure support for apt repositories served via HTTPS
echo "Installing apt-transport-https"
sudo apt-get install -y apt-transport-https

# Add Ubuntu universe repository
echo "Adding Ubuntu universe repository"
sudo apt-add-repository -y universe

# Add OpenJDK repository
echo "Adding OpenJDK repository"
sudo apt-add-repository -y ppa:openjdk-r/ppa

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

# Install Nginx
echo "Installing Nginx"
sudo apt-get install nginx
sudo systemctl stop nginx

cat <<EOF | sudo tee /etc/nginx/sites-available/${DOMAIN}
server {
    listen 80;
    listen [::]:80;
    server_name ${FQDN} ${OF_FQDN};

    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }

    # For Let's Encrypt verification
    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/html;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${FQDN};

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/${FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${FQDN}/privkey.pem;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Proxy all other requests to OpenFire Meetings
    location / {
        proxy_pass https://${IP}:7443/;

        # Important headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        # SSL verification (disable for self-signed certs)
        proxy_ssl_verify off;

        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;

        # Buffer settings
        proxy_buffering off;
        proxy_buffer_size 16k;
        proxy_busy_buffers_size 24k;
    }

}
EOF
# Enable the Nginx configuration
sudo ln -s /etc/nginx/sites-available/${DOMAIN} /etc/nginx/sites-enabled/


# Install OpenJDK
echo "Installing OpenJDK"
sudo apt-get -y install openjdk-24-jdk

# Set JAVA_HOME
echo "Setting JAVA_HOME"
echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" >>~/.bashrc
echo "export PATH=$PATH:$JAVA_HOME/bin" >>~/.bashrc
source ~/.bashrc

# Install PostgreSQL
echo "Installing PostgreSQL"
sudo apt-get -y install postgresql

# Install OpenFire
echo "Installing OpenFire"
wget https://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4.9.2_all.deb -O openfire.deb
sudo apt install -y ./openfire.deb

## Software configuration
# Configure PostgreSQL
echo "Configuring PostgreSQL"
sudo -u postgres psql -c "CREATE USER openfire WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE openfire;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE openfire TO openfire;"
sudo -u postgres psql -c "ALTER USER openfire WITH SUPERUSER;"

# Get certificate for the openfire domain using certbot
echo "Obtaining SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# After certificate generation
OF_CERTS=$(sudo ls /etc/letsencrypt/live/${FQDN}/fullchain.pem /etc/letsencrypt/live/${FQDN}/privkey.pem 2>/dev/null)

# After getting certificates with certbot, copy them to OpenFire's directory
echo "Copying certificates to OpenFire"
sudo mkdir -p /etc/openfire/security
sudo cp /etc/letsencrypt/live/${FQDN}/fullchain.pem /etc/openfire/security/
sudo cp /etc/letsencrypt/live/${FQDN}/privkey.pem /etc/openfire/security/
sudo chown -R openfire:openfire /etc/openfire/security
sudo chmod 640 /etc/openfire/security/fullchain.pem
sudo chmod 640 /etc/openfire/security/privkey.pem

# Create a PKCS12 file from the certificates
echo "Creating PKCS12 file for OpenFire"
PKCS_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
sudo openssl pkcs12 -export -out /etc/openfire/security/openfire.pkcs12 \
  -inkey /etc/openfire/security/privkey.pem \
  -in /etc/openfire/security/fullchain.pem \
  -name "${FQDN}" \
  -password pass:${PKCS_PASSWORD} 

# Convert PKCS12 to Java keystore
sudo keytool -importkeystore \
  -srckeystore /etc/openfire/security/openfire.pkcs12 \
  -srcstoretype PKCS12 \
  -srcstorepass ${PKCS_PASSWORD} \
  -destkeystore /etc/openfire/security/keystore \
  -deststorepass ${PKCS_PASSWORD} \
  -alias "${FQDN}"


# Create truststore with the same certificate
sudo keytool -import -trustcacerts -noprompt \
  -file /etc/openfire/security/fullchain.pem \
  -alias "${FQDN}" \
  -keystore /etc/openfire/security/truststore \
  -storepass ${PKCS_PASSWORD}

# Set proper ownership
sudo chown -R openfire:openfire /etc/openfire/security

# Move keystores to default diredctory
sudo cp /etc/openfire/security/keystore /usr/share/openfire/resources/security/
sudo cp /etc/openfire/security/truststore /usr/share/openfire/resources/security/


# Autosetup for OpenFire
echo "Creating autosetup file for OpenFire"
OF_ADMIN_PWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
cat <<EOF | sudo tee /etc/openfire/openfire.xml
<?xml version="1.0" encoding="UTF-8"?>
<jive>
  <autosetup>
    <run>true</run>
    <locale>en</locale>

    <cross-domain>
      <enabled>true</enabled>
      <allow-all-domains>true</allow-all-domains>
    </cross-domain>
    
    <xmpp>
        <domain>${FQDN}</domain>
        <fqdn>${FQDN}</fqdn>
        <auth>
            <anonymous>true</anonymous>
        </auth>
    </xmpp>
    
    <database>
        <mode>standard</mode>
        <defaultProvider>
            <driver>org.postgresql.Driver</driver>
            <serverURL>jdbc:postgresql://localhost:5432/openfire</serverURL>
            <username>openfire</username>
            <password>${DB_PASSWORD}</password>
            <minConnections>5</minConnections>
            <maxConnections>25</maxConnections>
            <connectionTimeout>1.0</connectionTimeout>
        </defaultProvider>
    </database>
    
    <admin>
      <email>admin@${DOMAIN}</email>
      <password>${OF_ADMIN_PWD}</password>
    </admin>

  </autosetup>
</jive>    
EOF

# Restart OpenFire to apply the configuration
echo "Restarting OpenFire"
sudo systemctl restart openfire

wait_for_openfire

# Install booksmarks plugin
echo "Installing OpenFire Bookmarks plugin"
sudo wget -O /tmp/bookmarks.jar https://www.igniterealtime.org/projects/openfire/plugins/bookmarks.jar
sudo mv /tmp/bookmarks.jar /usr/share/openfire/plugins/

# Install Certificate Manager plugin
echo "Installing OpenFire Certificate Manager plugin"
sudo wget -O /tmp/certmanager.jar https://www.igniterealtime.org/projects/openfire/plugins/certmanager.jar
sudo mv /tmp/certmanager.jar /usr/share/openfire/plugins/

# Install Monitoring Service plugin
echo "Installing OpenFire Monitoring Service plugin"
sudo wget -O /tmp/monitoring.jar https://www.igniterealtime.org/projects/openfire/plugins/monitoring.jar
sudo mv /tmp/monitoring.jar /usr/share/openfire/plugins/

# Install and enable the REST API plugin
echo "Installing and enabling OpenFire REST API plugin"
sudo wget -O /tmp/restAPI.jar https://www.igniterealtime.org/projects/openfire/plugins/restAPI.jar
sudo mkdir -p /usr/share/openfire/plugins/restapi/
echo "plugin.restapi.enabled=true" | sudo tee /usr/share/openfire/plugins/restapi/plugin.properties > /dev/null
sudo cp /tmp/restAPI.jar /usr/share/openfire/plugins/

# WebSocket plugin
echo "Installing OpenFire WebSocket plugin"
sudo wget -O /tmp/websocket.jar https://www.igniterealtime.org/projects/openfire/plugins/websocket.jar
sudo mv /tmp/websocket.jar /usr/share/openfire/plugins/

# HTTP File Upload
echo "Installing OpenFire HTTP File Upload plugin"
sudo wget -O /tmp/httpfileupload.jar https://www.igniterealtime.org/projects/openfire/plugins/httpFileUpload.jar
sudo mv /tmp/httpfileupload.jar /usr/share/openfire/plugins/

# Pade (Jitsi client)
echo "Installing OpenFire Pade plugin"
sudo wget -O /tmp/pade.jar https://www.igniterealtime.org/projects/openfire/plugins/pade.jar
sudo mv /tmp/pade.jar /usr/share/openfire/plugins/

# User Import/Export
echo "Installing OpenFire User Import/Export plugin"
sudo wget -O /tmp/userImportExport.jar https://www.igniterealtime.org/projects/openfire/plugins/userImportExport.jar
sudo mv /tmp/userImportExport.jar /usr/share/openfire/plugins/

# S2S (Server-to-Server)
echo "Installing OpenFire S2S plugin"
sudo wget -O /tmp/s2s.jar https://www.igniterealtime.org/projects/openfire/plugins/s2s.jar
sudo mv /tmp/s2s.jar /usr/share/openfire/plugins/

# Load Testing
echo "Installing OpenFire Load Testing plugin"
sudo wget -O /tmp/loadStats.jar https://www.igniterealtime.org/projects/openfire/plugins/loadStats.jar
sudo mv /tmp/loadStats.jar /usr/share/openfire/plugins/

# Restart nginx to apply the new configuration
echo "Restarting Nginx"
sudo systemctl restart nginx
# Restart OpenFire to apply the new plugins
echo "Restarting OpenFire"  
sudo systemctl restart openfire


## Write Configuration to File
# Save host data to file for reference
echo "Saving host data"
cat <<EOF >~/server_config.txt
-- Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}

EOF
echo "Saving Jitsi configuration"
# TODO: Save Jitsi configuration to file
cat <<EOF >>~/server_config.txt
-- Jitsi Configuration --
Jitsi FQDN: ${FQDN}
Jitsi IP Address: ${IP} 

focus:${FOCUS_PASSWORD}
jvb:${JVB_PASSWORD}

Jitsi Certs:
${JITSI_CERTS}

EOF
# Save OpenFire configuration to file
echo "Saving Openfire configuration"
cat <<EOF >>~/server_config.txt
-- OpenFire Configuration --
OpenFire FQDN: ${FQDN}
OpenFire IP Address: ${IP}

OpenFire Certs:
${OF_CERTS}
pkcs password: ${PKCS_PASSWORD}
OpenFire Database:
    Database Type: PostgreSQL
    Database Name: openfire
    Database User: openfire
    Database Password: ${DB_PASSWORD}
OpenFire Admin:
    Username: admin
    Password: ${OF_ADMIN_PWD}
EOF
chmod 600 ~/server_config.txt
echo "Database credentials saved to ~/server_config.txt"

### Part 2
# Set recommended system properties for Jitsi integration
echo "Setting recommended OpenFire system properties"

# Wait for plugins to load
sleep 30

# Increase resource cache size
curl -X PUT -H "Content-Type: application/json" -d "{\"value\":\"1000\"}" \
  http://localhost:9997/plugins/restapi/v1/system/properties/cache.fileTransfer.size

# Increase maximum MUC history size
curl -X PUT -H "Content-Type: application/json" -d "{\"value\":\"200\"}" \
  http://localhost:9997/plugins/restapi/v1/system/properties/xmpp.muc.history.maxNumber

# Enable CORS for HTTP binding (needed for Jitsi web clients)
curl -X PUT -H "Content-Type: application/json" -d "{\"value\":\"true\"}" \
  http://localhost:9997/plugins/restapi/v1/system/properties/xmpp.httpbind.client.cors.enabled

# Set session timeout higher for long meetings
curl -X PUT -H "Content-Type: application/json" -d "{\"value\":\"120\"}" \
  http://localhost:9997/plugins/restapi/v1/system/properties/xmpp.session.timeout
