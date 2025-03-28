#!/bin/bash
v1.0.0
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
  while ! curl -s -o /dev/null http://localhost:9997; do
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
OF_FQDN="openfire.${DOMAIN}"

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
sudo ufw allow 9997/tcp  # OpenFire admin console direct
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

# Add Jitsi repository
echo "Adding Jitsi repository"
curl -sL https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" | sudo tee /etc/apt/sources.list.d/jitsi-stable.list >/dev/null

# Update package list
sudo apt-get update

## Software Installation
# Install CertBot
echo "Installing CertBot (snap)"
sudo apt-get remove -y certbot --purge
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Install OpenJDK
echo "Installing OpenJDK"
sudo apt-get -y install openjdk-24-jdk

# Set JAVA_HOME
echo "Setting JAVA_HOME"
echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" >>~/.bashrc
echo "export PATH=$PATH:$JAVA_HOME/bin" >>~/.bashrc
source ~/.bashrc

# Install Maven
echo "Installing Maven"
sudo apt-get -y install maven

# Install PostgreSQL
echo "Installing PostgreSQL"
sudo apt-get -y install postgresql

# Install Jitsi
echo "Installing Jitsi"
sudo apt-get -y install jitsi-meet

# Shut down prosody to prevent conflicts with OpenFire
sudo systemctl stop prosody
sudo systemctl disable prosody

# Get Jitsi certs
JITSI_CERTS=$(sudo ls /etc/letsencrypt/live/${FQDN}/fullchain.pem /etc/letsencrypt/live/${FQDN}/privkey.pem 2>/dev/null)

#Shut down nginx to prevent conflicts with OpenFire
sudo systemctl stop nginx

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
echo "Obtaining SSL certificate for ${OF_FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} -d ${OF_FQDN} --preferred-challenges http-01
# Create a symlink to the certificate for Nginx
sudo ln -sf /etc/letsencrypt/live/${OF_FQDN}/fullchain.pem /etc/ssl/certs/openfire.crt
sudo ln -sf /etc/letsencrypt/live/${OF_FQDN}/privkey.pem /etc/ssl/private/openfire.key
# Set permissions on the certificate files
sudo chmod 644 /etc/ssl/certs/openfire.crt
sudo chmod 600 /etc/ssl/private/openfire.key

# After getting certificates with certbot, copy them to OpenFire's directory
echo "Copying certificates to OpenFire"
sudo mkdir -p /etc/openfire/security
sudo cp /etc/letsencrypt/live/${OF_FQDN}/fullchain.pem /etc/openfire/security/
sudo cp /etc/letsencrypt/live/${OF_FQDN}/privkey.pem /etc/openfire/security/
sudo chown -R openfire:openfire /etc/openfire/security
sudo chmod 640 /etc/openfire/security/*.pem

# Create a PKCS12 file from the certificates
sudo openssl pkcs12 -export -out /etc/openfire/security/openfire.pkcs12 \
  -inkey /etc/openfire/security/privkey.pem \
  -in /etc/openfire/security/fullchain.pem \
  -name "${OF_FQDN}" \
  -password pass:changeit

# Convert PKCS12 to Java keystore
sudo keytool -importkeystore \
  -srckeystore /etc/openfire/security/openfire.pkcs12 \
  -srcstoretype PKCS12 \
  -srcstorepass changeit \
  -destkeystore /etc/openfire/security/keystore \
  -deststorepass changeit \
  -alias "${OF_FQDN}"

# Create truststore with the same certificate
sudo keytool -import -trustcacerts -noprompt \
  -file /etc/openfire/security/fullchain.pem \
  -alias "${OF_FQDN}" \
  -keystore /etc/openfire/security/truststore \
  -storepass changeit

# Set proper ownership
sudo chown -R openfire:openfire /etc/openfire/security

# Configure Nginx for Openfire
echo "Configuring Nginx for Openfire"
cat <<EOF | sudo tee /etc/nginx/sites-available/openfire.conf
server {
    listen 80;
    server_name ${OF_FQDN};

    location / {
        proxy_pass http://localhost:9997;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        
        # Add WebSocket support
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Only add SSL server block if certificates exist
if sudo test -f /etc/letsencrypt/live/${OF_FQDN}/fullchain.pem && sudo test -f /etc/letsencrypt/live/${OF_FQDN}/privkey.pem; then
    cat <<EOF | sudo tee -a /etc/nginx/sites-available/openfire.conf
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${OF_FQDN};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m; 
    ssl_session_tickets off;

    ssl_certificate /etc/letsencrypt/live/${OF_FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${OF_FQDN}/privkey.pem;

    location / {
        proxy_pass http://localhost:9997;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        
        # Add WebSocket support
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

OF_CERTS=$(sudo ls /etc/letsencrypt/live/${OF_FQDN}/fullchain.pem /etc/letsencrypt/live/${OF_FQDN}/privkey.pem 2>/dev/null)
else
    echo "Warning: SSL certificates not found. HTTPS configuration for OpenFire not added."
    echo "You can add it later by running certbot for ${OF_FQDN} and updating the Nginx configuration."
OF_CERTS="SSL not installed"
fi

# Enable the Nginx site
sudo ln -sf /etc/nginx/sites-available/openfire.conf /etc/nginx/sites-enabled/
sudo systemctl start nginx

# Autosetup for OpenFire
echo "Creating autosetup file for OpenFire"
OF_ADMIN_PWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
cat <<EOF | sudo tee /etc/openfire/openfire.xml
<?xml version="1.0" encoding="UTF-8"?>
<jive>
  <autosetup>
    <run>true</run>
    <locale>en</locale>
    <adminConsole>
      <!-- Disable either port by setting the value to -1 -->
      <port>9997</port>
      <securePort>-1</securePort>
      <interface>0.0.0.0</interface>
    </adminConsole>
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
sleep 10
sudo systemctl stop openfire

# Create new XML content with proper admin console settings
sudo sed -i 's|</jive>|<adminConsole>\
    <port>9997</port>\
    <securePort>-1</securePort>\
    <interface>127.0.0.1</interface>\
</adminConsole>\
</jive>|' /etc/openfire/openfire.xml

# Start OpenFire with the updated configuration
sudo systemctl start openfire


# Configure Jitsi Meet to use OpenFire instead of Prosody
echo "Configuring Jitsi Meet to use OpenFire"
sudo sed -i "s/muc:.*/muc: '${FQDN}',/" /etc/jitsi/meet/${FQDN}-config.js
sudo sed -i "s|bosh:.*|bosh: '//${FQDN}/http-bind',|" /etc/jitsi/meet/${FQDN}-config.js

# Configure Jicofo to use OpenFire - correct format
echo "Configuring Jicofo for OpenFire"
sudo tee /etc/jitsi/jicofo/jicofo.conf > /dev/null << EOF
jicofo {
  authentication {
    enabled = true
    type = XMPP
    login-url = "xmpp://${FQDN}:5222"
    enable-auto-login = true
  }
  
  xmpp {
    client {
      enabled = true
      hostname = "${FQDN}"
      port = 5222
      domain = "${FQDN}"
      username = "focus"
      password = "${FOCUS_PASSWORD}"
      conference-muc-jid = "conference.${FQDN}"
    }
  }
}
EOF

# Create the old-style config for backward compatibility
echo "Creating legacy Jicofo configuration"
sudo tee /etc/jitsi/jicofo/config > /dev/null << EOF
# Jitsi Conference Focus settings
JICOFO_HOST=localhost
JICOFO_HOSTNAME=${FQDN}

# XMPP components
JICOFO_AUTH_USER=focus
JICOFO_AUTH_PASSWORD=${FOCUS_PASSWORD}
JICOFO_PORT=5222
EOF

# Configure JVB to use OpenFire
echo "Configuring JVB for OpenFire"
sudo tee /etc/jitsi/videobridge/config > /dev/null << EOF
videobridge {
  apis {
    xmpp-client {
      configs {
        shard {
          HOSTNAME = "${FQDN}"
          PORT = "5222"
          DOMAIN = "${FQDN}"
          USERNAME = "jvb"
          PASSWORD = "${JVB_PASSWORD}"
          MUC_JIDS = "jvbbrewery@internal.${FQDN}"
          MUC_NICKNAME = "jvb-\${ID}"
          DISABLE_CERTIFICATE_VERIFICATION = true
        }
      }
    }
  }
}
EOF

# Wait for OpenFire to be ready
echo "Waiting for OpenFire to start..."
sleep 20  # Basic wait, could be improved with a proper check

# Install OpenFire REST API plugin
echo "Installing OpenFire REST API plugin"
sudo wget -O /tmp/restAPI.jar https://www.igniterealtime.org/projects/openfire/plugins/restAPI.jar
sudo mv /tmp/restAPI.jar /usr/share/openfire/plugins/

# WebSocket plugin
echo "Installing OpenFire WebSocket plugin"
sudo wget -O /tmp/websocket.jar https://www.igniterealtime.org/projects/openfire/plugins/websocket.jar
sudo mv /tmp/websocket.jar /usr/share/openfire/plugins/

# HTTP File Upload
echo "Installing OpenFire HTTP File Upload plugin"
sudo wget -O /tmp/httpfileupload.jar https://www.igniterealtime.org/projects/openfire/plugins/httpFileUpload.jar
sudo mv /tmp/httpfileupload.jar /usr/share/openfire/plugins/

# Jingle Nodes
echo "Installing OpenFire Jingle Nodes plugin"
sudo wget -O /tmp/jinglenodes.jar https://www.igniterealtime.org/projects/openfire/plugins/jinglenodes.jar
sudo mv /tmp/jinglenodes.jar /usr/share/openfire/plugins/

# User Import/Export
echo "Installing OpenFire User Import/Export plugin"
sudo wget -O /tmp/userImportExport.jar https://www.igniterealtime.org/projects/openfire/plugins/userImportExport.jar
sudo mv /tmp/userImportExport.jar /usr/share/openfire/plugins/

# Connection Manager
echo "Installing OpenFire Connection Manager plugin"
sudo wget -O /tmp/connectionmanager.jar https://www.igniterealtime.org/projects/openfire/plugins/connection_manager.jar
sudo mv /tmp/connectionmanager.jar /usr/share/openfire/plugins/

# Load Testing
echo "Installing OpenFire Load Testing plugin"
sudo wget -O /tmp/loadStats.jar https://www.igniterealtime.org/projects/openfire/plugins/loadStats.jar
sudo mv /tmp/loadStats.jar /usr/share/openfire/plugins/

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

# Wait for settings to be activated
sleep 10

# Create the focus user and JVB user
echo "Creating required users via REST API"
curl -X POST -H "Content-Type: application/json" -d "{\"username\":\"focus\",\"password\":\"${FOCUS_PASSWORD}\",\"name\":\"Focus User\",\"email\":\"focus@${DOMAIN}\"}" http://localhost:9997/plugins/restapi/v1/users
curl -X POST -H "Content-Type: application/json" -d "{\"username\":\"jvb\",\"password\":\"${JVB_PASSWORD}\",\"name\":\"JVB User\",\"email\":\"jvb@${DOMAIN}\"}" http://localhost:9997/plugins/restapi/v1/users

# Create MUC room
# Update MUC room creation command
curl -X POST -H "Content-Type: application/json" -d "{\"roomName\":\"jvbbrewery\",\"naturalName\":\"JVB Brewery\",\"description\":\"JVB Conference Room\",\"persistent\":true,\"service\":\"conference.${FQDN}\"}" http://localhost:9997/plugins/restapi/v1/chatrooms
# Configure OpenFire for Jitsi
echo "Configuring OpenFire for Jitsi compatibility"

# Download and install required plugins
sudo wget -O /tmp/monitoring.jar https://www.igniterealtime.org/projects/openfire/plugins/monitoring.jar
sudo mv /tmp/monitoring.jar /usr/share/openfire/plugins/

# Enable anonymous login (required for Jitsi guests)
curl -X PUT -H "Content-Type: application/json" -d "{\"enabled\":true}" http://localhost:9997/plugins/restapi/v1/system/properties/xmpp.anonymous.login.enabled

# Enable MUC service
curl -X PUT -H "Content-Type: application/json" -d "{\"enabled\":true}" http://localhost:9997/plugins/restapi/v1/system/properties/xmpp.muc.enabled

# Restart all Jitsi components
echo "Restarting Jitsi services"
sudo systemctl restart jicofo
sudo systemctl restart jitsi-videobridge2
sudo systemctl restart nginx
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
