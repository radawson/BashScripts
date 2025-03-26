#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <FQDN> <IP>"
    exit 1
fi

FQDN=${1}
IP=${2}
# Generate a secure random-ish password (16 chars, alphanumeric only)
DB_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

## System Preparation
# Update and upgrade the system
echo "Updating and upgrading the system"
sudo apt update
sudo apt-get -y dist-upgrade
sudo apt-get -y autoremove

# Set hostname in two locations
echo "Setting hostname"
sudo hostnamectl hostname ${FQDN}
sudo echo "${IP} ${FQDN}" >> /etc/hosts

# Configure Firewall
echo "Configuring firewall"
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 10000/udp
sudo ufw allow 22/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
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
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" | sudo tee /etc/apt/sources.list.d/jitsi-stable.list > /dev/null

# Update package list
sudo apt-get update

## Software Installation
# Install OpenJDK
echo "Installing OpenJDK"
sudo apt-get -y install openjdk-22-jdk

# Set JAVA_HOME
echo "Setting JAVA_HOME"
echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" >> ~/.bashrc
echo "export PATH=$PATH:$JAVA_HOME/bin" >> ~/.bashrc
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

# Install OpenFire
echo "Installing OpenFire"
wget https://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4.9.2_all.deb -O openfire.deb
sudo apt install -y ./openfire.deb

## Software configuration
# Configure PostgreSQL
echo "Configuring PostgreSQL"
sudo -u postgres psql -e "CREATE USER openfire WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -e "CREATE DATABASE openfire;"
sudo -u postgres psql -e "GRANT ALL PRIVILEGES ON DATABASE openfire TO openfire;"
sudo -u postgres psql -e "ALTER USER openfire WITH SUPERUSER;"

# Configure Nginx for Openfire
echo "Configuring Nginx for Openfire"
cat <<EOF | sudo tee /etc/nginx/sites-available/openfire
server {
    listen 80;
    server_name ${FQDN};

    location /openfire {
        proxy_pass http://localhost:9090;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable the Nginx site
sudo ln -sf /etc/nginx/sites-available/openfire /etc/nginx/sites-enabled/
sudo systemctl reload nginx

## Write Configuration to File
# Save host data to file for reference
echo "Saving host data"
cat <<EOF > ~/server_config.txt
-- Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}

EOF

echo "Saving Jitsi configuration"
# TODO: Save Jitsi configuration to file
cat <<EOF > ~/server_config.txt
-- Jitsi Configuration --

EOF

# Save database credentials to a file for reference
echo "Saving database credentials"
cat <<EOF > ~/server_config.txt
-- Database Configuration --
Database User: openfire
Database Name: openfire
Database Password: ${DB_PASSWORD}
EOF
chmod 600 ~/server_config.txt
echo "Database credentials saved to ~/server_config.txt"