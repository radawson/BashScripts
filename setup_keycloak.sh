#!/bin/bash

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
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 8080
sudo ufw --force enable

## Install keycloak
sudo apt-get install -y unzip
wget https://github.com/keycloak/keycloak/releases/download/26.0.7/keycloak-26.0.7.zip
unzip keycloak-26.0.7.zip
rm keycloak-26.0.7.zip

# Create initial user
PASSWORD=$(openssl rand -base64 18)
echo "Admin password: ${PASSWORD}" > ~/keycloak.pwd
export KEYCLOAK_ADMIN="admin"
export KEYCLOAK_ADMIN_PASSWORD="${PASSWORD}"


cd keycloak-26.0.7
./bin/kc.sh start-dev