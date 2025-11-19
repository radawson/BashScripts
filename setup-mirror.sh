#!/bin/bash

# This script sets up a local mirror of the Ubuntu package repository.
# It uses apt-mirror and nginx to create the mirror and configures the system
# to use the local mirror for package installations.

set -e

# Variables
if [ -z "$1" ]; then
  echo "Usage: $0 <your-domain>"
  exit 1
fi

DOMAIN="$1"
MIRROR_DIR="/var/spool/apt-mirror"
NGINX_CONF="/etc/nginx/sites-available/ubuntu-mirror"
NGINX_LINK="/etc/nginx/sites-enabled/ubuntu-mirror"

# Install necessary packages
echo "Installing apt-mirror and nginx..."
sudo apt-get update
sudo apt-get install -y apt-mirror nginx
sudo apt-get -y autoremove
sudo apt-get -y clean

# Configure apt-mirror
echo "Configuring apt-mirror..."
sudo bash -c "cat > /etc/apt/mirror.list <<EOL
set base_path $MIRROR_DIR
set mirror_path \$base_path/mirror
set skel_path \$base_path/skel
set var_path \$base_path/var
set cleanscript \$var_path/clean.sh
set defaultarch amd64
set nthreads 20
set _tilde 0  

deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse


EOL"

# Configure nginx to serve the mirror
echo "Configuring nginx to serve the mirror..."
sudo bash -c "cat > $NGINX_CONF <<EOL
server {
    listen 80;
    server_name mirror.${DOMAIN};  

    location /ubuntu/ {
        alias $MIRROR_DIR/mirror/archive.ubuntu.com/ubuntu/;
        autoindex on;
    }
}
EOL"

sudo ln -s $NGINX_CONF $NGINX_LINK
sudo nginx -t
sudo nginx -s reload

# Run apt-mirror to create the mirror