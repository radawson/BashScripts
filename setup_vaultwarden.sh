#!/bin/bash
#Script to setup Vaultwarden with nginx Proxy
#(c) 2022 Richard Dawson
VERSION="1.0.0"

## MAIN ##
sudo apt update
sudo apt-get -y dist-upgrade

# Clean out old docker installations
sudo apt-get -y remove docker
sudo apt-get -y remove docker-engine
sudo apt-get -y remove docker.io
sudo apt-get -y remove containerd
sudo apt-get -y remove runc

# Install required OS components
# Note: this is normally unnecessary, but might be required
# for a minimum installation
sudo apt-get -y install ca-certificates 
sudo apt-get -y install curl 
sudo apt-get -y install gnupg 
sudo apt-get -y installlsb-release

# Add docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add docker stable repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  
# # Install the latest stable Docker version
sudo apt-get update
sudo apt-get -y install docker-ce
sudo apt-get -y install docker-ce-cli
sudo apt-get -y install containerd.io
sudo apt-get -y install docker-compose-plugin

sudo systemctl enable --now docker

sudo usermod -aG docker "${USER}"

# Install docker-compose
sudo apt-get -y install docker-compose

# Create internal docker network
docker network create internal

# Install vaultwarden
mkdir -p ~/dockers/vaultwarden/vw-data
cd ~/dockers/vaultwarden

# Create docker-compose file
cat << EOF > docker-compose.yml
---
version: "2.1"
services:
   vaultwarden:
    image: vaultwarden/server
    container_name: vaultwarden
    volumes:
      - ./vw-data/:/data/
    ports:
      - 127.0.0.1:8088:80
      - 3012:3012
    restart: unless-stopped
networks:
  default:
    external:
      name: internal
EOF

docker-compose up -d

# Install NginX Proxy Manager
mkdir ~/dockers/nginxproxymanager
cd ~/dockers/nginxproxymanager
mkdir data letsencrypt

cat << EOF > docker-compose.yml
version: '3'
services:
  app:
     image: 'jc21/nginx-proxy-manager:latest'
     restart: unless-stopped
     ports:
       - '80:80'
       - '81:81'
       - '443:443'
     environment:
       DB_MYSQL_HOST: "db"
       DB_MYSQL_PORT: 3306
       DB_MYSQL_USER: "npm"
       DB_MYSQL_PASSWORD: "f8j3u7ydFF@#GHR"
       DB_MYSQL_NAME: "npm"
     volumes:
       - ./data:/data
       - ./letsencrypt:/etc/letsencrypt
  db:
     image: 'jc21/mariadb-aria:latest'
     restart: unless-stopped
     environment:
       MYSQL_ROOT_PASSWORD: '9jf9834jkjdshf983#$F'
       MYSQL_DATABASE: 'npm'
       MYSQL_USER: 'npm'
       MYSQL_PASSWORD: 'f8j3u7ydFF@#GHR'
     volumes:
       - ./data/mysql:/var/lib/mysql
networks:
  default:
    external:
      name: internal
EOF