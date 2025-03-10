#!/bin/bash

echo "
----------------------
  NODE & NPM
----------------------
"

# add nodejs 16 ppa (personal package archive) from nodesource
curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -

# install nodejs and npm
sudo apt-get install -y nodejs


echo "
----------------------
  MONGODB
----------------------
"

# import mongodb 4.0 public gpg key
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -

# create the /etc/apt/sources.list.d/mongodb-org-4.0.list file for mongodb
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list

# reload local package database
sudo apt-get update

# install the latest version of mongodb
sudo apt-get install -y mongodb-org

# start mongodb
sudo systemctl start mongod

# set mongodb to start automatically on system startup
sudo systemctl enable mongod


echo "
----------------------
  PM2
----------------------
"

# install pm2 with npm
sudo npm install -g pm2

# set pm2 to start automatically on system startup
sudo pm2 startup systemd


echo "
----------------------
  NGINX
----------------------
"

# install nginx
sudo apt-get install -y nginx


echo "
----------------------
  UFW (FIREWALL)
----------------------
"

# allow ssh connections through firewall
sudo ufw allow OpenSSH

# allow http & https through firewall
sudo ufw allow 'Nginx Full'

# enable firewall
sudo ufw --force enable