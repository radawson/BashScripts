#!/bin/bash

## Install postgres 17
PASSWORD=$(openssl rand -bse64 32)
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

## Install keycloak
sudo apt-get install -y unzip
wget https://github.com/keycloak/keycloak/releases/download/26.0.7/keycloak-26.0.7.zip
unzip keycloak-26.0.7.zip
rm keycloak-26.0.7.zip

# Create initial user
PASSWORD=$(openssl rand -bse64 18)
KC_BOOTSTRAP_ADMIN_USERNAME="admin"
KC_BOOTSTRAP_ADMIN_PASSWORD="${PASSWORD}"