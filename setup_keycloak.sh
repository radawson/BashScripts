#!/bin/bash

## Install postgres 16
sudo apt-get install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh
sudo apt-get -y install postgresql

sudo -u postgres createuser -s -i -d -r -l -w keycloak
sudo -u postgres psql -c "ALTER ROLE keycloak WITH PASSWORD '';"
sudo -u postgres psql -c 'create database keycloak;'

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
wget https://github.com/keycloak/keycloak/releases/download/25.0.4/keycloak-25.0.4.zip
unzip keycloak-25.0.4.zip
rm keycloak-25.0.4.zip