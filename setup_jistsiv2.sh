#!/bin/bash

FQDN = ${1}
IP = ${2}

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
sudo ufw enable --force

## Repository Preparation
# Ensure support for apt repositories served via HTTPS
echo "Installing apt-transport-https"
sudo apt install apt-transport-https

# Add Ubuntu universe repository
echo "Adding Ubuntu universe repository"
sudo apt-add-repository universe

# Add OpenJDK repository
echo "Adding OpenJDK repository"
sudo apt-add-repository ppa:openjdk-r/ppa

# Set JAVA_HOME
echo "Setting JAVA_HOME"
echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" >> ~/.bashrc
echo "export PATH=$PATH:$JAVA_HOME/bin" >> ~/.bashrc
source ~/.bashrc

# Add Maven repository
echo "Adding Maven repository"
sudo apt-add-repository ppa:andrei-pozolotin/maven3

# Add PostgreSQL repository
echo "Adding PostgreSQL repository"
sudo apt install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh

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
