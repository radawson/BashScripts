#!/bin/bash

sudo apt update
sudo apt-get -y dist-upgrade
sudo apt-get -y autoremove

# Ensure support for apt repositories served via HTTPS
sudo apt install apt-transport-https

# Add Ubuntu universe repository
sudo apt-add-repository universe

# Add OpenJDK repository
sudo apt-add-repository ppa:openjdk-r/ppa

# Add Maven repository
sudo apt-add-repository ppa:andrei-pozolotin/maven3

# Update package list
sudo apt-get update

# Install OpenJDK
sudo apt-get install openjdk-22-jdk

# Install Maven
sudo apt-get install maven