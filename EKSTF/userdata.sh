#!/bin/bash

# Update and upgrade the system packages
sudo apt-get update -y
sudo apt-get upgrade -y

# Install MySQL client
sudo apt-get install -y mysql-client

# Install AWS CLI
sudo apt-get install -y awscli

