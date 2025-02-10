#!/bin/bash

apt --fix-missing update && apt update && apt upgrade -y
wget -q -O install https://raw.githubusercontent.com/rsvofc/new/refs/heads/main/v1/install.sh
chmod +x install
./install
