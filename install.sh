#!/bin/bash

apt --fix-missing update && apt update && apt upgrade -y
wget -q -O install https://gitea.com/rsvofc/new/raw/branch/main/v1/rsv.sh
chmod +x install
./install