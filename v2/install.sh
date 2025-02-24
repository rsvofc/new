#!/bin/bash

apt --fix-missing update && apt update && apt upgrade -y
wget -q -O install https://raw.githubusercontent.com/rsvofc/new/main/v2/rsv.sh
chmod +x install
./install