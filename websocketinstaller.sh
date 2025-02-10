#!/bin/bash
#installer Websocket tunneling 
#by RSV
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
green "Installing Websocket Services"
link="https://raw.githubusercontent.com/rsvofc/new/main/v1"
cd
#Install Script Websocket-SSH Python
wget -q -O /usr/local/bin/ws-dropbear ${link}/ws-dropbear
wget -q -O /usr/local/bin/ws-stunnel ${link}/ws-stunnel

#izin permision
chmod +x /usr/local/bin/ws-dropbear
chmod +x /usr/local/bin/ws-stunnel

#System Dropbear Websocket-SSH Python
wget -q -O /etc/systemd/system/ws-dropbear.service ${link}/ws-dropbear.service && chmod +x /etc/systemd/system/ws-dropbear.service

#System SSL/TLS Websocket-SSH Python
wget -q -O /etc/systemd/system/ws-stunnel.service ${link}/ws-stunnel.service && chmod +x /etc/systemd/system/ws-stunnel.service

#restart service
systemctl daemon-reload

#Enable & Start & Restart ws-dropbear service
systemctl enable ws-dropbear.service
systemctl start ws-dropbear.service
systemctl restart ws-dropbear.service

#Enable & Start & Restart ws-openssh service
systemctl enable ws-stunnel.service
systemctl start ws-stunnel.service
systemctl restart ws-stunnel.service
green "DONE"
clear