#!/bin/bash
# Color Validation
DF='\e[39m'
Bold='\e[1m'
Blink='\e[5m'
yell='\e[33m'
red='\e[31m'
green='\e[32m'
blue='\e[34m'
PURPLE='\e[35m'
cyan='\e[36m'
Lred='\e[91m'
Lgreen='\e[92m'
Lyellow='\e[93m'
NC='\e[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
LIGHT='\033[0;37m'
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# Data Validity
ssh=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)
vmess=$(cat /etc/client/vms.txt | grep "###" | wc -l)
vless=$(cat /etc/client/vls.txt | grep "###" | wc -l)
trojan=$(cat /etc/client/trj.txt | grep "###" | wc -l)
# CERTIFICATE STATUS
myuser=$(cat /etc/.vvt/user)
today=$(date -d +0day +%Y-%m-%d)
exp=$(cat /etc/.vvt/exp)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$today" +%s)
expday=$(( (d1 - d2) / 86400 ))
scversion=$(cat /etc/.vvt/version)
domain=$(cat /etc/xray/domain)
ISP=$(cat /usr/local/etc/xray/org)
WKT=$(cat /usr/local/etc/xray/timezone)
clear
echo -e "${PURPLE}╒════════════════════════════════════════════╕\033[0m"
echo -e "${PURPLE}┃${NC}\E[0;41;32m       ••••• MEMBER INFORMATION •••••       \E[0m${PURPLE}┃${NC}"
echo -e "${PURPLE}╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -e " ${RED}SSH Account${NC}        :${GREEN} $ssh${NC}"
echo -e " ${RED}Vmess Account${NC}      :${GREEN} $vmess${NC}"
echo -e " ${RED}Vless Account${NC}      :${GREEN} $vless${NC}"
echo -e " ${RED}Trojan Account${NC}     :${GREEN} $trojan${NC}"
echo ""
echo -e "${PURPLE}╒════════════════════════════════════════════╕\033[0m"
echo -e "${PURPLE}┃${NC}\E[0;41;32m       ••••• SCRIPT INFORMATION •••••       \E[0m${PURPLE}┃${NC}"
echo -e "${PURPLE}╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -e " \e[32mOwner      \e[0m : ${GREEN}RSV Official${NC}"
echo -e " \e[32mVersion    \e[0m : ${CYAN}RSV $scversion LTS${NC}"
echo -e " \e[32mExpired    \e[0m : ${GREEN}$expday${NC} Days remaining"
echo -e " \e[32mUser       \e[0m : ${ORANGE}$myuser${NC}"
echo -e " \e[32mISP        \e[0m : ${GREEN}$ISP${NC}"
echo -e " \e[32mRegion     \e[0m : ${ORANGE}$WKT${NC}"
echo ""
echo -e "${PURPLE} ════════════════════════════════════════════\033[0m"
echo ""
echo -e "             Type ${GREEN}[menu]${NC} to start"
echo ""