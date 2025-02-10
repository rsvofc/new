#!/bin/bash
# Provide by Zenvio
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
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
clear
# VPS Information
DATE=$(date +'%Y-%m-%d')
today=`date -d "0 days" +"%Y-%m-%d"`
# CERTIFICATE STATUS
d1=$(date -d "$exp2" +%s)
d2=$(date -d "$exp1" +%s)
certificate=$(( (d1 - d2) / 86400 ))
# Download
vnstat_profile=$(vnstat | sed -n '3p' | awk '{print $1}' | grep -o '[^:]*')
vnstat -i ${vnstat_profile} >/root/t1
bulan=$(date +%b)
today=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $8}')
todayd=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $8}')
today_v=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $9}')
today_rx=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $2}')
today_rxv=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $3}')
today_tx=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $5}')
today_txv=$(vnstat -i ${vnstat_profile} | grep today | awk '{print $6}')
if [ "$(grep -wc ${bulan} /root/t1)" != '0' ]; then
    bulan=$(date +%b)
    month=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $9}')
    month_v=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $10}')
    month_rx=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $3}')
    month_rxv=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $4}')
    month_tx=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $6}')
    month_txv=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $7}')
else
    bulan=$(date +%Y-%m)
    month=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $8}')
    month_v=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $9}')
    month_rx=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $2}')
    month_rxv=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $3}')
    month_tx=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $5}')
    month_txv=$(vnstat -i ${vnstat_profile} | grep "$bulan " | awk '{print $6}')
fi
# Getting CPU Information & VPS Information
OS=$(cat /etc/os-release | grep "^PRETTY_NAME" | cut -d '"' -f2)
KERNEL=$(uname -r)
uptime="$(uptime -p | cut -d " " -f 2-10)"
cpu_usage1="$(ps aux | awk 'BEGIN {sum=0} {sum+=$3}; END {print sum}')"
cpu_usage="$((${cpu_usage1/\.*} / ${corediilik:-1}))"
cpu_usage+=" %"
nami=$(cat /etc/.vvt/name)
domain=$(cat /etc/xray/domain)
ISP=$(cat /usr/local/etc/xray/org)
WKT=$(cat /usr/local/etc/xray/timezone)
CNT=$(cat /usr/local/etc/xray/country)
DAY=$(date +%A)
DATE=$(date +%m/%d/%Y)
DATE2=$(date -R | cut -d " " -f -5)
IPVPS=$(cat /etc/.vvt/ipv4)
Name=$(cat /etc/.vvt/name)
cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
tram=$( free -m | awk 'NR==2 {print $2}' )
uram=$( free -m | awk 'NR==2 {print $3}' )
fram=$( free -m | awk 'NR==2 {print $4}' )

# Mendapatkan total RAM dan RAM yang digunakan (dalam MB)
tram=$(free -m | awk 'NR==2 {print $2}')
uram=$(free -m | awk 'NR==2 {print $3}')

# Menghitung persentase penggunaan RAM
percent=$((uram * 100 / tram))

# Definisi warna
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
NC="\e[0m" # No Color

# Menentukan warna berdasarkan persentase penggunaan RAM
if [ $percent -le 30 ]; then
    COLOR=$GREEN
elif [ $percent -le 60 ]; then
    COLOR=$YELLOW
else
    COLOR=$RED
fi

# Output dengan pewarnaan


#STATUS RUNNING
cek=$(service ssh status | grep active | cut -d ' ' -f5)
if [ "$cek" = "active" ]; then
stat=-f5
else
stat=-f7
fi
ssh=$(service ssh status | grep active | cut -d ' ' $stat)
if [ "$ssh" = "active" ]; then
xssh="${green}ON ${NC}"
else
xssh="${red}OFF${NC}"
fi
nginx=$(service nginx status | grep active | cut -d ' ' $stat)
if [ "$nginx" = "active" ]; then
xnginx="${green}ON ${NC}"
else
xnginx="${red}OFF${NC}"
fi
xray=$(service xray status | grep active | cut -d ' ' $stat)
if [ "$xray" = "active" ]; then
xxray="${green}ON ${NC}"
else
xxray="${red}OFF${NC}"
fi
# CERTIFICATE STATUS
myuser=$(cat /etc/.vvt/user)
today=$(date -d +0day +%Y-%m-%d)
exp=$(cat /etc/.vvt/exp)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$today" +%s)
expday=$(( (d1 - d2) / 86400 ))
scversion=$(cat /etc/.vvt/version)
clear 
echo ""
echo -e "${PURPLE}╒════════════════════════════════════════════╕\033[0m"
echo -e "${PURPLE}┃${NC}\E[0;41;32m       ••••• SYSTEM INFORMATION •••••       \E[0m${PURPLE}┃${NC}"
echo -e "${PURPLE}╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -e " OS System    :  ${BLUE}$OS${NC}"	
echo -e " Uptime       :  ${BLUE}$uptime${NC}"	
echo -e " ISP          :  ${GREEN}$ISP${NC}"	
echo -e " IP VPS       :  ${GREEN}$IPVPS${NC}"
echo -e " Domain       :  ${PURPLE}$domain${NC}"
echo -e " Timezone     :  ${PURPLE}$WKT${NC}"
echo -e " Country      :  ${PURPLE}$CNT${NC}"
echo -e " RAM Usage    :  ${COLOR}${uram}${NC} MB / ${BLUE}${tram}${NC} MB (${percent}%)"
echo -e " Bandwidth D  \e[0m:  \e[32m$todayd\e[0m \e[32m$today_v\e[0m (Daily)"
echo -e " Bandwidth M  \e[0m:  \e[32m$month\e[0m \e[32m$month_v\e[0m (Monthly)"
echo -e " SSH Status   :  $xssh "
echo -e " Nginx Status :  $xnginx"
echo -e " Xray Status  :  $xxray"
echo ""
echo -e "${PURPLE}╒════════════════════════════════════════════╕\033[0m"
echo -e "${PURPLE}┃${NC}\E[0;41;32m       ••••• SCRIPT INFORMATION •••••       \E[0m${PURPLE}┃${NC}"
echo -e "${PURPLE}╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -e " \e[32mOwner      \e[0m : ${GREEN}RSV Official${NC}"
echo -e " \e[32mVersion    \e[0m : ${GREEN}RSV $scversion LTS${NC}"
echo -e " \e[32mExpired    \e[0m : ${GREEN}$expday${NC} Days remaining"
echo -e " \e[32mUser       \e[0m : ${ORANGE}$myuser${NC}"
echo ""
echo -e "${PURPLE}╒════════════════════════════════════════════╕\033[0m"
echo -e "${PURPLE}┃${NC}\E[0;41;32m            ••••• VPS MENU •••••            \E[0m${PURPLE}┃${NC}"
echo -e "${PURPLE}╘════════════════════════════════════════════╛\033[0m"
echo ""
echo -e " 01. ${RED}=>${NC}${CYAN} SSH Menu${NC}       07. ${RED}=>${NC}${CYAN} Running${NC}   "
echo -e " 02. ${RED}=>${NC}${CYAN} Vmess Menu${NC}     08. ${RED}=>${NC}${CYAN} Restart VPN${NC}   "
echo -e " 03. ${RED}=>${NC}${CYAN} Vless Menu${NC}     09. ${RED}=>${NC}${CYAN} Speedtest${NC}     "
echo -e " 04. ${RED}=>${NC}${CYAN} Trojan Menu${NC}    10. ${RED}=>${NC}${CYAN} Domain Menu${NC}   "
echo -e " 05. ${RED}=>${NC}${CYAN} Trial Menu${NC}     11. ${RED}=>${NC}${CYAN} Backup Menu${NC}   "
echo -e " 06. ${RED}=>${NC}${CYAN} Banner SSH${NC}     12. ${RED}=>${NC}${CYAN} Additional Setup${NC}   "
echo -e " ${PURPLE}------------------------------------------${NC}"
echo -e " 100. ${RED}=>${NC}${CYAN} Check Update${NC}  00. ${RED}=>${NC}${CYAN} System Live${NC}  "
echo -e "${PURPLE} ════════════════════════════════════════════\033[0m"
echo -e   ""
read -p " Select menu (00-101) => "  opt
echo -e   ""
case $opt in
1) clear ; sshmenu ;;
2) clear ; vmessmenu ;;
3) clear ; vlessmenu ;;
4) clear ; trojanmenu ;;
5) clear ; trialmenu ;;
6) clear ; nano /etc/banner.com ;;
7) clear ; running ;;
8) clear ; restart ;;
9) clear ; speedtest ;;
10) clear ; domainmenu ;;
11) clear ; backupmenu ;;
12) clear ; settingmenu ;;
100) clear ; updater ;;
00) clear ; gotop ;;
x) exit ;;
*) menu ;;
esac
