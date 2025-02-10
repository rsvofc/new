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
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

#DATA VALIDATION
rm -rf /etc/.vvt
mkdir /etc/.vvt
touch /etc/.vvt/ip
touch /etc/.vvt/ip1
touch /etc/.vvt/exp
touch /etc/.vvt/chatidbw
touch /etc/.vvt/name
touch /etc/.vvt/chatidbak
touch /root/limitxray.log
touch /etc/.vvt/chatidnot
touch /etc/.vvt/toknot
apt install jq curl -y
apt install curl sudo -y
clear
link="https://raw.githubusercontent.com/rsvofc/new/main/v1"
link2="https://gitlab.com/kenzo6414537/mycore/-/raw/main"
MYIP=$(curl -sS ipv4.icanhazip.com)
echo $MYIP > /etc/.vvt/ipv4
Name=$(curl -sS ${link2}/ip | grep $MYIP | awk '{print $1}')
echo $Name > /etc/.vvt/user
echo $Name > /etc/.vvt/name
Expired=$(curl -sS ${link2}/ip | grep $MYIP | awk '{print $2}')
echo $Expired > /etc/.vvt/exp
ipv4=$(curl -sS ${link2}/ip | grep $MYIP | awk '{print $3}')
echo $ipv4 > /etc/.vvt/ip

exp1=$(date -d +0day +%Y-%m-%d)
exp2=$(cat /etc/.vvt/exp)
ip1=$(cat /etc/.vvt/ip)
ip2=$(cat /etc/.vvt/ipv4)
#Validating
echo -e "${BLUE}VALIDATING IP${NC}"
if [ $ip1 = $ip2 ]; then
echo -e "${GREEN}Your IP is Valid${NC}"
sleep 2
else
echo -e "${RED}Your IP is Invalid${NC}"
exit 0
rm install
rm -rf /etc/.vvt
fi
echo ""
echo -e "${BLUE}VALIDATING EXP${NC}"
if [ $exp2 > $exp1 ]; then
echo -e "${GREEN}Your IP is Active${NC}"
sleep 2
else
clear
echo -e "${RED}Your Permission is valid but they has Expired${NC}"
echo -e "Contact Admin if you want to get a new License or renewal the current License permission"
echo -e "Whatsapp ${GREEN}081977814343${NC}"
echo -e "Telegram ${BLUE}t.me/zenvio${NC}"
exit 0
rm install
rm -rf /etc/.vvt
fi

IP1=$(curl -sS ipv4.icanhazip.com)
echo "$IP1" > /etc/.vvt/ip1
echo "5908612911" > /etc/.vvt/chatidbw
echo "5908612911" > /etc/.vvt/chatidbak
clear
RGN=$(curl -s ipinfo.io/city)
PROVIDER=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
nami=$(cat /etc/.vvt/name)
myuser=$(cat /etc/.vvt/user)
today=$(date -d +0day +%Y-%m-%d)
exp=$(cat /etc/.vvt/exp)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$today" +%s)
expday=$(( (d1 - d2) / 86400 ))
version=$(curl -sS ${link}/version)
cat > /etc/.vvt/version << END
$version
END
echo "$version" > /etc/.vvt/version
touch /etc/version
cat > /etc/version << END
$version
END
clear
red "YOUR DATA INFORMATION"
echo ""
echo -e "Your Name     : ${CYAN}$myuser${NC}"
echo -e "Your IP VPS   : ${ORANGE}$IP1${NC}"
echo -e "Region        : ${GREEN}$RGN${NC}"
echo -e "ISP           : ${GREEN}$PROVIDER${NC}"
echo -e "Expired       : ${RED}$expday${NC} ${GREEN}Days${NC}"
echo ""
purple "Installation will be started in 5 Seconds"
sleep 5
TIMES="10"
CHATID="5908612911"
KEY="6980250010:AAFSowqhte0qjDHFuEmeDj7EQt6vFBiaqjY"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TEXT="
<u>INSTALLATION SCRIPT</u>

<code>Name          : </code><code>${myuser}</code>
<code>IP            : </code><code>${IP1}</code>
<code>Region        : </code><code>${RGN}</code>
<code>ISP           : </code><code>${PROVIDER}</code>
<code>Exp           : </code><code>${expday} Days</code>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
clear
green "INSTALATION STARTED"

cd /root
apt install jq curl -y
apt install curl sudo -y
sudo apt install megatools
mkdir -p /etc/xray
mkdir -p /etc/v2ray
mkdir /etc/xraylog >> /dev/null 2>&1
touch /etc/xray/domain
rm -rf /etc/usg
rm -rf /etc/lmt
rm -rf /etc/client
mkdir /etc/usg
mkdir /etc/lmt
mkdir /etc/client
touch /etc/client/vms.txt
touch /etc/client/vls.txt
touch /etc/client/trj.txt
echo "# Vmess User #" > /etc/client/vms.txt
echo "# Vless User #" > /etc/client/vls.txt
echo "# Trojan User #" > /etc/client/trj.txt
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
sleep 0.5
mkdir /user >> /dev/null 2>&1
apt install resolvconf network-manager dnsutils bind9 -y
cat > /etc/systemd/resolved.conf << END
[Resolve]
DNS=1.1.1.1 1.0.0.1
Domains=~.
ReadEtcHosts=yes
END
systemctl enable resolvconf
systemctl enable systemd-resolved
systemctl enable NetworkManager
rm -rf /etc/resolv.conf
rm -rf /etc/resolvconf/resolv.conf.d/head
echo "
nameserver 1.1.1.1
" >> /etc/resolv.conf
echo "
" >> /etc/resolvconf/resolv.conf.d/head
systemctl restart resolvconf
systemctl restart systemd-resolved
systemctl restart NetworkManager
echo "Cloudflare DNS" > /user/current

mkdir -p /var/lib/zenhost >/dev/null 2>&1
echo "IP=" >> /var/lib/zenhost/ipvps.conf

mkdir -p /usr/local/etc/xray
rm /usr/local/etc/xray/city >> /dev/null 2>&1
rm /usr/local/etc/xray/org >> /dev/null 2>&1
rm /usr/local/etc/xray/timezone >> /dev/null 2>&1
rm /usr/local/etc/xray/country >> /dev/null 2>&1

curl -s "https://ipapi.co/$MYIP/json/" | grep '"country_name"' | awk -F': ' '{gsub(/[",]/, "", $2); print $2}' >> /usr/local/etc/xray/country
curl -s ipinfo.io/city >> /usr/local/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /usr/local/etc/xray/org
curl -s ipinfo.io/timezone >> /usr/local/etc/xray/timezone
echo ""
clear
yellow "Creating Auto Domain"
# // String / Request Data
sub=$(</dev/urandom tr -dc a-z0-9 | head -c5)
DOMAIN=vpnme.biz.id
SUB_DOMAIN=${sub}.vpnme.biz.id
CF_ID=cloudflaredomainpanel@gmail.com
CF_KEY=91b7451cf8fed9cbc1c4ca31931ffce8741f6
set -euo pipefail
IP=$(curl -sS ifconfig.me);
echo "Updating DNS for ${SUB_DOMAIN}..."
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${SUB_DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}')
     
echo "Host : $SUB_DOMAIN"
echo "$SUB_DOMAIN" > /etc/xray/domain
echo "IP=$SUB_DOMAIN" > /var/lib/zenhost/ipvps.conf
sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
sleep 2
clear
green "Creating Wildcard NonTLS Domain"
DOMAIN=vpnme.biz.id
WC_DOMAIN=*.${sub}.vpnme.biz.id
CF_ID=cloudflaredomainpanel@gmail.com
CF_KEY=91b7451cf8fed9cbc1c4ca31931ffce8741f6
set -euo pipefail
IP=$(curl -sS ifconfig.me);
echo "Updating DNS for ${WC_DOMAIN}..."
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${WC_DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${WC_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${WC_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}')
     
green "Done"
sleep 3
sts=jancok
echo $sts > /home/email

clear   
#install ssh ovpn
wget -q ${link}/ssh.sh && chmod +x ssh.sh && ./ssh.sh
#install backup
wget -q ${link}/backupinstaller.sh && chmod +x backupinstaller.sh && ./backupinstaller.sh
#Instal Xray
wget -q ${link}/xrayinstaller.sh && chmod +x xrayinstaller.sh && ./xrayinstaller.sh
wget -q ${link}/websocketinstaller.sh && chmod +x websocketinstaller.sh && ./websocketinstaller.sh
wget -q ${link}/toolsinstaller.sh;chmod +x toolsinstaller.sh;./toolsinstaller.sh
wget -q ${link}/udp.sh && chmod +x udp.sh && ./udp.sh
wget -q ${link}/rsvproxyinstaller.sh && chmod +x rsvproxyinstaller.sh && ./rsvproxyinstaller.sh
clear
#Setting CronJob
cat > /etc/cron.d/expired <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * * root /usr/bin/sshxp
*/30 * * * * root /usr/bin/xrayxp
END

cat <(crontab -l) <(echo "@hourly /usr/bin/backupmgbot") | crontab -
cat <(crontab -l) <(echo "@hourly /usr/bin/bwusage") | crontab -
cat <(crontab -l) <(echo "@hourly systemctl restart udpgw") | crontab -
cat <(crontab -l) <(echo "@hourly systemctl restart udp-custom") | crontab -
cat <(crontab -l) <(echo "*/5 * * * * /usr/bin/booster") | crontab -
cat <(crontab -l) <(echo "@reboot systemctl restart stunnel4") | crontab -

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
clear
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
export PATH=$PATH:/usr/games:/snap/bin
clear
cxz
END
chmod 644 /root/.profile

history -c
clear
echo ""
green " INSTALLATION SUCCESS"
echo ""
echo -e " ${BLUE}Services${NC}             ${ORANGE}Feature${NC}"
echo ""
echo -e " SSH WEBSOCKET        Fully Automatic Script"
echo -e " XRAY VMESS           Backup & Restore"
echo -e " XRAY VLESS           Check Create Account"
echo -e " XRAY TROJAN          AutoDelete Expired User"
echo -e " UDP CUSTOM           Limit Quota Xray User"
echo -e "                      Lock SSH Multilogin User"
echo -e "                      Notify to Telegram Bot"
#echo -e "                      "
echo ""
red " © Zenvio 2021-2025"
rm /root/install >/dev/null 2>&1
rm /root/backupinstaller.sh >/dev/null 2>&1
rm /root/ssh.sh >/dev/null 2>&1
rm /root/xrayinstaller.sh >/dev/null 2>&1
rm /root/websocketinstaller.sh >/dev/null 2>&1
rm /root/toolsinstaller.sh >/dev/null 2>&1
rm /root/udp.sh >/dev/null 2>&1
rm /root/rsvproxyinstaller.sh >/dev/null 2>&1
find ~ -maxdepth 1 -type f -name "20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]" -delete
echo -e ""
red "Warning !!"
echo "Reboot in 10 Seconds"
sleep 10
red "Rebooting..."
sleep 1
reboot