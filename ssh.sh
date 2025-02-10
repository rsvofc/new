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

apt dist-upgrade -y
apt install netfilter-persistent -y
apt-get remove --purge ufw firewalld -y
apt install -y screen curl jq bzip2 gzip vnstat coreutils rsyslog iftop zip unzip git apt-transport-https build-essential -y

# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
link="https://raw.githubusercontent.com/rsvofc/new/main/v1"
#detail nama perusahaan
country="ID"
state="Jakarta"
locality="Kebayoran"
organization="RSVCompany"
organizationalunit="RSVCompany"
commonname="RSV"
email="admin@rsvzone.biz.id"

# simple password minimal
curl -sS https://raw.githubusercontent.com/sreyaeve/rsvzen/main/websocket/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

wget -q -O /usr/local/bin/traffic.sh "${link}/file/xraylimiter.sh" 
chmod +x /usr/local/bin/traffic.sh
cd
# Limit Data Service
cat > /etc/systemd/system/net0.service <<-END
[Unit]
Description=Network Push Service
Documentation=https://rsv.web.id
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/local/bin/traffic.sh
StandardError=null
MemoryLimit=512M
Type=simple
Restart=Always
RestartSec=5s
WorkingDirectory=/usr/local/bin
CPUQuota=50%
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
END
systemctl enable net0.service
systemctl start net0.service

cd
# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt install ruby -y
apt install python3 -y
apt install make -y
apt install cmake -y
apt install coreutils -y
apt install rsyslog -y
apt install net-tools -y
apt install zip -y
apt install unzip -y
apt install nano -y
apt install sed -y
apt install gnupg -y
apt install gnupg1 -y
apt install bc -y
apt install apt-transport-https -y
apt install build-essential -y
apt install dirmngr -y
apt install libxml-parser-perl -y
apt install neofetch -y
apt install git -y
apt install lsof -y
apt install libsqlite3-dev -y
apt install libz-dev -y
apt install gcc -y
apt install g++ -y
apt install libreadline-dev -y
apt install zlib1g-dev -y
apt install libssl-dev -y
apt install libssl1.0-dev -y
apt install dos2unix -y
apt install at -y
apt install htop -y
#install jq
apt -y install jq

#install shc
apt -y install shc

# install wget and curl
apt -y install wget curl

#figlet
apt-get install figlet -y
apt install lolcat -y
gem install lolcat -y

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# install webserver
apt -y install nginx
# install webserver
apt -y install nginx
wget -O /etc/nginx/mime.types https://raw.githubusercontent.com/nginx/nginx/master/conf/mime.types
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -q -O /etc/nginx/nginx.conf "${link}/file/nginx.conf"
mkdir -p /home/vps/public_html
cat > /lib/systemd/system/nginx.service << END
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/sh -c "/bin/kill -s HUP $(/bin/cat /var/run/nginx.pid)"
ExecStop=/bin/sh -c "/bin/kill -s TERM $(/bin/cat /var/run/nginx.pid)"

[Install]
WantedBy=multi-user.target
END
systemctl daemon-reload
/etc/init.d/nginx restart

# install badvpn
cd
wget -q -O /usr/bin/badvpn-udpgw "${link}/file/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

sudo apt-get update
sudo apt-get install -y build-essential zlib1g-dev bzip2
apt install -y dropbearwget -q ${link}/fixdropbear.tar.bz2
tar xjf fixdropbear.tar.bz2
cd dropbear-2019.78
chmod +x *
./configure
make
sudo make install

# Pindahkan file binari Dropbear ke direktori yang benar
sudo systemctl stop dropbear
sudo mv /usr/local/sbin/dropbear /usr/sbin/dropbear

# Konfigurasi Dropbear
sudo mkdir -p /etc/dropbear

# Buat Banner
sudo tee /etc/banner.com > /dev/null <<END
<p style="text-align:center"><b>
<font color="#0000CD">⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸</font><br>
<h1 style="text-align:center;"><font color="#DC143C">Premium Server</font></h1>
<p style="text-align:center;"><b>
<font color="#CD853F">プレミアムサーバー</font><br>
<br>
<font color="#0000CD">⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸</font><br>
<font color="#CD853F">$ISP</font><br>
$WKT<br>
<br>
<font color="#5F9EA0">No Multilogin<br>
No Spam<br>
No Ddos<br
No Torrent</font><br>
</font>
Abuse = <font color="red">Banned</font><br>
<br>
<font color="#0000CD">⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸</font><br>
<font color="#FF7F50">Autoscript</font><br>
<font color="#4169E1">By</font><br>
<font color="#DC143C">Z</font><font color="#FF8C00">e</font><font color="#FFD700">n</font><font color="#7CFC00">v</font><font color="#32CD32">i</font><font color="#008B8B">o</font><br>
<font color="#0000CD">⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸⩸</font>
END
chmod +x /etc/banner.com

# Konfigurasi Dropbear dengan multi-port, banner, dan receive window
sudo tee /etc/default/dropbear > /dev/null <<EOF
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 69 -b /etc/banner.com -W 65536"
EOF
# Penjelasan:
# - -p 109 -p 110 -p 69 : Mengaktifkan Dropbear di port 109, 110, dan 69
# - -b /etc/banner.com  : Menampilkan banner saat login
# - -W 65536            : Receive Window diatur ke 65536 bytes (64 KB)

# Restart Dropbear
sudo systemctl start dropbear
sudo systemctl enable dropbear

# Bersihkan file yang tidak diperlukan
cd
rm -rf dropbear-2019.78
rm -f dropbear-2019.78.tar.bz2

cd
apt -y install sslh
rm -f /etc/default/sslh

# Settings SSLH
cat > /etc/default/sslh <<-END
RUN=yes
DAEMON=/usr/sbin/sslh
DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssl 127.0.0.1:777 --ssh 127.0.0.1:109 --openvpn 127.0.0.1:1194 --http 127.0.0.1:8880 --pidfile /var/run/sslh/sslh.pid -n"
END

# Restart Service SSLH
service sslh restart
systemctl restart sslh
/etc/init.d/sslh restart
/etc/init.d/sslh status
/etc/init.d/sslh restart

apt install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:69

[dropbear]
accept = 777
connect = 127.0.0.1:443

[ws-stunnel]
accept = 2096
connect = 700
END

# Tambahkan user stunnel4
useradd --system --no-create-home --shell /usr/sbin/nologin stunnel4

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

# install fail2ban
apt -y install fail2ban

# banner /etc/issue.net
sleep 1
ISP=$(cat /usr/local/etc/xray/org)
WKT=$(cat /usr/local/etc/xray/timezone)

echo "Banner /etc/banner.com" >> /etc/ssh/sshd_config

# blokir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# download script
clear
cd /usr/bin
green "Downloading Menu"
wget -q -O autokill "${link}/file/autokill.sh" && chmod +x autokill
wget -q -O backupgh "${link}/file/backupgh.sh" && chmod +x backupgh
wget -q -O backupmg "${link}/file/backupmg.sh" && chmod +x backupmg
wget -q -O backupmgbot "${link}/file/backupmgbot.sh" && chmod +x backupmgbot
wget -q -O backupmenu "${link}/file/backupmenu.sh" && chmod +x backupmenu
wget -q -O ceklimitssh "${link}/file/ceklim.sh" && chmod +x ceklimitssh
wget -q -O createssh "${link}/file/createssh.sh" && chmod +x createssh
wget -q -O createtrojan "${link}/file/createtrojan.sh" && chmod +x createtrojan
wget -q -O createvless "${link}/file/createvless.sh" && chmod +x createvless
wget -q -O createvmess "${link}/file/createvmess.sh" && chmod +x createvmess
wget -q -O deletessh "${link}/file/deletessh.sh" && chmod +x deletessh
wget -q -O deletetrojan "${link}/file/deletetrojan.sh" && chmod +x deletetrojan
wget -q -O deletevless "${link}/file/deletevless.sh" && chmod +x deletevless
wget -q -O deletevmess "${link}/file/deletevmess.sh" && chmod +x deletevmess
wget -q -O dns "${link}/file/dns.sh" && chmod +x dns
wget -q -O domain "${link}/file/domain.sh" && chmod +x domain
wget -q -O domainmenu "${link}/file/domainmenu.sh" && chmod +x domainmenu
wget -q -O log-ssh "${link}/file/log-ssh.sh" && chmod +x log-ssh
wget -q -O log-trojan "${link}/file/log-trojan.sh" && chmod +x log-trojan
wget -q -O log-vless "${link}/file/log-vless.sh" && chmod +x log-vless
wget -q -O log-vmess "${link}/file/log-vmess.sh" && chmod +x log-vmess
wget -q -O loginssh "${link}/file/loginssh.sh" && chmod +x loginssh
wget -q -O logintrojan "${link}/file/logintrojan.sh" && chmod +x logintrojan
wget -q -O loginvless "${link}/file/loginvless.sh" && chmod +x loginvless
wget -q -O loginvmess "${link}/file/loginvmess.sh" && chmod +x loginvmess
wget -q -O memberssh "${link}/file/loginmember.sh" && chmod +x memberssh
wget -q -O menu-tcp "${link}/file/menu-tcp.sh" && chmod +x menu-tcp
wget -q -O menu "${link}/file/menu.sh" && chmod +x menu
wget -q -O renewssh "${link}/file/renew.sh" && chmod +x renewssh
wget -q -O renewtrojan "${link}/file/renewtrojan.sh" && chmod +x renewtrojan
wget -q -O renewvless "${link}/file/renewvless.sh" && chmod +x renewvless
wget -q -O renewvmess "${link}/file/renewvmess.sh" && chmod +x renewvmess
wget -q -O restart "${link}/file/restart.sh" && chmod +x restart
wget -q -O running "${link}/file/running.sh" && chmod +x running
wget -q -O restoregh "${link}/file/restoregh.sh" && chmod +x restoregh
wget -q -O restoremg "${link}/file/restoremg.sh" && chmod +x restoremg

wget -q -O sshmenu "${link}/file/sshmenu.sh" && chmod +x sshmenu
wget -q -O sslcert "${link}/file/sslcert.sh" && chmod +x sslcert
wget -q -O tendang "${link}/file/tendang.sh" && chmod +x tendang
wget -q -O trojanmenu "${link}/file/trojanmenu.sh" && chmod +x trojanmenu
wget -q -O vlessmenu "${link}/file/vlessmenu.sh" && chmod +x vlessmenu
wget -q -O vmessmenu "${link}/file/vmessmenu.sh" && chmod +x vmessmenu
wget -q -O xp "${link}/file/xp.sh" && chmod +x xp
wget -q -O booster "${link}/file/booster.sh" && chmod +x booster
wget -q -O unlock "${link}/file/unlock.sh" && chmod +x unlock
wget -q -O lock "${link}//file/lock.sh" && chmod +x lock

wget -q -O bwusage "${link}/file/vnstatdata.sh" && chmod +x bwusage
wget -q -O botmenu "${link}/file/botmenu.sh" && chmod +x botmenu
wget -q -O limitlog "${link}/file/limitlog.sh" && chmod +x limitlog
wget -q -O cxz "${link}/file/checker.sh" && chmod +x cxz
wget -q -O jso "${link}/file/jso.sh" && chmod +x jso
wget -q -O updater "${link}/file/updater.sh" && chmod +x updater
wget -q -O datavpn "${link}/file/datavpn.sh" && chmod +x datavpn
wget -q -O sshxp "${link}/file/sshxp.sh" && chmod +x sshxp
wget -q -O xrayxp "${link}/file/xrayxp.sh" && chmod +x xrayxp
wget -q -O trialmenu "${link}/file/trialmenu.sh" && chmod +x trialmenu
wget -q -O trialssh30m "${link}/file/trialssh30m.sh" && chmod +x trialssh30m
wget -q -O trialssh1h "${link}/file/trialssh1h.sh" && chmod +x trialssh1h
wget -q -O trialvmess30m "${link}/file/trialvmess30m.sh" && chmod +x trialvmess30m
wget -q -O trialvmess1h "${link}/file/trialvmess1h.sh" && chmod +x trialvmess1h
wget -q -O trialvless30m "${link}/file/trialvless30m.sh" && chmod +x trialvless30m
wget -q -O trialvless1h "${link}/file/trialvless1h.sh" && chmod +x trialvless1h
wget -q -O trialtrojan30m "${link}/file/trialtrojan30m.sh" && chmod +x trialtrojan30m
wget -q -O trialtrojan1h "${link}/file/trialtrojan1h.sh" && chmod +x trialtrojan1h
wget -q -O addwc "${link}/file/addwc.sh" && chmod +x addwc
wget -q -O proxymenu "${link}/file/proxymenu.sh" && chmod +x proxymenu
wget -q -O proxymanage "${link}/file/proxymanage.sh" && chmod +x proxymanage
wget -q -O routemenu "${link}/file/routemenu.sh" && chmod +x routemenu
wget -q -O routemanage "${link}/file/routemanage.sh" && chmod +x routemanage
wget -q -O routesetup "${link}/file/routesetup.sh" && chmod +x routesetup
wget -q -O vpslimiter "${link}/file/wslimiter.sh" && chmod +x vpslimiter
wget -q -O vmessmanage "${link}/file/vmessmanage.sh" && chmod +x vmessmanage
wget -q -O vlessmanage "${link}/file/vlessmanage.sh" && chmod +x vlessmanage
wget -q -O trojanmanage "${link}/file/trojanmanage.sh" && chmod +x trojanmanage
wget -q -O settingmenu "${link}/file/settingmenu.sh" && chmod +x settingmenu
wget -q -O sshpass "${link}/file/sshpass.sh" && chmod +x sshpass


if [ ! -d "/snap/bin" ]; then
  mkdir -p /snap/bin
else
  echo "continue"
fi
if [ ! -d "/usr/games" ]; then
  mkdir -p /usr/games
else
  echo "continue"
fi
mv createssh createvmess createvless createtrojan deletessh deletevmess deletevless deletetrojan renewssh renewvmess renewvless renewtrojan loginssh loginvmess loginvless logintrojan log-ssh log-vmess log-vless log-trojan backupgh backupmg addwc restoregh restoremg domain proxymanage routemanage routesetup /snap/bin/ && chmod +x /snap/bin/*
mv sshmenu vmessmenu vlessmenu trojanmenu backupmenu botmenu proxymenu domainmenu trialmenu routemenu /usr/games/ && chmod +x /usr/games/*
cd
mkdir /etc/.vinfx
wget -q -O /etc/.vinfx/sde "${link}/file/menu.sh" && chmod +x /etc/.vinfx/sde
wget -q -O /etc/.vinfx/dse "${link}/file/dse.sh" && chmod +x /etc/.vinfx/dse

green "DONE"
mkdir /.temp
# remove unnecessary files
clear
green "Prepare Rclone Setup"
apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi
apt-get -y --purge remove samba* >/dev/null 2>&1
apt-get -y --purge remove apache2* >/dev/null 2>&1
apt-get -y --purge remove bind9* >/dev/null 2>&1
apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

echo "unset HISTFILE" >> /etc/profile
rm -f /root/key.pem
rm -f /root/cert.pem
