#!/bin/bash
apt update && apt upgrade -y
apt install ufw -y
apt install sudo -y
apt install dante-server

rm -rf /lib/systemd/system/danted.service
cat > /lib/systemd/system/danted.service << EOF
[Unit]
Description=SOCKS (v4 and v5) Proxy by RSV
Documentation=Contact RSV
After=network.target

[Service]
Type=simple
PIDFile=/run/danted.pid
ExecStart=/usr/sbin/danted
ExecStartPre=/bin/sh -c ' \
	uid=`sed -n -e "s/[[:space:]]//g" -e "s/#.*//" -e "/^user\\.privileged/{s/[^:]*://p;q;}" /etc/danted.conf`; \
	if [ -n "$uid" ]; then \
		touch /var/run/danted.pid; \
		chown $uid /var/run/danted.pid; \
	fi \
	'
PrivateTmp=yes
InaccessibleDirectories=/boot /home /media /mnt /opt /root
ReadOnlyDirectories=/bin /etc /lib -/lib64 /sbin /usr /var
DeviceAllow=/dev/null rw

[Install]
WantedBy=multi-user.target
EOF

rm -rf /etc/danted.conf
touch /etc/danted.conf
cat > /etc/danted.conf << EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

# Proxy Config Improved by RSV

# Proxy Local # Port
internal: 0.0.0.0 port=12345

# Interface pada VPSMU
external: eth0

# Abaikan saja pilihan di bawah ini
socksmethod: none
clientmethod: none

# Contoh Format Client
client pass {
    from: 0.0.0.0/16 to: 0.0.0.0/0
}

# Contoh Format Socks
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

EOF

systemctl daemon-reload
systemctl restart danted.service