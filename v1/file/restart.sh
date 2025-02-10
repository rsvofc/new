#!/bin/bash
# Provided by Zenvio

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Helper Functions
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# Clear the screen and display header
clear
echo ""
echo -e "========================="
echo -e "${PURPLE}  Restart Service Menu  ${NC}"
echo -e "========================="
echo ""

# Menu options
echo -e " [\e[36m1\e[0m] Restart All Services"
echo -e " [\e[31m0\e[0m] \e[31mBACK TO MENU\033[0m"
echo -e ""

# Prompt for menu selection
read -p "Select menu: " Restart
echo ""
sleep 1
clear

# Handle the menu options
case $Restart in
    1)
        # Restart all services
        clear
        yellow "========================="
        yellow "  Restart All Services  "
        yellow "========================="
        echo ""
        echo -e "[ \033[32mInfo\033[0m ] Restarting services, please wait..."

        # Restart each service
        systemctl restart ssh && echo -e "[ \033[32mInfo\033[0m ] SSH Restarted"
        sleep 1
        systemctl restart udp-custom && echo -e "[ \033[32mInfo\033[0m ] UDP Restarted"
        sleep 1
        systemctl restart dropbear && echo -e "[ \033[32mInfo\033[0m ] Dropbear Restarted"
        sleep 1
        pkill -f stunnel4
        systemctl restart stunnel4 && echo -e "[ \033[32mInfo\033[0m ] Stunnel Restarted"
        sleep 1
        systemctl restart cron && echo -e "[ \033[32mInfo\033[0m ] Cron Restarted"
        sleep 1
        systemctl restart nginx && echo -e "[ \033[32mInfo\033[0m ] Nginx Restarted"
        sleep 1
        systemctl restart net0 && echo -e "[ \033[32mInfo\033[0m ] Xray Quota Restarted"
        systemctl restart xray && echo -e "[ \033[32mInfo\033[0m ] Xray Restarted"
#        systemctl restart xray.service && echo -e "[ \033[32mInfo\033[0m ] Xray Service Restarted"
        sleep 1

        # Restart BadVPN
        screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
        echo -e "[ \033[32mInfo\033[0m ] BadVPN Restarted"
        sleep 1

        # Restart Websocket Services
        systemctl restart ws-stunnel.service && echo -e "[ \033[32mInfo\033[0m ] Websocket Stunnel Restarted"
        systemctl restart ws-dropbear.service && echo -e "[ \033[32mInfo\033[0m ] Websocket Dropbear Restarted"
        sleep 1

        # Completion message
        echo -e "[ \033[32mInfo\033[0m ] All services have been successfully restarted."
        echo ""
        green "RSV Project"
        exit 0
        ;;

    0)
        # Return to main menu
        menu
        exit
        ;;

    x)
        # Exit script
        clear
        exit
        ;;

    *)
        # Invalid option
        red "Invalid option selected. Please try again."
        sleep 1
        exit 1  # Recursively call the script again
        ;;
esac