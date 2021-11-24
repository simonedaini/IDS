#!/bin/bash

CHECK_MARK="\033[0;32m\xE2\x9C\x94\033[0m"
CROSS_MARK='\u274c'

#read -p "Targed IP address: " ip
ip=10.0.1.6
echo -e "\n\e[4mAttempting Nmap scan on $ip:\e[0m\n"
scan=$(nmap -sT $ip)

if [[ $scan == *"Host is up"* ]]
then
    echo -e "\\r${CHECK_MARK} Nmap scan done"
else
    echo -e "\\r${CROSS_MARK} Nmap scan failed    "
    exit 1
fi

echo -n "Checking that $ip is now unreachable"
sleep 2
ping_result=$(ping -w 2 $ip)

if [[ $ping_result == *"0 received"* ]]
then
    echo -e "\\r${CHECK_MARK} Host successfully blocked                                    "
else
    echo -e "\\r${CROSS_MARK} Host still reachable, IDS failed blocking attacker address.  "
    exit 1
fi

echo -n "Waiting for MAC address to be removed from blacklist: 15"
for i in {14..0}; do
	echo -e -n "\\rWaiting for MAC address to be removed from blacklist: $i "
    sleep 1
done

echo ""
echo -e "\n\e[4mAttempting SYN flood attack on $ip:\e[0m"

flood=$(sudo hping3 -q -c 1000 -i u1 -S -p 80 $ip)

echo "Checking that $ip is now unreachable"
sleep 2
ping_result=$(ping -w 2 $ip)
if [[ $ping_result == *"0 received"* ]]
then
    echo -e "\\r${CHECK_MARK} Host successfully blocked"
else
    echo -e "\\r${CROSS_MARK} Host still reachable, IDS failed blocking attacker address."
    exit 1
fi