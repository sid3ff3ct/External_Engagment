#!/bin/bash

# Place Script in the Root of the working directory
# This script also assumes you have the following tools in a folder called /Scripts"
##### INPUT LIST OF TOOLS NEEDED
# nmapscraper.py

if [ $# -eq 0 ]; then
echo "Usage: ./external_start.sh <IP list in NMAP friendly format>";
echo "";
exit 1;
fi
echo "";
echo "";
echo -e "\e[1;96m External Pentesting Start Script by Daniel Brown \e[0m";
echo "";
echo "";


# User Input of Information #
echo -n " Input the number of top TCP ports you would like to scan greater than 0 : ";
read topports

if [ $topports -eq 0 ];
then
	echo -e "\e[34m I TOLD YOU GREATER THAN ZERO! \e[0m";
	exit 1;
fi



#Folder Where you will store all raw masscan and NMAP files.
mkdir Nmap_files


#######Must Match above directories#######
f1='Nmap_files';

## Pingable IP Check ##
echo "";
echo -e "\e[34m Checking for Ping on Hosts \e[0m";
echo "";
nmap -sP -iL $1 -PE -oG - | awk '/Up/{print $2}' >>pingable_hosts.txt
echo "";
echo -e "\e[34m Finished Checking for Ping \e[0m";
echo "";

# Performs NMAP TCP Scans#
echo -e "\e[34m Starting NMAP TCP scans \e[0m";
echo "";
nmap -sT -Pn -n -iL $1 --top-ports=$topports -oA $f1/nmap-sT-Pn-n-top-$topports;
echo "";
echo -e "\e[34m Finished NMAP TCP scans \e[0m";
echo "";


# Performs NMAP UDP Scans ##
echo "";
echo -e "\e[34m Starting UDP Scan for top 10 UDP ports. \e[0m"
echo "";
nmap -sU -iL $1 --top-ports=10 -oA $f1/nmap-sU-top-10;
echo "";
echo -e "\e[34m Finished NMAP UDP scans \e[0m";
echo "";

## Parses NMAP results ##
/Scripts/nmapscraper.py $f1/nmap-sT-Pn-n-top-$topports.gnmap;
mv open-ports/ tcp-open-ports
/Scripts/nmapscraper.py $f1/nmap-sU-top-10.gnmap
mv open-ports/ udp-open-ports
echo "";
echo -e "\e[34m Finished Parsing NMAP outputs. \e[0m";
echo "";

## Performs SSLScan on 443 Hosts ##
if [ -f tcp-open-ports/443.txt ]
then
	echo -e "\e[34m Running SSLScan on 443/TCP Hosts \e[0m";
	echo "";
	sslscan --no-failed --targets=tcp-open-ports/443.txt >> sslscan-results.txt;
	echo "";
	echo -e "\e[34m Finished Running SSLScan \e[0m";
	echo "";
fi

## OSSL-Early Injection Testing ##
if [ -f tcp-open-ports/443.txt ]
then
	echo -e "\e[34m Running OSSL-CCS-Early-Injection Test on 443/TCP Hosts \e[0m";
	echo "";
	for i in $(cat tcp-open-ports/443.txt);do python /Scripts/OSSL_CCS_InjectTest.py $i;done >> CCS-Early-Injection-results.txt
	echo "";
	echo -e "\e[34m Finished Running OSSL-CCS-Early-Injection Test \e[0m";
	echo "";
fi

## IKE Transfroms for Possible Agressive Hashes ##
if [ -f udp-open-ports/500.txt ]
then
	echo -e "\e[34m Running IKE Transforms Against 500/UDP hosts \e[0m";
	echo "";
	for i in $(cat udp-open-ports/500.txt);do /Scripts/ike-trans.sh $i;done >> Agressive-mode-check.txt
	echo "";
	echo -e "\e[34m Finished Running IKE Transforms Check \e[0m";
	echo "";
fi

## FTP Script Runs ##
if [ -f tcp-open-ports/21.txt ]
then
	echo -e "\e[34m Running FTP Script Checks \e[0m";
	echo "";
	nmap -sC -Pn -n -p 21 -iL tcp-open-ports/21.txt --script=ftp* -oN ftp-script-run.nmap
	echo "";
	echo -e "\e[34m Finished Running FTP Script Checks \e[0m";
	echo "";
fi

## NTP Internal IP Check ## 
if [ -f udp-open-ports/123.txt ]
then
	echo -e "\e[34m Running NTPQ to see if there is an internal IP Disclosure \e[0m";
	echo "";
	for i in $(cat udp-open-ports/123.txt);do echo $i;ntpq -c readvar $i;done >> ntpq-check.txt
	echo "";
	echo -e "\e[34m Finished Running NTPQ Checks \e[0m";
	echo "";
fi

## HTTPS Location Header Check for Internal IP Disclosure ##
if [ -f tcp-open-ports/443.txt ]
then
	echo -e "\e[34m Checking for Internal IP Disclosure in Location Headers 443/TCP Hosts \e[0m";
	echo "";
	for i in $(cat tcp-open-ports/443.txt);do echo $i;curl -v -0 -H Host: https://$i;done >> internal-ip-disclosure-check-location-header.txt
	echo "";
	echo -e "\e[34m Finished Checking for Internal IP Disclosure in Location Headers \e[0m";
	echo "";
fi

## HTTPS Body  Check for Internal IP Disclosure ##
if [ -f tcp-open-ports/443.txt ]
then
	echo -e "\e[34m Checking for Internal IP Disclosure in Body 443/TCP Hosts \e[0m";
	echo "";
	for i in $(cat tcp-open-ports/443.txt);do echo $i;curl -v -0 -k –X PROPFIND -H Host: -H Content-Length:0 https://$i;done >> internal-ip-disclosure-check-body.txt
	echo "";
	echo -e "\e[34m Finished Checking for Internal IP Disclosure in Location Headers \e[0m";
	echo "";
fi

echo "";
echo -e "\e[1;34m Finished Running Script \e[0m";
echo "";
