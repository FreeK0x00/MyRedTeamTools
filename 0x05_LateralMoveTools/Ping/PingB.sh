#!/bin/bash
if [ "$1" == "" ]
then
	echo "You forgot an IP address!"
	echo "Syntax: ./ipsweep.sh 172.16"
else
	for ip in `seq 1 254`;do
		ping -c 1 $1.$ip.1 | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
		ping -c 1 $1.$ip.2 | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
		ping -c 1 $1.$ip.253 | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
		ping -c 1 $1.$ip.254 | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
	done
fi
