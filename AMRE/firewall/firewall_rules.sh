#!/bin/bash

ip_list=$1

#tr translates all "," in "\n"
ip_arr=$(echo $ip_list | tr "," "\n")

for ip in $ip_arr
do
    iptables -A INPUT -s $ip -j DROP
    iptables -A OUTPUT -s $ip -j DROP
done
