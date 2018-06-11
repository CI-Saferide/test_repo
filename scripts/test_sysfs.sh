#!/bin/bash

# cls_ipv4 print options:
# (First two options apply for cls_file and cls_can as well)
# "dump"           : print rule's table 
# "2"              : print given rule number
# "tree -s"        : print radix tree for source IP
# "tree -d"        : print radix tree for destination IP
# "ip 35.67.89.12" : print given IP tree node with all matching rules

sudo sh -c "echo -n dump > /sys/kernel/debug/vsentry/cls_can"
sleep 0.1;
sudo sh -c "echo -n dump > /sys/kernel/debug/vsentry/cls_file"
sleep 0.1;
sudo sh -c "echo -n dump > /sys/kernel/debug/vsentry/cls_ipv4"
sleep 0.1;

sudo cat /sys/kernel/debug/vsentry/cls_can
sleep 0.2;
echo " "
sudo cat /sys/kernel/debug/vsentry/cls_file
sleep 0.2;
echo " "
sudo cat /sys/kernel/debug/vsentry/cls_ipv4
sleep 0.2;
echo " "
sudo cat /sys/kernel/debug/vsentry/state
