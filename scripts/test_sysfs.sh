#!/bin/bash

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
