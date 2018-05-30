#!/bin/bash

sudo sh -c "echo -n dump > /sys/kernel/vsentry/cls_can"
sleep 0.2;
sudo sh -c "echo -n dump > /sys/kernel/vsentry/cls_file"
sleep 0.2;
sudo sh -c "echo -n dump > /sys/kernel/debug/rules_check/cls_ipv4"
sleep 0.1;

cat /sys/kernel/vsentry/cls_can
sleep 0.1;
cat /sys/kernel/vsentry/cls_file
sleep 0.1;
sudo cat /sys/kernel/debug/rules_check/cls_ipv4
sleep 0.6;
cat /sys/kernel/vsentry/state
