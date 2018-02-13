#!/bin/sh
module="vsentry"
device="vsentry"
mode="666"

sudo rm -f /dev/${device} || true
sudo rmmod $module.ko || true
sudo insmod $module.ko $* || exit 1
major=`cat /proc/devices | awk "\\$2==\"$module\" {print \\$1}"`
sudo mknod /dev/${device} c $major 0
sudo chmod $mode /dev/${device}

