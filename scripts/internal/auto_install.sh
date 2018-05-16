#!/bin/bash

#set colors
export red='\e[0;31m'
export green='\e[0;32m'
export yellow='\e[1;33m'
export white='\e[1;37m'
export blue='\e[1;34m'
export nc='\e[0m'

#exports
current_app=$0
export script_dir=`cd $(dirname $0); pwd`
PWD=`pwd`
export install_dir=`dirname $PWD`
check_distro(){
    printf "%-70s" "Check running distribution"
    #currently support ubuntu
    distro=`cat /etc/lsb-release |grep DISTRIB_ID | cut -d "=" -f 2`
	case "$distro" in
	"Ubuntu")
		echo -e "[ ${green}Ubuntu${nc} ]"
		./ubuntu/install_ubuntu.sh
		;;
	*)
		echo -e "[ ${red}FAIL${nc} ]"
        exit 1
		;;
	esac
}

#################################################
# start main script                             #
#################################################
echo -ne "\r"

check_distro

exit 0
