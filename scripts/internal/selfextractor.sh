#!/bin/bash

#set colors
export red='\e[0;31m'
export green='\e[0;32m'
export nc='\e[0m'

#exports
export BUNDLE_DIR=`cd $(dirname $0); pwd`

ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`

usage(){
    echo "usage: $0 [mode]"
    echo "mode options:"
    echo "extract           - extract bundle to working directory"
    echo "install           - automatic installation"
    exit 1
}

pr_log(){
    #param1 = priority
    #param2 = message
    logger -p $1 -t "$0" "$2"
}

check_space(){
    space_left=`df -h |grep "$log_partition" |awk '{print $5;}' | grep -o "[0-9\. ()]\+"`
    if [[ $space_left -gt ${percentage} ]]; then
        echo -e "\nlog partition is running out of space ($space_left% full)"
        echo "please free some space and try again"
        exit 1
    fi
}

check_md5(){
    printf "\r%-70s" "Verify bundle checksum"
    cd saferide
    #remove previous md5.calc if exist
    rm md5.calc 2>/dev/null
    files=`find -type f ! -iname "md5.check"| sort -f`
    md5sum $files > md5.calc
    md5_result=`diff md5.calc md5.check 1> ${BUNDLE_DIR}/stdout.log 2> ${BUNDLE_DIR}/stderr.log`
    if [ $? != 0 ]; then
        echo -e "[ ${red}FAIL${nc} ]"
        pr_log ERROR "=== bundle $0 checksum failed ==="
        pr_log ERROR "stdout=`cat ${BUNDLE_DIR}/stdout.log`"
        pr_log ERROR "stderr=`cat ${BUNDLE_DIR}/stderr.log`"
        pr_log ERROR "=== end of bundle $0 checksum failed ==="
        exit 1
    else
        echo -e "[  ${green}OK${nc}  ]"
    fi
}

extract_bundle(){
    mkdir -p ${BUNDLE_DIR}
    pr_log INFO "extracting bundle $0"
    #check_space
    mkdir -p $1
    echo -ne "Extracting bundle..."
    tail -n+$ARCHIVE $0 | tar -xpzm -C $1 1> ${BUNDLE_DIR}/stdout.log 2> ${BUNDLE_DIR}/stderr.log
    cd $1
    check_md5
}

#clear the screen and set cursor at 1,1
#echo -ne '\e[2J'
#echo -ne '\e[1;1H'
if [ -z $1 ]; then
    usage
fi

if [ "extract" == $1 ]; then 
    extract_bundle .
    exit 0
elif [ "install" == $1 ]; then
    extract_bundle .
    (cd $BUNDLE_DIR/saferide/scripts; ./auto_install.sh $0 $2 $3 $4)
else
    usage
fi

exit $?
__ARCHIVE_BELOW__
