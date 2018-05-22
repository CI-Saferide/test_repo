#!/bin/bash

#set colors
red='\e[0;31m'
green='\e[0;32m'
yellow='\e[1;33m'
#white='\e[1;37m'
#blue='\e[1;34m'
nc='\e[0m'

script_dir=`cd $(dirname $0); pwd`
OUTPUT_FILE=${script_dir}/tmp/bundle.log
echo "log start: `date`" > ${OUTPUT_FILE}
echo "==========================================" 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}

operation="NA"
PACKAGE_DIR="tmp/saferide"
VSENTRY_DIR="$PACKAGE_DIR/vsentry"
TARGET_SCRIPT_DIR="$PACKAGE_DIR/scripts"

run_cmd(){
    echo -ne "${yellow}$operation${nc}"
    cmd=$@
    echo "cmd: $cmd" 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
    echo "date: `date`" 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
    echo "==========================================" 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
    ${cmd} 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
    if [ $? != 0 ] 
    then
        echo "failed"
        echo -e "${red}ERROR: failed to run command: ${cmd}${nc}"
        exit 1
    fi
    echo -e "${green} done${nc}"
    echo "==========================================" 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
}

mkdir -p ${script_dir}/tmp/

operation="create vsentry package folder"
run_cmd mkdir -p ${script_dir}/$VSENTRY_DIR
cd ${script_dir}/$VSENTRY_DIR

operation="copy kernel module"
run_cmd cp ${script_dir}/../vsentry-mod/vsentry.ko ${script_dir}/$VSENTRY_DIR

operation="copy engine binary"
run_cmd cp ${script_dir}/../vsentry-engine/build/bin/sr_engine ${script_dir}/$VSENTRY_DIR

operation="copy config file"
run_cmd cp ${script_dir}/../vsentry-engine/config/sr_config ${script_dir}/$VSENTRY_DIR

operation="create scripts folder"
run_cmd mkdir -p $script_dir/$TARGET_SCRIPT_DIR

operation="copy installation scripts"
run_cmd cp -ra ${script_dir}/internal/auto_install.sh ${script_dir}/internal/ubuntu/ $script_dir/$TARGET_SCRIPT_DIR
operation="copy kernel object script"
run_cmd cp -ra ${script_dir}/../vsentry-mod/init_vsentry.sh ${script_dir}/$VSENTRY_DIR

cd ${script_dir}/$PACKAGE_DIR
operation="create md5 signature"
#remove previous md5.check
rm md5.check 2>/dev/null
echo -ne "${yellow}$operation${nc}"
files=`find -type f | sort -f`
md5sum $files > md5.check
if [ $? != 0 ]
then
    echo "failed"
    echo -e "${red}ERROR: failed to create md5 signature${nc}"
    exit 1
else
    echo -e "${green} done${nc}"
fi

VER_MAJOR=`cat ${script_dir}/../common/include/sr_ver.h  | grep VSENTRY_VER_MAJOR | awk '{print $3;}'` 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
VER_MINOR=`cat ${script_dir}/../common/include/sr_ver.h | grep VSENTRY_VER_MINOR | awk '{print $3;}'` 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}
VER_BUILD=`cat ${script_dir}/../common/include/sr_build_ver.h |  awk '{print $7;}' |tr -d '"' |tr -d ";"` 1>> ${OUTPUT_FILE} 2>> ${OUTPUT_FILE}

operation="create package tarball"
cd ${script_dir}/tmp 
run_cmd tar -czpf saferide.tgz saferide/
cd ${script_dir}

operation="create self extracting bundle"
echo -ne "${yellow}$operation${nc}"
cat internal/selfextractor.sh tmp/saferide.tgz  > ${script_dir}/tmp/vsentry_${VER_MAJOR}.${VER_MINOR}_${VER_BUILD}
if [ $? != 0 ] 
then
    echo "failed"
    echo -e "${red}ERROR: failed to create self extracting bundle${nc}"
    exit 1
else
    echo -e "${green} done${nc}"
fi

operation="fix permissions"
run_cmd chmod a+x ${script_dir}/tmp/vsentry_${VER_MAJOR}.${VER_MINOR}_${VER_BUILD}

operation="remove temporary files"
run_cmd rm -rf ${script_dir}/saferide.tgz
