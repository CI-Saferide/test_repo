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
export OUTPUT_FILE=/var/log/install_ubuntu.log
no_prints=0

pr_log(){
    #param1 = priority
    #param2 = message
    logger $debug_options -p $1 -t "$current_app[${BASH_LINENO[$i]}]" "$2"
}

run_cmd(){
    if [ "$no_prints" -eq 0 ]; then
        echo -ne "$operation"
    fi
    cmd=$@
    if [ "$no_prints" -eq 0 ]; then
        let spaces=80-10-${#operation}
        printf "%-${spaces}s" " "
    fi
    pr_log DEBUG "[from line ${BASH_LINENO[$i]}] running command: ${cmd}"
    ${cmd} 1> /var/log/stdout.log 2> /var/log/stderr.log
    if [ $? != 0 ]; then 
        if [ "$no_prints" -eq 0 ]; then
            echo -e "[ ${red} FAIL ${nc} ]"
        fi
        pr_log ERROR "failed to run command: ${cmd}"
        pr_log ERROR "stdout=`cat /var/log/stdout.log`"
        pr_log ERROR "stderr=`cat /var/log/stderr.log`"
        exit 1
    fi
    if [ "$no_prints" -eq 0 ]; then
        echo -e "[  ${green} OK ${nc}  ]"
    fi
}

library_path_update(){
    operation="Update library path (1/2)"
    lib_exist=`cat /etc/ld.so.conf.d/x86_64-linux-gnu.conf |grep $install_dir/lib | wc -l`
	if [ "$lib_exist" -eq "0" ]; then
	   run_cmd `echo "$install_dir/lib" >> /etc/ld.so.conf.d/x86_64-linux-gnu.conf`
	else
	   run_cmd
	fi
	operation="Update library path (2/2)"
	lib_exist=`cat /etc/ld.so.conf.d/x86_64-linux-gnu.conf |grep $install_dir/lib/x86_64-linux-gnu | wc -l`
	if [ "$lib_exist" -eq "0" ]; then
	   run_cmd `echo "$install_dir/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/x86_64-linux-gnu.conf`
	else
	   run_cmd
	fi
	ldconfig
}

insatll_saferide_service(){
    operation="Prepare saferide service"
    string="INSTALL_DIR=$install_dir"
    string="${string//\//\\/}"
    run_cmd `sed -i.bak s/INSTALL_DIR=NA/$string/g $script_dir/ubuntu/saferide`
    operation="Install saferide service"
    run_cmd `cp -ra $script_dir/ubuntu/saferide /etc/init.d`
    operation="Fix service owner"
    run_cmd `chown root:root /etc/init.d/saferide`
}

insatll_sysrepo_service(){
    operation="Prepare sysrepo service"
    string="INSTALL_DIR=$install_dir"
    string="${string//\//\\/}"
    run_cmd `sed -i.bak s/INSTALL_DIR=NA/$string/g $script_dir/ubuntu/sysrepo`
    operation="Install sysrepo service"
    run_cmd `cp -ra $script_dir/ubuntu/sysrepo /etc/init.d`
    operation="Fix service owner"
    run_cmd `chown root:root /etc/init.d/sysrepo`
    operation="Config automatic running for sysrepo"
    run_cmd update-rc.d sysrepo defaults
}

install_yang(){
    #operation="Install yang db"
    #run_cmd echo `$install_dir/bin/sysrepoctl --install --yang=$install_dir/sysrepo/yang/saferide.yang --permissions=644`
    operation="Install /var related files"
    run_cmd `cp -ra $install_dir/var/run/* /var/run/`
	operation="Install /etc related files"
	run_cmd `cp -ra $install_dir/sysrepo/   /etc/`
	rm -rf $install_dir/var
	rm -rf $install_dir/sysrepo
}

remove_tmp_files(){
    operation="Remove temporary files"
	run_cmd `rm $install_dir/md5.calc $install_dir/md5.check`
}

#################################################
# start main script                             #
#################################################
echo -ne "\r"
library_path_update
insatll_saferide_service
insatll_sysrepo_service
install_yang
remove_tmp_files

exit 0
