#!/bin/sh

watch_mem()
{
    local NUM=`ps | grep kernelapp | grep -v grep |wc -l`
    local PID=`ps | grep kernelapp | awk -F: NR==${NUM} | awk '{print $1}' `
    local USEMEM=`cat /proc/${PID}/status | grep VmRSS |  awk '{print $2}' `
    if [ "${USEMEM}" -ge "11246" ]; then
        ./plugin_stop.sh
    fi
}

watch_cap()
{
    if [ -e /var/dslFlagForPlugin ]; then 
        echo "DSL mode"
        return
    fi
    local PLUGIN_CAP=CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_KILL,CAP_LEASE,CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_RESOURCE=eip
    
    local opkgcap=`getcap bin/opkg`
    if [ -z "${opkgcap}" ]; then
        setcap $PLUGIN_CAP bin/opkg
    fi
    
    local kernelappcap=`getcap bin/kernelapp`
    if [ -z "${kernelappcap}" ]; then
        setcap $PLUGIN_CAP bin/kernelapp
    fi
}

watch_file()
{
    if [ -f ./upgrade_done ]; then
        rm -f ./upgrade_done
    fi
    
    if [ -e /var/dslFlagForPlugin ]; then 
        echo "DSL mode"
        return
    fi
    
    local errs=`ls -l ./Lib/ | grep -v '\->' | awk '{print $1}' | grep rwx`
    if [ ! -z "${errs}" ]; then
        chown -Rh osgi_proxy:osgi ../MyPlugin
        watch_cap
        
        chmod 750 ../MyPlugin
        chmod 400 ./Lib/*
    fi
    
    errs=`ls -l /var/|grep Cplugin_upgrade|grep -v "osgi"`
    if [ ! -z "${errs}" ]; then
        chown -Rh osgi_proxy:osgi /var/Cplugin_upgrade
    fi
}

watch_proc()
{
    local NUM=`ps | grep -wE "kernelapp$" | grep -v grep | wc -l`
    if [ "${NUM}" -gt "1" ]; then
        ./plugin_stop.sh
    fi
}

watch_startshell()
{
    if [ -e ../MyPlugin1 ] && [ ! -f ../MyPlugin1/upgrade_done ]; then
        echo "need upgrade!"
        return
    fi
    
    if [ -f ./plugin_startup_new.sh ]; then
        mv -f plugin_startup_new.sh plugin_startup.sh
    fi
}

watch_mem
watch_file
watch_cap
watch_startshell
watch_proc

