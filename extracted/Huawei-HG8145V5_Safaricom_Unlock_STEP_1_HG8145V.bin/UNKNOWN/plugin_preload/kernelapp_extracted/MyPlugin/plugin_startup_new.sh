#!/bin/sh

#deviceFlag为0表示ONT,为1表示DSL
deviceFlag=0

function prestart()
{
    if [ -e /var/dslFlagForPlugin ]; then 
        deviceFlag=1
    fi
    echo "deviceFlag=${deviceFlag}"
    if [ "$deviceFlag" == "0" ]; then
      chown -Rh osgi_proxy:osgi /mnt/jffs2/app/cplugin
    fi

    #创建升级用的临时目录
    if [ ! -d  /var/Cplugin_upgrade ]; then
      mkdir /var/Cplugin_upgrade
      chown -Rh osgi_proxy:osgi /var/Cplugin_upgrade 
      mount none /var/Cplugin_upgrade -t tmpfs -o size=10m,mode=700
    fi
}

function startkernelapp()
{
    local curdir=`pwd`
    chmod -R 710 $(pwd)/bin
    cd bin/
    
    PLUGIN_CAP=CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_KILL,CAP_LEASE,CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_RESOURCE=eip
    FREEMEM=`cat /proc/meminfo | grep MemFree | cut -d: -f2 |cut -dk -f1`
    if [ "${FREEMEM}" -gt "5120" ]; then
        echo "begin to start kernelapp..."
        if [ "$deviceFlag" == "0" ]; then
            echo "ONT mod"
            setcap $PLUGIN_CAP kernelapp
            setcap $PLUGIN_CAP opkg
            su -s /bin/sh osgi_proxy -c "./kernelapp" &
            sleep 1
            kill -9 `ps | grep "sh -c ./kernelapp" | grep  -v grep | awk '{print $1}'`
        elif [ "$deviceFlag" == "1" ]; then
            echo "DSL mod"
            ./kernelapp &
        fi
    else
        echo "no space left on ont!"
    fi
    
    cd $curdir
}

function rollbackfiles()
{
    echo "rollback files!"
    touch ../Data/upgrade_failed
    if [ -e ../back_dir/kernelapp.tar ]; then
        tar -zxf ../back_dir/kernelapp.tar -C /
        rm -f ../back_dir/kernelapp.tar
    fi
}

function updatefiles()
{   
    rm -rf ./Lib/*;mv -f ../MyPlugin1/*.sh ./;cp -rf ../MyPlugin1/* ../MyPlugin
    touch ../MyPlugin1/upgrade_done
    chown -Rh osgi_proxy:osgi ../MyPlugin
}

function startup()
{   
    rm -f ../Data/startup_failed
    local try=0
    while [ "$try" -lt "3" ] ; do 
        echo "startapp $try."
        startkernelapp
        try=$(($try+1))
        sleep 8
        
        NUM=`ps | grep kernelapp | grep -v grep |wc -l`
        if [ "${NUM}" -gt "0" ]; then
            echo "startup success"
            return
        fi
    done
    
    touch ../Data/startup_failed
}

function dostart()
{
    prestart
    startup
    exit
}

function dorollback()
{
    rollbackfiles
    exit
}

function doupdate()
{
    updatefiles
    exit
}

if pidof kernelapp; then
    exit
fi

# 升级已完成文件覆盖
if [ -f ../MyPlugin1/upgrade_done ]; then
    rm -rf ../MyPlugin1
    dostart
fi

# 升级未开始文件覆盖
if [ -e ../MyPlugin1 ]; then
    doupdate
fi

# 升级失败需要回滚
if [ -f ../Data/startup_failed ]; then
    rm ../Data/startup_failed
    dorollback
fi

# 异常退出的场景
dostart

