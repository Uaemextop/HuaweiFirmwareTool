#!/bin/sh
var_boardinfo_5113=/mnt/jffs2/hw_boardinfo.xml
var_cfgword_path=BoardInfo.CfgFeatureWord 
var_machineitem_path=BoardInfo.MachineItem
var_cfgword_5113=""  #R3及R6版本的程序特征字
var_cfgword_5115=""  #R12及后续版本的程序特征字
var_upgrade_log=/mnt/jffs2/upgrade_script_log.txt
var_jffs2_boardinfo_file="/mnt/jffs2/hw_boardinfo"
var_jffs2_boardinfo_temp="/mnt/jffs2/hw_boardinfo.temp"
machineItem_5115=""


#echo采用的是追加模式，若文件不存在会报错，故先进行判断
HW_Script_CreateLogFile()
{
    if [ ! -f "$var_upgrade_log" ]
    then
        touch $var_upgrade_log
    fi
    
    echo "Recover to factory setting Time" "`date \"+%Y-%m-%d%t%H:%M:%S\"`" >> $var_upgrade_log	
    
}

#记录21条码和定制特征字    
HW_Script_RecordInfo_5113()
{
	rm -rf /var/cfgtool_ret
	cfgtool gettofile $var_boardinfo_5113 $var_machineitem_path infoStr
	if [ 0 -eq $? ]
	then
	    if [ -f "/var/cfgtool_ret" ]
	    then
	        read machineItem < /var/cfgtool_ret
	    fi
	fi
	
	rm -rf /var/cfgtool_ret
	cfgtool gettofile $var_boardinfo_5113 $var_cfgword_path infoStr
	if [ 0 -eq $? ]
	then
	    if [ -f "/var/cfgtool_ret" ]
	    then
	        read var_cfgword_5113 < /var/cfgtool_ret
	    fi
	fi	
	
	
	echo "MachinItem       :" $machineItem >> $var_upgrade_log	
	echo "Configure Word   :" $var_cfgword_5113 >> $var_upgrade_log	
	echo "Version TimeStamp: `cat /etc/timestamp` "  >> $var_upgrade_log

}       

HW_Script_ClearLoid_5113()
{
    cfgtool set $var_boardinfo_5113 BoardInfo.eponkey infoStr ""
    cfgtool set $var_boardinfo_5113 BoardInfo.snpassword infoStr ""
    cfgtool set $var_boardinfo_5113 BoardInfo.snhexpassword infoStr ""
    cfgtool set $var_boardinfo_5113 BoardInfo.loid infoStr ""
    cfgtool set $var_boardinfo_5113 BoardInfo.eponpwd infoStr ""
    rm /mnt/jffs2/hw_boardinfo.xml.bak
    cp $var_boardinfo_5113 /mnt/jffs2/hw_boardinfo.xml.bak
}   

HW_Script_ClearLoid_5115()
{
	cat $var_jffs2_boardinfo_file | while read -r line;
	do
		obj_id_temp=`echo $line | sed 's/\(.*\)obj.value\(.*\)/\1/g'`
		obj_id=`echo $obj_id_temp | sed 's/\(.*\)"\(.*\)"\(.*\)/\2/g'`
		
		if [ "0x00000003" == $obj_id ];then
		    echo "obj.id = \"0x00000003\" ; obj.value = \"\";"
		elif [ "0x00000004" == $obj_id ];then
		    echo "obj.id = \"0x00000004\" ; obj.value = \"\";"		    
		elif [ "0x00000005" == $obj_id ];then
		    echo "obj.id = \"0x00000005\" ; obj.value = \"\";"
		elif [ "0x00000006" == $obj_id ];then
		    echo "obj.id = \"0x00000006\" ; obj.value = \"\";"
		elif [ "0x00000016" == $obj_id ];then
		    echo "obj.id = \"0x00000016\" ; obj.value = \"\";"	    		    
		else
		    echo -E $line
		fi
	done  > $var_jffs2_boardinfo_temp    
	
	mv $var_jffs2_boardinfo_temp $var_jffs2_boardinfo_file
    rm /mnt/jffs2/hw_boardinfo.bak
    cp /mnt/jffs2/hw_boardinfo /mnt/jffs2/hw_boardinfo.bak	
}

#记录21条码和定制特征字    
HW_Script_RecordInfo_5115()
{
	#read cfgword/machineItem
	while read line;
	do
		obj_id_temp=`echo $line | sed 's/\(.*\)obj.value\(.*\)/\1/g'`
		obj_id=`echo $obj_id_temp | sed 's/\(.*\)"\(.*\)"\(.*\)/\2/g'`
	
		if [ "0x00000008" == $obj_id ];then
			obj_value=`echo $line | sed 's/\(.*\)"\(.*\)"\(.*\)"\(.*\)"\(.*\)/\4/g'`
			machineItem_5115=$obj_value;
		fi

		if [ "0x0000001b" == $obj_id ];then
		    obj_value=`echo $line | sed 's/\(.*\)"\(.*\)"\(.*\)"\(.*\)"\(.*\)/\4/g'`
			var_cfgword_5115=$obj_value;
		fi				
		
	done < $var_jffs2_boardinfo_file
		
	echo "MachinItem       :" $machineItem_5115 >> $var_upgrade_log	
	echo "Configure Word   :" $var_cfgword_5115 >> $var_upgrade_log	
	echo "Version TimeStamp: `cat /etc/timestamp` "  >> $var_upgrade_log
}   


#针对某些定制，禁止按键功能，将按键重启、恢复出厂和恢复默认设置为1千万秒
HW_Script_DealWithResetKey()
{
    #调用ontinfo工具获取产品类型
    var_boardtype=`ontinfo -s -b`
    var_len=${#var_boardtype}
    let var_len=var_len-1
    var_boardtype=`expr substr $var_boardtype 1 $var_len`   
    vRversion=$(cat /etc/version | cut -b 6-8)
    vCversion=$(cat /etc/version | cut -b 10-11)
    vSPCversion=$(cat /etc/version | cut -b 15-17)
    var_Flag=0  #默认不需要规避
    
	
    ##限制到产品形态为HG8245C且定制为AHCT或SCCT定制
    if [ $var_cfgword_5115 == "AHCT" -o $var_cfgword_5115 == "SCCT" ] && [ $var_boardtype == "HG8245C" ]
    then	    
        if [ $vRversion -eq "013" ] && [ $vCversion -eq "10" ]
        then
            vDateLen=${#machineItem_5115}
            if [ $vDateLen -eq 20 ]
            then
                vDate=$(echo $machineItem_5115 | cut -b 13-14)                    
                if [ "$vDate" \< "EA" ]
                then
                    var_Flag=1  #2014年10月生产的R13C10版本，需要规避
                fi
            fi  
        fi
                
	    
        if [ $var_Flag == 1 ]
        then
            echo "AHCT HG8245C Set Key Press Invalid"  >> $var_upgrade_log
            echo "SSMP_SPEC_DM_TIMEFORREBOOTSYS=315360000;SSMP_SPEC_DM_TIMEFORLOCALCFG=315360100;SSMP_SPEC_DM_TIMEFORRESETCFG=315360200;" > /mnt/jffs2/hw_equip_hardinfo
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORREBOOTSYS\" spec.type=\"uint\" spec.value=\"315360000\"" > /mnt/jffs2/hw_hardinfo_spec
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORLOCALCFG\" spec.type=\"uint\" spec.value=\"315360100\"" >> /mnt/jffs2/hw_hardinfo_spec
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORRESETCFG\" spec.type=\"uint\" spec.value=\"315360200\"" >> /mnt/jffs2/hw_hardinfo_spec
            cp /mnt/jffs2/hw_hardinfo_spec /mnt/jffs2/hw_hardinfo_spec.bak -rf	    
        fi	    	    	    
    fi	    
}

#针对V1R3及后续版本删除无用文件
HW_Script_DeleteFile()
{
    [ -f /mnt/jffs2/hw_ctree_bak.xml ] && rm -rf /mnt/jffs2/hw_ctree_bak.xml
    [ -f /mnt/jffs2/cwmp_rebootsave ] && rm -rf /mnt/jffs2/cwmp_rebootsave
    [ -f /mnt/jffs2/oldcrc ] && rm -rf /mnt/jffs2/oldcrc
    [ -f /mnt/jffs2/prevcrc ] && rm -rf /mnt/jffs2/prevcrc
    [ -f /mnt/jffs2/hw_bms_prev.xml ] && rm -rf /mnt/jffs2/hw_bms_prev.xml
    [ -f /mnt/jffs2/servicecfg.xml ] && rm -rf /mnt/jffs2/servicecfg.xml
    [ -f /mnt/jffs2/hw_osk_voip_prev.xml ] && rm -rf /mnt/jffs2/hw_osk_voip_prev.xml
    [ -f /mnt/jffs2/usr_device.bin ] && rm -rf /mnt/jffs2/usr_device.bin
    [ -f /mnt/jffs2/FTCRC ] && rm -rf /mnt/jffs2/FTCRC
    [ -f /mnt/jffs2/ftvoipcfgstate ] && rm -rf /mnt/jffs2/ftvoipcfgstate
    [ -f /mnt/jffs2/dhcpc/wan*_request_ip ] && rm -rf /mnt/jffs2/dhcpc/wan*_request_ip
    [ -f /mnt/jffs2/emergencystatus ] && rm -rf /mnt/jffs2/emergencystatus
    [ -f /mnt/jffs2/ProductLineMode ] && rm -rf /mnt/jffs2/ProductLineMode
    [ -f /mnt/jffs2/TelnetEnable ] && rm -rf /mnt/jffs2/TelnetEnable
}

HW_Script_ResetFactory()
{
    vRversion=$(cat /etc/version | cut -b 6-8)
    echo > /var/notsavedata
    if [ "$vRversion" -lt "003" ] #V1R1及V1R2不处理，不支持
    then
        echo R$vRversion version not support >> $var_upgrade_log
        return 0
    elif [ $vRversion -lt "012" ] #V1R3及V1R6
    then        
        HW_Script_RecordInfo_5113
        if [ "$var_cfgword_5113" == "COMMON" ] || [ -z "$var_cfgword_5113" ]
        then
    	    cp /etc/wap/hw_default_ctree.xml /mnt/jffs2/hw_ctree.xml -rf
        else
            if [ -f /mnt/jffs2/hw_default_ctree.xml ]   #定制版本默认配置不存在需要报错
            then
                cp /mnt/jffs2/hw_default_ctree.xml /mnt/jffs2/hw_ctree.xml -rf
            else
                echo "/mnt/jffs2/hw_default_ctree.xml not exist"
                return 0
            fi	    
        fi
    	
    	HW_Script_ClearLoid_5113
    else                            #V3R012及之后的版本
        
        HW_Script_RecordInfo_5115
        
        if [ "$vRversion" -eq "012" ]
        then
            if [ "$var_cfgword_5115" == "COMMON" ] || [ -z "$var_cfgword_5115" ] #R12版本可能是没有定制的，所以对于无定制版本，默认从/etc/wap/hw_default_ctree.xml下恢复
            then
        	    cp /etc/wap/hw_default_ctree.xml /mnt/jffs2/hw_ctree.xml -rf
            else
                if [ -f /mnt/jffs2/hw_default_ctree.xml ]    #定制版本默认配置不存在需要报错
                then
                    cp /mnt/jffs2/hw_default_ctree.xml /mnt/jffs2/hw_ctree.xml -rf
                else
                    echo "/mnt/jffs2/hw_default_ctree.xml not exist"
                    return 0
                fi	    
            fi        
        else
            if [ -f /mnt/jffs2/hw_default_ctree.xml ]    #对于R13C00及后续版本，默认都是有定制的，如果默认配置丢失，需要报错
            then
                cp /mnt/jffs2/hw_default_ctree.xml /mnt/jffs2/hw_ctree.xml -rf
            else
                echo "/mnt/jffs2/hw_default_ctree.xml not exist"
                return 0
            fi        
        fi
                

    	
    	HW_Script_ClearLoid_5115      
    	#对于通用的恢复出厂合一包，无需做RESETKEY的特殊处理
    	#HW_Script_DealWithResetKey 
    fi	
    
    HW_Script_DeleteFile	
}

#删除装备组件包
HW_Script_DeleteComponent()
{
    [ -d /mnt/jffs2/equipment ] && rm -rf /mnt/jffs2/equipment
    [ -f /mnt/jffs2/module_desc.xml ] && rm -rf /mnt/jffs2/module_desc.xml
    [ -f /mnt/jffs2/module_desc_bak.xml ] && rm -rf /mnt/jffs2/module_desc_bak.xml
}


HW_Script_CreateLogFile
HW_Script_ResetFactory
HW_Script_DeleteComponent



