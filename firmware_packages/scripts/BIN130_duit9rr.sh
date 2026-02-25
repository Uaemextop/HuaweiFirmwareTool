#! /bin/sh
var_etc_version_file="/etc/version"
var_etc_version=""
#目前处理的四种版本号
var_version_1="V100R006C00SPC130"
var_version_2="V200R006C00SPC130"
var_version_3="V300R013C00SPC106"
var_version_4="V300R013C10SPC108"
var_etc_version_V=""
var_etc_version_R=""
var_etc_version_C=""
var_etc_version_S=""
var_file_productlinemode="/mnt/jffs2/ProductLineMode"
var_file_telnetenable="/mnt/jffs2/TelnetEnable"
var_file_equipfile="/mnt/jffs2/equipment.tar.gz"
var_path_eauipfile="/mnt/jffs2/equipment"
var_file_xml1=/mnt/jffs2/module_desc.xml
var_file_xml2=/mnt/jffs2/module_desc_bak.xml
var_jffs2_current_ctree_file="/mnt/jffs2/hw_ctree.xml"
var_current_ctree_bak_file="/var/hw_ctree_equipbak.xml"
var_current_ctree_file_tmp="/var/hw_ctree.xml.tmp"
var_pack_temp_dir="/bin/"
var_nosave=/var/notsavedata
machineItem_5115=""
var_jffs2_boardinfo_file="/mnt/jffs2/hw_boardinfo"
var_upgrade_log=/mnt/jffs2/upgrade_script_log.txt

echo "  "  >>  $var_file_productlinemode
echo "  "  >>  $var_file_telnetenable

#echo采用的是追加模式，若文件不存在会报错，故先进行判断
HW_Script_CreateLogFile()
{
    if [ ! -f "$var_upgrade_log" ]
    then
        touch $var_upgrade_log
    fi
    
}

#判断一下，是否需要加密，该函数的第一个参数代表预配置是否需要加密
#para1 是否需要加密的标志 1：加密
#para2 要加密的ctree的路径
HW_Script_Encrypt()
{
    if [ $1 -eq 1 ]
    then
        gzip -f $2
        mv $2".gz" $2
        $var_pack_temp_dir/aescrypt2 0 $2 $2"_tmp"
		echo "Encrypt at the end!"
    fi
}

#记录21条码和定制特征字    
HW_Script_RecordInfo_5115()
{
	#read cfgword/machineItem
	if [ ! -f $var_jffs2_boardinfo_file ];then
		echo "$var_jffs2_boardinfo_file is not exist!"  >> $var_upgrade_log
		return 1
	fi
	
	while read line;
	do
		obj_id_temp=`echo $line | sed 's/\(.*\)obj.value\(.*\)/\1/g'`
		obj_id=`echo $obj_id_temp | sed 's/\(.*\)"\(.*\)"\(.*\)/\2/g'`
	
		if [ "0x00000008" == $obj_id ];then
			obj_value=`echo $line | sed 's/\(.*\)"\(.*\)"\(.*\)"\(.*\)"\(.*\)/\4/g'`
			machineItem_5115=$obj_value;
		fi				
		
	done < $var_jffs2_boardinfo_file
		
	echo "MachinItem       :" $machineItem_5115 >> $var_upgrade_log	
	echo "Version TimeStamp: `cat /etc/timestamp` "  >> $var_upgrade_log
}

#为8120C设置馈电电流
HW_Script_SetCurrent_8120()
{
    #调用ontinfo工具获取产品类型
    if [ ! -f /bin/ontinfo ]
    then
    	return 1
    fi    
    var_boardtype=`ontinfo -s -b`
    var_len=${#var_boardtype}
    let var_len=var_len-1
    var_boardtype=`expr substr $var_boardtype 1 $var_len`

    ##限制到产品形态为HG8120C
    if [ $var_boardtype != "HG8120C" ]
    then
        return 0
	fi		
	
	var_current_path="InternetGatewayDevice.Service.VoiceService.VoiceServiceInstance.1.PhyInterface.PhyInterfaceInstance.1.X_HW_Extend"
	var_default_ctree_path=/mnt/jffs2/hw_default_ctree.xml
	var_default_ctree_path_bak=/var/hw_default_ctree_bak.xml
	varIsXmlEncrypted=0
	
	if [ -f $var_default_ctree_path ]
	then
		cp -rf $var_default_ctree_path $var_default_ctree_path_bak
	else
		echo "/mnt/jffs2/hw_default_ctree.xml not exist"
        return 1
	fi
	# decrypt var_ctree          
    $var_pack_temp_dir/aescrypt2 1 $var_default_ctree_path_bak $var_default_ctree_path_bak"_tmp"
    if [ 0 -ne $? ]
    then
	    varIsXmlEncrypted=0
		echo $var_default_ctree_path_bak" Is not Encrypted!" >> $var_upgrade_log
	else
        echo $var_default_ctree_path_bak" Is Encrypted!" >> $var_upgrade_log
		varIsXmlEncrypted=1
        mv $var_default_ctree_path_bak $var_default_ctree_path_bak".gz"
	    gunzip -f $var_default_ctree_path_bak".gz"	    
    fi
	
	echo "Start..."

	cfgtool set $var_default_ctree_path_bak $var_current_path Current "20"
	if [ 0 -ne $? ]
		then
		echo "Failed to set parameters!"
		#return 1
	fi	
	
	#encrypt var_ctree
	HW_Script_Encrypt $varIsXmlEncrypted $var_default_ctree_path_bak
	
	rm -rf $var_default_ctree_path
	cp -rf $var_default_ctree_path_bak $var_default_ctree_path 
	
	echo "Finish!"
	return 0

}

#针对某些定制，禁止按键功能，将按键重启、恢复出厂和恢复默认设置为1千万秒
HW_Script_DealWithResetKey()
{  
	HW_Script_RecordInfo_5115
	if [ 0 -ne $? ]
	then
		echo "Read machineItem failed!"
		return 1
	fi
	
    #调用ontinfo工具获取产品类型
    if [ ! -f /bin/ontinfo ]
    then
    	return 1
    fi
    
    var_boardtype=`ontinfo -s -b`
    var_len=${#var_boardtype}
    let var_len=var_len-1
    var_boardtype=`expr substr $var_boardtype 1 $var_len`   
    var_Flag=0  #默认不需要规避	
	
    ##限制到产品形态为HG8245C
    if [ $var_boardtype == "HG8245C" ]
    then	      
		vDateLen=${#machineItem_5115}
		if [ $vDateLen -eq 20 ]
		then
			vDate=$(echo $machineItem_5115 | cut -b 13-14)
			if [ "$vDate" \< "EC" ] || [ "$vDate" == "EC" ]
			then
				var_Flag=1  #2014年12月生产的，需要规避
			fi
		fi                 
	    
        if [ $var_Flag == 1 ]
        then
            echo "Set Key Press Invalid"  >> $var_upgrade_log
            echo "SSMP_SPEC_DM_TIMEFORREBOOTSYS=315360000;SSMP_SPEC_DM_TIMEFORLOCALCFG=315360100;SSMP_SPEC_DM_TIMEFORRESETCFG=315360200;" > /mnt/jffs2/hw_equip_hardinfo
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORREBOOTSYS\" spec.type=\"uint\" spec.value=\"315360000\"" > /mnt/jffs2/hw_hardinfo_spec
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORLOCALCFG\" spec.type=\"uint\" spec.value=\"315360100\"" >> /mnt/jffs2/hw_hardinfo_spec
            echo "spec.name = \"SSMP_SPEC_DM_TIMEFORRESETCFG\" spec.type=\"uint\" spec.value=\"315360200\"" >> /mnt/jffs2/hw_hardinfo_spec
            cp /mnt/jffs2/hw_hardinfo_spec /mnt/jffs2/hw_hardinfo_spec.bak -rf	    
        fi	    	    	    
    fi
	
}


#设置短柄按键的处理
HW_Script_DealWithDBKey()
{
    vDateLen=${#machineItem_5115}	
    if [ $vDateLen -ne 20 ]
    then
        return 1
    fi

    vDate=$(echo $machineItem_5115 | cut -b 13-14)
    if [ "$vDate" \< "F9" ] || [ "$vDate" \> "G1" ]  #对于15年9月之前和16年之后的编码无需做处理
    then
        return 1
    fi

    vCode=$(echo $machineItem_5115 | cut -b 3-10)
    if [ "$vCode" == "02311AXJ" ] || [ "$vCode" == "02311BVH" ] || [ "$vCode" == "02311BHY" ] || [ "$vCode" == "02311AYK" ] || [ "$vCode" == "02311BJD" ] || [ "$vCode" == "02310WWS" ]
    then
        echo "Set Key Press Invalid"  >> $var_upgrade_log
        echo "SSMP_SPEC_DM_TIMEFORREBOOTSYS=315360000;SSMP_SPEC_DM_TIMEFORLOCALCFG=315360100;SSMP_SPEC_DM_TIMEFORRESETCFG=315360200;" > /mnt/jffs2/hw_equip_hardinfo
        echo "spec.name = \"SSMP_SPEC_DM_TIMEFORREBOOTSYS\" spec.type=\"uint\" spec.value=\"315360000\"" > /mnt/jffs2/hw_hardinfo_spec
        echo "spec.name = \"SSMP_SPEC_DM_TIMEFORLOCALCFG\" spec.type=\"uint\" spec.value=\"315360100\"" >> /mnt/jffs2/hw_hardinfo_spec
        echo "spec.name = \"SSMP_SPEC_DM_TIMEFORRESETCFG\" spec.type=\"uint\" spec.value=\"315360200\"" >> /mnt/jffs2/hw_hardinfo_spec
        cp /mnt/jffs2/hw_hardinfo_spec /mnt/jffs2/hw_hardinfo_spec.bak -rf
    fi

}

#设置打开telnet的控制节点
HW_Open_Telnet_Ctree_Node()
{
	var_node_telnet=InternetGatewayDevice.X_HW_Security.AclServices
	varIsXmlEncrypted=0
	#set telnet
	EnableLanTelnetValue="1"                                                                                                   
	cp -f $var_jffs2_current_ctree_file $var_current_ctree_bak_file
	$var_pack_temp_dir/aescrypt2 1 $var_current_ctree_bak_file $var_current_ctree_file_tmp
	if [ 0 -eq $? ]
	then
		varIsXmlEncrypted=1
		mv $var_current_ctree_bak_file $var_current_ctree_bak_file".gz"
		gunzip -f $var_current_ctree_bak_file".gz"
	fi

	#set TELNETLanEnable
	cfgtool set $var_current_ctree_bak_file $var_node_telnet TELNETLanEnable $EnableLanTelnetValue
	if [ 0 -ne $? ]
	then
		echo "ERROR::Failed to set TELNETLanEnable!"
	fi
	
	#encrypt var_default_ctree
	if [ $varIsXmlEncrypted -eq 1 ]
	then
		gzip -f $var_current_ctree_bak_file
		mv $var_current_ctree_bak_file".gz" $var_current_ctree_bak_file
		$var_pack_temp_dir/aescrypt2 0 $var_current_ctree_bak_file $var_current_ctree_file_tmp
	fi
	
	rm -f $var_jffs2_current_ctree_file
	cp -f $var_current_ctree_bak_file $var_jffs2_current_ctree_file
	return 0
}

CreateXMLDescFile()
{
	if [ -f "$var_file_xml1" ]
	then
		rm -rf $var_file_xml1
		rm -rf $var_file_xml2
	fi
		
	echo "<module>"  >>  $var_file_xml1
	echo "<moduleitem name=\"equipment\" path=\"/mnt/jffs2/equipment\"/>"  >>  $var_file_xml1
	echo "</module>"  >>  $var_file_xml1
	cp -rf $var_file_xml1 $var_file_xml2
	return;
}

#For R12 Version
RemoveFileForVersionSupportNothing()
{
	echo "RemoveFileForVersionSupportNothing"
	rm -rf $var_file_productlinemode
	rm -rf $var_file_telnetenable
	return;
}

RemoveFileForSupportR15FileTelnet()
{
	echo "RemoveFileForSupportR15FileTelnet"
	rm -rf $var_file_telnetenable
	tar -xzf /var/equipment_R15C00.tar.gz -C /mnt/jffs2
	CreateXMLDescFile
	return;
}

RemoveFileForSupportR15C10FileTelnet()
{
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	# 识别是否是nand flash
	if grep ubi /proc/devices >/dev/null
	then 
		#通过ubifs这个ko是否存在来识别bin6的HG8040系列
		if [ ! -f /lib/modules/linux/kernel/fs/ubifs/ubifs.ko ]; then
			echo "RemoveFileForSupportR15C10FileTelnet"
			tar -xzf /var/equipment_R15C10.tar.gz -C /mnt/jffs2
			return;
		fi
	fi

	echo "RemoveFileForSupportR15C10CUTFileTelnet"
	tar -xzf /var/equipment_R15C10cut.tar.gz -C /mnt/jffs2
	
	return;
}

RemoveFileForSupportR15C80FileTelnet()
{
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	
	# 识别是否是nand flash
	if grep ubi /proc/devices >/dev/null
	then 
		#通过ubifs这个ko是否存在来识别bin6的HG8040系列
		if [ ! -f /lib/modules/linux/kernel/fs/ubifs/ubifs.ko ]; then
			echo "RemoveFileForSupportR15C10FileTelnet"
			tar -xzf /var/equipment_R15C80.tar.gz -C /mnt/jffs2
			return;
		fi
	fi

	echo "RemoveFileForSupportR15C10CUTFileTelnet"
	tar -xzf /var/equipment_R15C80_cut.tar.gz -C /mnt/jffs2
	
	return;
}

RemoveFileForSupportR16C00FileTelnet()
{
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	
	if [ ! -f /var/equipment_R16C00.tar.gz ];then
		echo "RemoveFileForSupportR16C00FileTelnet error"
	fi
	
	tar -xzf /var/equipment_R16C00.tar.gz -C /var
	
	# 识别是否是nand flash
	if grep ubi /proc/devices >/dev/null
	then 
		#通过ubifs这个ko是否存在来识别bin6的HG8040系列
		if [ ! -f /lib/modules/linux/kernel/fs/ubifs/ubifs.ko ]; then
			echo "RemoveFileForSupportR16C00FileTelnet"
			tar -xzf /var/equipment_R16C00/equipment.tar.gz -C /mnt/jffs2
			return;
		fi
	fi

	echo "RemoveFileForSupportR16C00FileTelnet"
	tar -xzf /var/equipment_R16C00/equipment_cut.tar.gz -C /mnt/jffs2
	
	return;
}

RemoveFileForSupportR16C10FileTelnet()
{
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	
	if [ ! -f /var/equipment_R16C10.tar.gz ];then
		echo "RemoveFileForSupportR16C10FileTelnet error"
	fi
	
	tar -xzf /var/equipment_R16C10.tar.gz -C /var
	
	# 识别是否是nand flash
	if grep ubi /proc/devices >/dev/null
	then 
		#通过ubifs这个ko是否存在来识别bin6的HG8040系列
		if [ ! -f /lib/modules/linux/kernel/fs/ubifs/ubifs.ko ]; then
			echo "RemoveFileForSupportR16C10FileTelnet"
			tar -xzf /var/equipment_R16C10/equipment.tar.gz -C /mnt/jffs2
			return;
		fi
	fi

	echo "RemoveFileForSupportR16C10CUTFileTelnet"
	tar -xzf /var/equipment_R16C10/equipment_cut.tar.gz -C /mnt/jffs2
	
	return;
}

RemoveFileForSupportR17C00FileTelnet()
{
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	
	if [ ! -f /var/equipment_R17C00.tar.gz ];then
		echo "RemoveFileForSupportR17C00FileTelnet error"
	fi
	
	tar -xzf /var/equipment_R17C00.tar.gz -C /var
	
	# 识别是否是nand flash
	if grep ubi /proc/devices >/dev/null
	then 
		#通过ubifs这个ko是否存在来识别bin6的HG8040系列
		if [ ! -f /lib/modules/linux/kernel/fs/ubifs/ubifs.ko ]; then
			echo "RemoveFileForSupportR17C00FileTelnet"
			tar -xzf /var/equipment_R17C00/equipment.tar.gz -C /mnt/jffs2
			return;
		fi
	fi

	echo "RemoveFileForSupportR17C00FileTelnet"
	tar -xzf /var/equipment_R17C00/equipment_cut.tar.gz -C /mnt/jffs2
	return;
}

RemoveFileForSupportR13FileTelnet()
{
	echo "RemoveFileForSupportR13FileTelnet"
	tar -xzf /var/equipment_R13C10.tar.gz -C /mnt/jffs2
	rm -rf $var_file_telnetenable
	CreateXMLDescFile
	return;
}

RemoveFileForSupportR6FileTelnet()
{
	echo "RemoveFileForSupportR6FileTelnet"
	rm -rf $var_file_productlinemode
	return;
}

RemoveFileForSupportFileTelnet()
{
	echo "RemoveFileForSupportR6FileTelnet"
	rm -rf $var_file_telnetenable
	return;
}

#V300R013C10SPC108
ParseVersion()
{
	var_version=$1
	var_key=$2
	var_key_version=""
	
	if [ $var_key == "R" ]; then
		var_key_version=$(echo $var_version | cut -b 6-8)
		return $var_key_version;
	fi
	
	if [ $var_key == "C" ]; then
		var_key_version=$(echo $var_version | cut -b 10-11)
		return $var_key_version;
	fi
	
	if [ $var_key == "SPC" ]; then
		var_key_version=$(echo $var_version | cut -b 15-17)
		return $var_key_version;
	fi
}

DeleteFileByVersion()
{
	var_etc_version=$(cat $var_etc_version_file)
	
	#var_etc_version_V=ParseVersion $var_etc_version "V"
	ParseVersion "$var_etc_version" "R"
	var_etc_version_R=$?
	ParseVersion "$var_etc_version" "C"
	var_etc_version_C=$?
	ParseVersion "$var_etc_version" "SPC"
	var_etc_version_S=$?
	
	 
	if [  "$var_etc_version_R" -lt "6" ] || [ "$var_etc_version_R" = "" ] ; then
		RemoveFileForVersionSupportNothing
	fi
	
	if [ "$var_etc_version_R" = "6" ] ; then
		#小于VxxxR006CxxSPC130
		if [ "$var_etc_version_S" -lt "130" ]; then
			RemoveFileForVersionSupportNothing
		else
			RemoveFileForSupportR6FileTelnet
		fi
	fi
	
	if [ "$var_etc_version_R" = "12" ]; then
		RemoveFileForVersionSupportNothing
	fi
	
	if [ $var_etc_version_R = "13" ] ; then
		#For C00
		if [ "$var_etc_version_C" == "0" ] ; then
			if [ "$var_etc_version_S" -lt "106" ]; then
				RemoveFileForVersionSupportNothing
			else
				RemoveFileForSupportFileTelnet
			fi
		fi
		
		#For C10
		if [ "$var_etc_version_C" == "10" ] ; then
			if [ "$var_etc_version_S" -lt "108" ]; then
				RemoveFileForVersionSupportNothing
			else
				RemoveFileForSupportR13FileTelnet
			fi
		fi
	fi

	if [ $var_etc_version_R = "15" ] ; then
		if [ $var_etc_version_C = "0" ] ; then
			RemoveFileForSupportR15FileTelnet
		else
			if [ "$var_etc_version_S" -le "51" ]; then
				RemoveFileForSupportR15C80FileTelnet
			else
				RemoveFileForSupportR15C10FileTelnet
			fi
		fi
	fi

	if [ $var_etc_version_R = "16" ] ; then
		if [ $var_etc_version_C = "0" ] ; then
			RemoveFileForSupportR16C00FileTelnet
		else
			RemoveFileForSupportR16C10FileTelnet
		fi
	fi
	
	if [ $var_etc_version_R -gt "16" ] ; then
		RemoveFileForSupportR17C00FileTelnet
	fi
	
	rm -rf /var/equipment_R15C10.tar.gz
	rm -rf /var/equipment_R15C10cut.tar.gz
	rm -rf /var/equipment_R16C00.tar.gz
	rm -rf /var/equipment_R16C00cut.tar.gz
	rm -rf /var/equipment_R16C10.tar.gz
	rm -rf /var/equipment_R16C10cut.tar.gz
	rm -rf /var/equipment_R13C10.tar.gz	
	rm -rf /var/equipment_R15C00.tar.gz
	rm -rf /var/equipment_R15C80.tar.gz
	rm -rf /var/equipment_R15C80_cut.tar.gz
	
	rm -rf /var/equipment_R16C00.tar.gz
	rm -rf /var/equipment_R16C00
	
	rm -rf /var/equipment_R16C10.tar.gz
	rm -rf /var/equipment_R16C10
	
	rm -rf /var/equipment_R17C00.tar.gz
	rm -rf /var/equipment_R17C00
}

echo > $var_nosave

HW_Script_CreateLogFile

HW_Open_Telnet_Ctree_Node

DeleteFileByVersion

HW_Script_DealWithResetKey 

HW_Script_DealWithDBKey   #短柄按键处理

HW_Script_SetCurrent_8120

rm  -rf /var/cplugin
rm  -rf /mnt/jffs2/app/osgi
rm  -rf /mnt/jffs2/app/cplugin

echo "success!" && exit 0

