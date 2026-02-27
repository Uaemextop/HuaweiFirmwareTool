<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/wlan_list.asp"></script>
<script language="javascript" src="./refreshTime.asp"></script>
<title>Guest WiFi</title>
<script language="JavaScript" type="text/javascript">

var DoubleWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';

function stGuestWifi(domain,SSID_IDX,PortIsolation,Duration,UpRateLimit,DownRateLimit,AutoGenFlag)
{
	this.domain = domain;
    this.SSID_IDX = SSID_IDX;
	this.PortIsolation = PortIsolation;
	this.Duration = Duration;
	this.UpRateLimit = UpRateLimit;
	this.DownRateLimit = DownRateLimit;
	this.AutoGenFlag = AutoGenFlag;
}

var GuestWifi = new Array();

var wep1password;

var GuestWifiArr = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.{i},SSID_IDX|PortIsolation|Duration|UpRateLimit|DownRateLimit|AutoGenFlag,stGuestWifi);%>;
var GuestWifiArrLen = GuestWifiArr.length - 1;

for(var i=0; i <GuestWifiArrLen; i++)
{
    GuestWifi[i] = new stGuestWifi();
    GuestWifi[i] = GuestWifiArr[i];
}

function sldcinfo(domain,startIP,endIP,enable)
{
	this.domain		= domain;
	this.startIP    = startIP;
	this.endIP      = endIP;
	this.enable		= enable;
}

var SlaveDhcpInfo= <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2.,MinAddress|MaxAddress|Enable,sldcinfo);%>;
var GuestWifiFlag=SlaveDhcpInfo.length - 1;
function stipaddr(domain,enable,ipaddr,subnetmask)
{
	this.domain		= domain;
	this.enable		= enable;
	this.ipaddr		= ipaddr;
	this.subnetmask	= subnetmask;	
}
var LanIpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.{i},Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask,stipaddr);%>;
if (LanIpInfos[1] == null)
{
    LanIpInfos[1] = new stipaddr("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2", "", "", ""); 
}
function madcinfo(domain,minaddress,maxaddress,enable)
{
	this.domain		= domain;
	this.minaddress = minaddress;
	this.maxaddress = maxaddress;
	this.enable		= enable;
}
var MainDhcpInfo= <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement,MinAddress|MaxAddress|DHCPServerEnable,madcinfo);%>;

function stWlan(domain,name,enable,SSID,SSIDAdvertisementEnabled,DeviceNum,wmmEnable,BeaconType,BasicEncryptionModes,BasicAuthenticationMode,
                KeyIndex,EncryptionLevel,WPAEncryptionModes,WPAAuthenticationMode,IEEE11iEncryptionModes,IEEE11iAuthenticationMode,
                X_HW_WPAand11iEncryptionModes,X_HW_WPAand11iAuthenticationMode,WPARekey,RadiusServer,RadiusPort,RadiusKey,X_HW_ServiceEnable, LowerLayers,
                X_HW_WAPIEncryptionModes,X_HW_WAPIAuthenticationMode,X_HW_WAPIServer,X_HW_WAPIPort, X_HW_Standard)
{
    this.domain = domain;
    this.name = name;
    this.enable = enable;
    this.SSID = SSID;
    this.SSIDAdvertisementEnabled = SSIDAdvertisementEnabled;
    this.DeviceNum = DeviceNum;
    this.wmmEnable = wmmEnable;
    this.BeaconType = BeaconType;
    this.BasicEncryptionModes = BasicEncryptionModes;
    this.BasicAuthenticationMode = BasicAuthenticationMode;
    this.KeyIndex = KeyIndex;
    this.EncypBit = EncryptionLevel;
    this.WPAEncryptionModes = WPAEncryptionModes;
    this.WPAAuthenticationMode = WPAAuthenticationMode;
    this.IEEE11iEncryptionModes = IEEE11iEncryptionModes;
    this.IEEE11iAuthenticationMode = IEEE11iAuthenticationMode;
    this.X_HW_WPAand11iEncryptionModes = X_HW_WPAand11iEncryptionModes;
    this.X_HW_WPAand11iAuthenticationMode = X_HW_WPAand11iAuthenticationMode;
    this.WPARekey = WPARekey;
    this.RadiusServer = RadiusServer;
    this.RadiusPort = RadiusPort;
    this.RadiusKey = RadiusKey;
    this.X_HW_ServiceEnable = X_HW_ServiceEnable;
    this.LowerLayers = LowerLayers;
    this.X_HW_WAPIEncryptionModes = X_HW_WAPIEncryptionModes;
    this.X_HW_WAPIAuthenticationMode = X_HW_WAPIAuthenticationMode;
    this.X_HW_WAPIServer = X_HW_WAPIServer;
    this.X_HW_WAPIPort = X_HW_WAPIPort;
    this.mode = X_HW_Standard;
}
var Wlan = new Array();

var WlanArr = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|Enable|SSID|SSIDAdvertisementEnabled|X_HW_AssociateNum|WMMEnable|BeaconType|BasicEncryptionModes|BasicAuthenticationMode|WEPKeyIndex|WEPEncryptionLevel|WPAEncryptionModes|WPAAuthenticationMode|IEEE11iEncryptionModes|IEEE11iAuthenticationMode|X_HW_WPAand11iEncryptionModes|X_HW_WPAand11iAuthenticationMode|X_HW_GroupRekey|X_HW_RadiuServer|X_HW_RadiusPort|X_HW_RadiusKey|X_HW_ServiceEnable|LowerLayers|X_HW_WAPIEncryptionModes|X_HW_WAPIAuthenticationMode|X_HW_WAPIServer|X_HW_WAPIPort|X_HW_Standard,stWlan);%>;
var WlanWifi = WlanArr[0];
if (null == WlanWifi)
{
    WlanWifi = new stWlanWifi("","","","","11n","","","","","");
}
function stPreSharedKey(domain, value)
{
    this.domain = domain;
    this.value = value;
}
var wpaPskKey = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.PreSharedKey.1,PreSharedKey,stPreSharedKey);%>;

var wlanArrLen = WlanArr.length - 1;

for (i=0; i < wlanArrLen; i++)
{
    Wlan[i] = new stWlan();
    Wlan[i] = WlanArr[i];
}

function stWEPKey(domain, value)
{
    this.domain = domain;
    this.value = value;
}

if (null != g_keys)
{
    wep1password = g_keys[0];
    wep2password = g_keys[1];
    wep3password = g_keys[2];
    wep4password = g_keys[3];
}

var g_keys = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.WEPKey.{i},WEPKey,stWEPKey);%>;

var addFlags = false;
var ssidindex = 0;

var wlanloop = 0;

function getInstIdByDomain(domain)
{
    if ('' != domain)
    {
        return parseInt(domain.charAt(domain.length - 1));    
    }
}

function getinstbyath(name)
{
	for(loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == name)
		{
			return getInstIdByDomain(WlanArr[loop].domain);
		}
	}
	return -1;
}

function getwlanloopbyath(name)
{
	for(loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == name)
		{
			return loop;
		}
	}
	return -1;
}

function GetWepKeyIndex(name)
{
	for(loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == name)
		{
			return Wlan[loop].KeyIndex;
		}
	}
	return -1;
}


var wlaninst = 0;
var wlaninstext = 0;

function ShowOrHideText(checkBoxId, passwordId, textId)
{
    if (1 == getCheckVal(checkBoxId))
    {
        setDisplay(passwordId, 0);
        setDisplay(textId, 1);
    }
    else
    {
        setDisplay(passwordId, 1);
        setDisplay(textId, 0);
    }
}

function changeauthandpassword(value)
{
	displayPasswordEnable();
    if (value == 'open')
    {
		setDisplay("wpakeyInfo", 0);
		setDisplay("wepkeyInfo", 0)
		setDisplay("wepkeylength",0);
				
        setText('pwd_ssidpassword', "");
        setText('txt_ssidpassword', "");
    }
	else if(value == 'shared')
	{
		setDisplay("wpakeyInfo",0);
		setDisplay("wepkeyInfo", 1);
		setDisplay("wepkeylength",1);	
		
		var keyIndex = Wlan[wlanloop].KeyIndex;
		var level = getEncryLevel(Wlan[wlanloop].EncypBit);
		wlanSetSelect('wlKeyBit', parseInt(level)+24);
		
		if(1 == IfAutoGen())
		{
			if((1 == GuestInst)||(3 == GuestInst))
			{
				setText('wlKeys1',wepkey2G);          
				setText('twlKeys1',wepkey2G);
			}
			else
			{
				setText('wlKeys1',wepkey5G);          
				setText('twlKeys1',wepkey5G);
			}
		}
		else
		{
			setText('wlKeys1', g_keys[wlanloop*4+(keyIndex-1)].value);
			setText('twlKeys1',g_keys[wlanloop*4+(keyIndex-1)].value);
		}
	}
    else
    {	
		setDisplay("wpakeyInfo", 1);
		setDisplay("wepkeyInfo", 0)
		setDisplay("wepkeylength",0);	
		
		if(1 == IfAutoGen())
		{
			if((1 == GuestInst)||(3 == GuestInst))
			{
				setText('pwd_ssidpassword',wpakey2G);           
				setText('txt_ssidpassword',wpakey2G);
			}
			else
			{
				setText('pwd_ssidpassword',wpakey5G);           
				setText('txt_ssidpassword',wpakey5G);
			}
		}
		else
		{
			setText('pwd_ssidpassword', wpaPskKey[wlanloop].value);
			setText('txt_ssidpassword',wpaPskKey[wlanloop].value);
		}
    }
}

function setPasswordOrText()
{
	var displayEnable = getCheckVal('displaypassword');
	var psk;
	
	if(0 == displayEnable)
	{
		psk = getValue('pwd_ssidpassword');
	}
	else
	{
		psk = getValue('txt_ssidpassword');
	}
	
	return psk;
}


var keyIndex = Wlan[wlanloop].KeyIndex;

function GetSelectWlanInst()
{
	var enable2G = 0;
	var enable5G = 0;
	for(var loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == 'ath1')
		{
			enable2G = WlanArr[loop].enable;
		}
		
		if(WlanArr[loop].name == 'ath5')
		{
			enable5G = WlanArr[loop].enable;
		}
	}
	
	if(selectRadioFlag == 0)
	{
		GuestInst = 1;
		setSelect('GuestwifiRadio',0);
		wlaninst = getinstbyath("ath1");
		wlanloop = getwlanloopbyath("ath1");
		if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>' == '1')
		{
			wlaninstext = getinstbyath("ath5");
		}
		else
		{
			wlaninstext = wlaninst;
		}
	}
	else if(2 == selectRadioFlag)
	{
		GuestInst = 3;
		setSelect('GuestwifiRadio',2);
		wlaninst = getinstbyath("ath1");
		wlaninstext = getinstbyath("ath5");
		wlanloop = getwlanloopbyath("ath1");
	}
	else 
	{
		GuestInst = 2;
		setSelect('GuestwifiRadio',1)
		wlaninstext = getinstbyath("ath1");
		wlaninst = getinstbyath("ath5");
		wlanloop = getwlanloopbyath("ath5");		
	}
}

function checkssidname()
{
	var ssidname = getValue('ssidname');
	if(ssidname == '')
	{
		AlertEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_checkssid']);
		return false;
	}
	return true;
}

function checkModifyAutoGenKey()
{
	if(0 == GuestWifi[0].AutoGenFlag)
	{
		if((0 == getSelectVal('GuestwifiRadio'))||(2 == getSelectVal('GuestwifiRadio')))
		{
			if(wpakey2G ==getValue('txt_ssidpassword') && wepkey2G == getValue('twlKeys1'))
			{
				if (ConfirmEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_modify_key'])) 
				{
					return false;
				}
			}
		}
		else
		{	
			if(wpakey5G ==getValue('txt_ssidpassword') && wepkey5G == getValue('twlKeys1'))
			{
				if (ConfirmEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_modify_key'])) 
				{
					return false;
				}
			}
		}
	}
	return true;
}

function IsLessThan(lip, rip)
{
	var ladress = lip.split('.');
	var radress = rip.split('.');
	var ladnum = 0;
	var radnum = 0;
	
	for(var i = 0; i < 4; i++)
	{
		ladnum = ladnum + parseInt(ladress[i], 10);
		radnum = radnum + parseInt(radress[i], 10);
	}

	if(ladnum <= radnum)
	{
	    return true;
	}
	return false;
}

function CheckStEdIp()
{
    var guestwifiroute = LanIpInfos[0].ipaddr;
    var guestwifiMask = LanIpInfos[0].subnetmask;
	
	if (isValidIpAddress(getValue("StartIPaddress")) == false) 
	{
	   AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfstartipinvalid']);
   	   return false;
	}

	if (isBroadcastIp(getValue("StartIPaddress"), guestwifiMask) == true)
	{
	   AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfstartipinvalid']);
	   return false;
	}

	if (false == isSameSubNet(getValue("StartIPaddress"),guestwifiMask,guestwifiroute,guestwifiMask))
	{
		AlertEx(cfg_wlanguestwifi_language['bbsp_gststipinsamemahost']);
		return false;
	}

	if (isValidIpAddress(getValue("EndIPaddress")) == false) 
	{
		AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfendipinvalid']);
		return false;
	}

	if (isBroadcastIp(getValue("EndIPaddress"), guestwifiMask) == true)
	{
		AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfendipinvalid']);
		return false;
	}

	if (false == isSameSubNet(getValue("EndIPaddress"),guestwifiMask,guestwifiroute,guestwifiMask))
	{
		AlertEx(cfg_wlanguestwifi_language['bbsp_gststipinsamemahost']);
		return false;
	}

	if (!(isEndGTEStart(getValue("EndIPaddress"), getValue("StartIPaddress")))) 
	{
		AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfendipgeqstartip']);
		return false;
	}
	   
	if(((IsLessThan(MainDhcpInfo[0].minaddress, getValue("EndIPaddress")) && IsLessThan(getValue("StartIPaddress"), MainDhcpInfo[0].minaddress)) || 
		(IsLessThan(MainDhcpInfo[0].minaddress, getValue("StartIPaddress")) && IsLessThan(getValue("EndIPaddress"), MainDhcpInfo[0].maxaddress))))
	{
	   AlertEx(cfg_wlanguestwifi_language['bbsp_gstwfpoolinmianpool']);
	   return false;
	}

	
	   return true;
}
function funProtectionmodeSelect()
{
	var value = getSelectVal('wlAuthMode');
	changeauthandpassword(value);
}

var broadenable2g = 0;
var broadenable5g = 0;
var setBroadFlag = 0;

function SetWifiBroadcastEnable()
{
	setBroadFlag = 1;
	if((GuestInst == 1)||(GuestInst == 3))
	{
		broadenable2g = 1 - broadenable2g;
		if(broadenable2g == 1)
		{
			$("#swithicon").attr("src", "../../../images/checkon.jpg");
		}
		else
		{
			$("#swithicon").attr("src", "../../../images/checkoff.jpg");
		}
	}
	else
	{
		broadenable5g = 1 - broadenable5g;
		if(broadenable5g == 1)
		{
			$("#swithicon").attr("src", "../../../images/checkon.jpg");
		}
		else
		{
			$("#swithicon").attr("src", "../../../images/checkoff.jpg");
		}
	}

}

function getWifiBroadcastEnable()
{
	if((GuestInst == 1)||(GuestInst == 3))
	{
		return broadenable2g;
	}
	else
	{
		return broadenable5g;
	}
}

function CheckStreamRateValue()
{ 
    var UpstreamRate = getValue('wlUpRate');
    var DownstreamRate = getValue('wlDownRate');

    if(!isInteger(UpstreamRate))
    {
        AlertEx(cfg_wlanguestwifi_language['amp_uprate_int']);
        return false;
    }

    if( (parseInt(UpstreamRate,10) < 0) || (parseInt(UpstreamRate,10) > 4094) )
    {
        AlertEx(cfg_wlanguestwifi_language['amp_uprate_out_range']);
        return false;
    }

    if(!isInteger(DownstreamRate))
    {
        AlertEx(cfg_wlanguestwifi_language['amp_downrate_int']);
        return false;
    }

    if( (parseInt(DownstreamRate,10) < 0) || (parseInt(DownstreamRate,10) > 4094) )
    {
        AlertEx(cfg_wlanguestwifi_language['amp_downrate_out_range']);
        return false;
    }

    return true;
}

function checkDuration()
{
	var durationTime = getValue('ActivationTimeLimit');
	if(!isInteger(durationTime))
    {
        return false;
    }
	if(parseInt(durationTime,10) < 0)
    {
        return false;
    }
	return true;
}

function checkRadioEnable()
{
	var enable2g = RadioEnableByBand("2G");
	var enable5g = RadioEnableByBand("5G");
	
	if(enable2g == false)
	{
		if((0 == getSelectVal('GuestwifiRadio'))||(2 == getSelectVal('GuestwifiRadio')))
		{
			return false;
		}
	}
	if(enable5g == false)
	{
		if((1 == getSelectVal('GuestwifiRadio'))||(2 == getSelectVal('GuestwifiRadio')))
		{
			return false;
		}
	}
	return true;
}

function getWlanPortNumber(name)
{
    var length = name.length;
    var number;
    var str = parseInt(name.charAt(length-1));
    return str;
}

function checkSharedAuthentication()
{
	var value = getSelectVal('wlAuthMode');
	var loop2g = getwlanloopbyath("ath0");
	var loop5g = getwlanloopbyath("ath4");
	
	if(value == 'shared')
	{
		if(0 == getSelectVal('GuestwifiRadio'))
		{
			if("11n" == WlanArr[loop2g].mode)
			{
				AlertEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_checkwep']);
				return false;
			}
		}
		else
		{		
			if (((WlanArr[loop2g].mode == "11n") || (WlanArr[loop2g].mode == "11ac"))||
			((WlanArr[loop5g].mode == "11n") || (WlanArr[loop5g].mode == "11ac")))
			{
				AlertEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_checkwep']);
				return false;
			}
		}
	}
	return true;
}

function SSIDcheck()
{
	var i = 0;
	var ssid = getValue('ssidname');
	for (i = 0; i < Wlan.length; i++)
    {	
		if((getWlanPortNumber(Wlan[i].name) == 5)||(getWlanPortNumber(Wlan[i].name) == 1))
		{
			continue;
		}

        if (wlanloop != i)
        {
        	if (Wlan[i].SSID == ssid)
            {
                AlertEx(cfg_wlancfgother_language['amp_ssid_exist']);
                return false;
            }
        }
        else
        {
            continue;
        }
    }
}

function getbeaconandkey(Form,inst)
{
	var value = getSelectVal('wlAuthMode');
	
	var pskpassword;
	
	var txtpskpassword =  getValue('txt_ssidpassword');
	var pswpskpassword =  getValue('pwd_ssidpassword');
	
	var wlKeys1 = getValue('wlKeys1');
	
	var KeyBit = getSelectVal('wlKeyBit');
	
	if(value == 'open')
	{
		Form.addParameter('x' + inst + '.BeaconType','Basic');
		Form.addParameter('x' + inst + '.BasicAuthenticationMode','None');
		Form.addParameter('x' + inst + '.BasicEncryptionModes','None');
	}
	else if(value == 'shared')
	{
	
		Form.addParameter('x' + inst + '.BeaconType','Basic');
		Form.addParameter('x' + inst + '.BasicEncryptionModes','WEPEncryption');
		Form.addParameter('x' + inst + '.BasicAuthenticationMode','SharedAuthentication');
		Form.addParameter('x' + inst + '.WEPEncryptionLevel',(KeyBit-24)+'-bit');
		
		if (KeyBit == '128')
		{
			if ( (wlKeys1 != "*************") || (wep1PsdModFlag == true)|| (1 == curUserType) )
			{
				Form.addParameter('k' + inst +'.WEPKey', getValue('twlKeys1'));
			}
		}
		else
		{
			if ( (wlKeys1 != "*****") || (wep1PsdModFlag == true) || (1 == curUserType))
			{
				Form.addParameter('k' + inst +'.WEPKey', getValue('twlKeys1'));
			}
		}
	}
	else if(value == 'wpa-psk')
	{
		Form.addParameter('x' + inst + '.BeaconType','WPA');
		Form.addParameter('x' + inst + '.WPAAuthenticationMode','PSKAuthentication');
		
		if ((pswpskpassword != "********") || (pskPsdModFlag == true) || (1 == curUserType))
		{
			Form.addParameter('z' + inst + '.PreSharedKey', pswpskpassword);
		}    
	}
	else if(value == 'wpa2-psk')
	{
		Form.addParameter('x' + inst + '.BeaconType','11i');
		Form.addParameter('x' + inst + '.IEEE11iAuthenticationMode','PSKAuthentication');
		if ((pswpskpassword != "********") || (pskPsdModFlag == true) || (1 == curUserType))
		{
			Form.addParameter('z' + inst +  '.PreSharedKey', pswpskpassword);
		}  
	}
	else if(value == 'wpa/wpa2-psk')
	{
		Form.addParameter('x' + inst + '.BeaconType','WPAand11i');
		Form.addParameter('x' + inst + '.X_HW_WPAand11iAuthenticationMode','PSKAuthentication');
		if ((pswpskpassword != "********") || (pskPsdModFlag == true) || (1 == curUserType))
		{
			Form.addParameter('z' + inst + '.PreSharedKey', pswpskpassword);
		}  
	}
}

function AddAutoGenPara(Form,inst,GuestInst)
{
	if((1 == IfAutoGen())&&(1 == DoubleWlanFlag))
	{
		if(1 == GuestInst)
		{
			Form.addParameter('z' + inst + '.PreSharedKey', wpakey5G);
			Form.addParameter('k' + inst +'.WEPKey', wepkey5G);
			Form.addParameter('x' +inst+ '.SSID', guestrandomssid5G);
		}
		else
		{
			Form.addParameter('z' + inst + '.PreSharedKey', wpakey2G);
			Form.addParameter('k' + inst +'.WEPKey', wepkey2G);
			Form.addParameter('x' +inst+ '.SSID', guestrandomssid2G);
		}
	}
}

function AddAnotherAutoKey(Form,inst,wpakey,wepkey)
{
	var value = getSelectVal('wlAuthMode');
	if(1 == IfAutoGen())
	{
		if(value == 'shared')
		{
			Form.addParameter('z' + inst + '.PreSharedKey', wpakey);
		}
		else if(value == 'wpa-psk' || value == 'wpa2-psk' || value == 'wpa/wpa2-psk')
		{
			Form.addParameter('k' + inst +'.WEPKey', wepkey);
		}	
	}
}

function AddOpenAuthKey(Form,inst,wpakey,wepkey)
{
	var value = getSelectVal('wlAuthMode');	
	if(1 == IfAutoGen())
	{
		if(value == 'open')
		{
			Form.addParameter('z' + inst + '.PreSharedKey', wpakey);
			Form.addParameter('k' + inst +'.WEPKey', wepkey);		
		}
	}
}

function AddWlanPara(Form,inst,enable)
{
	if(0 == getCheckVal('EnableGuestWifi'))
	{
		Form.addParameter('x' +inst+ '.Enable', 0);
	}
	else
	{
		Form.addParameter('x' +inst+ '.Enable', 1);
	}
    Form.addParameter('x' +inst+ '.SSID', getValue('ssidname'));
	Form.addParameter('x' +inst+ '.SSIDAdvertisementEnabled', enable);
}

function AddGuestPara(Form,GuestInst,wlaninst)
{
	Form.addParameter('y'+GuestInst+'.SSID_IDX', wlaninst);
	Form.addParameter('y'+GuestInst+'.Duration', parseInt(getValue('ActivationTimeLimit'),10));
	Form.addParameter('y'+GuestInst+'.UpRateLimit', parseInt(getValue('wlUpRate'), 10));
	Form.addParameter('y'+GuestInst+'.DownRateLimit', parseInt(getValue('wlDownRate'), 10));
	getAutoGenFlag(Form);
}

function getAutoGenFlag(Form)
{
	if(1 == SetAutoGenFlag)
	{
		Form.addParameter('y'+1+'.AutoGenFlag', 1);
		if(1 == DoubleWlanFlag)
		{
			Form.addParameter('y'+2+'.AutoGenFlag', 1);
		}
	}
}

function CheckWepPassword()
{
	var value = getSelectVal('wlAuthMode');
	
	if(value != 'shared')
	{
		return;
	}
	
	var val = getValue('twlKeys1');
	var KeyBit = getSelectVal('wlKeyBit');
	   if ( val != '' && val != null)
	   { 
		   if ( KeyBit == '128' )
		   {
			   if (isValidKey(val, 13) == false )
			   {
				   AlertEx(cfg_wlancfgdetail_language['amp_key_check1'] + val + cfg_wlancfgdetail_language['amp_key_invalid1']);
				   return false;
			   }
		   }
		   else
		   {
			   if (isValidKey(val, 5) == false )
			   {
				   AlertEx(cfg_wlancfgdetail_language['amp_key_check1'] + val + cfg_wlancfgdetail_language['amp_key_invalid2']);
				   return false;
			   }
		   }
	   }
	   else
	   {
		   AlertEx(cfg_wlancfgdetail_language['amp_key_invalid3']);
		   return false;
	   }
}


function isValidKey(val, size)
{
    var ret = false;
    var len = val.length;
    var dbSize = size * 2;
 
      if (isValidAscii(val) != '')
     { 
        return false;
         }

    if ( len == size )
       ret = true;
    else if ( len == dbSize )
    {
       for ( i = 0; i < dbSize; i++ )
          if ( isHexaDigit(val.charAt(i)) == false )
             break;
       if ( i == dbSize )
          ret = true;
    }
    else
      ret = false;

   return ret;
}

function NoSelectRadioGetWlanInst()
{
	var enable2G = 0;
	var enable5G = 0;
	for(var loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == 'ath1')
		{
			enable2G = WlanArr[loop].enable;
		}
		
		if(WlanArr[loop].name == 'ath5')
		{
			enable5G = WlanArr[loop].enable;
		}
	}
	
	if((enable5G ==0)&&(enable2G ==1))
	{
		GuestInst = 1;
		setSelect('GuestwifiRadio',0);
		wlaninst = getinstbyath("ath1");
		wlanloop = getwlanloopbyath("ath1");
		if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>' == '1')
		{
			wlaninstext = getinstbyath("ath5");
			wlanloopext =  getwlanloopbyath("ath5");
		}
		else
		{
			wlaninstext = wlaninst;
		}
	}
	else if((enable5G ==1)&&(enable2G ==0))
	{
		GuestInst = 2;
		setSelect('GuestwifiRadio',1)
		wlaninstext = getinstbyath("ath1");
		wlaninst = getinstbyath("ath5");
		wlanloop = getwlanloopbyath("ath5");	
	}
	else
	{   
		if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>' == '1')
		{
			GuestInst = 3;
			setSelect('GuestwifiRadio',2);
			wlaninst = getinstbyath("ath1");
			wlaninstext = getinstbyath("ath5");
			wlanloop = getwlanloopbyath("ath1");
		}
		else
		{
			GuestInst = 1;
			setSelect('GuestwifiRadio',0);
			wlaninst = getinstbyath("ath1");
			wlanloop = getwlanloopbyath("ath1");
			wlaninstext = wlaninst;
		}

	}
}

function btnApplySubmit()
{
	if(IfSelectRadio == 0)
	{
		NoSelectRadioGetWlanInst();
	}

	if(false == CheckWepPassword())
	{
		return;
	}

	if(false == SSIDcheck())
	{
		return;
	}

	if(false == checkRadioEnable())
	{
		AlertEx(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_checkradio']);
		return;
	}
	
	if(false == checkssidname())
	{
		return;
	}
	
	if (false == CheckStreamRateValue())
    {
        return;
    }
	

	if(1 == getCheckVal('EnableGuestWifi'))
	{
		if(false == CheckStEdIp())
		{
			return;
		}
	}
	
	if(false == checkSharedAuthentication())
	{
		return;
	}
	
	if(false == checkModifyAutoGenKey())
	{
		return;
	}
	
	var Form = new webSubmitForm();
	
	var BroadEnable = 0;
	if(setBroadFlag == 1)
	{
		BroadEnable = getWifiBroadcastEnable();
		setBroadFlag = 0;
	}
	else
	{
		BroadEnable = Wlan[wlanloop].SSIDAdvertisementEnabled;
	}
	
	if((GuestInst == 1)||(GuestInst == 2))
	{
		getbeaconandkey(Form,wlaninst);

		AddWlanPara(Form,wlaninst,BroadEnable);
		AddAutoGenPara(Form,wlaninstext,GuestInst);
		
		if(GuestInst == 1)
		{
			AddAnotherAutoKey(Form,wlaninst,wpakey2G,wepkey2G);
			if(1 == DoubleWlanFlag)
			{	
				AddOpenAuthKey(Form,wlaninst,wpakey2G,wepkey2G);
				AddOpenAuthKey(Form,wlaninstext,wpakey5G,wepkey5G);
			}
			else
			{
				AddOpenAuthKey(Form,wlaninst,wpakey2G,wepkey2G);
			}
		}
		else
		{
			AddAnotherAutoKey(Form,wlaninst,wpakey5G,wepkey5G);

			AddOpenAuthKey(Form,wlaninst,wpakey5G,wepkey5G);
			AddOpenAuthKey(Form,wlaninstext,wpakey2G,wepkey2G);
		}		
		
		if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>' == '1')
		{
			Form.addParameter('x'+wlaninstext+'.Enable', 0);
		}
		AddGuestPara(Form,GuestInst,wlaninst);
	}
	else
	{
		getbeaconandkey(Form,wlaninst);
		getbeaconandkey(Form,wlaninstext);
		AddAnotherAutoKey(Form,wlaninst,wpakey2G,wepkey2G);
		AddAnotherAutoKey(Form,wlaninstext,wpakey5G,wepkey5G);
		AddWlanPara(Form,wlaninst,BroadEnable);
		AddWlanPara(Form,wlaninstext,BroadEnable);
		AddGuestPara(Form,1,wlaninst);
		AddGuestPara(Form,2,wlaninstext);
	}
	
	if(GuestWifiFlag == 0)
	{
		Form.addParameter('Add_p.Enable', '1');
		Form.addParameter('Add_p.MinAddress', getValue('StartIPaddress'));
    	Form.addParameter('Add_p.MaxAddress', getValue('EndIPaddress'));
		Form.addParameter('Add_p.IPRouters',  LanIpInfos[0].ipaddr);
		Form.addParameter('Add_p.SubnetMask', LanIpInfos[0].subnetmask);
		Form.addParameter('Add_p.DHCPLeaseTime', '1800');
		Form.addParameter('Add_p.X_HW_Description',"guestwifi");
		Form.addParameter('Add_p.PoolOrder',"1");

		var SL = GetSSIDList();
		var path1 = '';
		var path2 = '';
		var path = '';
		
		for(var i = 0; i < SL.length; i++)
		{
			if(wlaninst == getWlanInstFromDomain(SL[i].domain))
			{
				path1 = SL[i].domain;
			}

			if(wlaninstext == getWlanInstFromDomain(SL[i].domain))
			{
				path2 = SL[i].domain;
			}
		}
		if((getSelectVal('GuestwifiRadio') == 2)&&(path1 != '')&&(path2 != ''))
		{
			path = path1 + ',' + path2;
		}
		else
		{
			path = path1;
		}
		Form.addParameter('Add_p.SourceInterface',path);


		Form.addParameter('x.X_HW_Token', getValue('onttoken'));

		if(0 == getCheckVal('EnableGuestWifi'))
		{
			Form.setAction('complex.cgi?'
			+ '&x'+ wlaninst + '=' + getWlanPath(wlaninst)
			+ '&x'+ wlaninstext + '=' + getWlanPath(wlaninstext)
			+ getGuestPath(GuestInst) 
			+ getWlanPskPath()
			+ getWlanWepPath()
			+ '&RequestFile=html/amp/wlanbasic/VDFWlanGuestWifi.asp');		}
		else
		{
			Form.setAction('complex.cgi?'
			+ '&x'+ wlaninst + '=' + getWlanPath(wlaninst)
			+ '&x'+ wlaninstext + '=' + getWlanPath(wlaninstext)
			+ getGuestPath(GuestInst) 
			+ getWlanPskPath()
			+ getWlanWepPath()
			+ '&Add_p=' + 'InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.'
			+ '&RequestFile=html/amp/wlanbasic/VDFWlanGuestWifi.asp');
		}

	}
	else
	{
		Form.addParameter('w.Enable', '1');
		Form.addParameter('w.MinAddress', getValue('StartIPaddress'));
    	Form.addParameter('w.MaxAddress', getValue('EndIPaddress'));
		Form.addParameter('w.IPRouters',  LanIpInfos[0].ipaddr);
		Form.addParameter('w.SubnetMask', LanIpInfos[0].subnetmask);
		Form.addParameter('w.DHCPLeaseTime', '1800');
		Form.addParameter('w.X_HW_Description',"guestwifi");
		Form.addParameter('w.PoolOrder',"1");

		var SL = GetSSIDList();
		var path1 = '';
		var path2 = '';
		var path = '';
		
		for(var i = 0; i < SL.length; i++)
		{
			if(wlaninst == getWlanInstFromDomain(SL[i].domain))
			{
				path1 = SL[i].domain;
			}

			if(wlaninstext == getWlanInstFromDomain(SL[i].domain))
			{
				path2 = SL[i].domain;
			}
		}

		if((getSelectVal('GuestwifiRadio') == 2)&&(path1 != '')&&(path2 != ''))
		{
			path = path1 + ',' + path2;
		}
		else
		{
			path = path1;
		}
		
		Form.addParameter('w.SourceInterface', path);

		Form.addParameter('x.X_HW_Token', getValue('onttoken'));

		if(0 == getCheckVal('EnableGuestWifi'))
		{
			Form.setAction('complex.cgi?'
		                    + '&x'+ wlaninst + '=' + getWlanPath(wlaninst)
							+ '&x'+ wlaninstext + '=' + getWlanPath(wlaninstext)
							+ getGuestPath(GuestInst) 
							+ '&Del_z=' + 'InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2'
							+ getWlanPskPath()
							+ getWlanWepPath()
							+ '&RequestFile=html/amp/wlanbasic/VDFWlanGuestWifi.asp');
		}
		else
		{
			Form.setAction('set.cgi?'
		                    + '&x'+ wlaninst + '=' + getWlanPath(wlaninst)
							+ '&x'+ wlaninstext + '=' + getWlanPath(wlaninstext)
							+ getGuestPath(GuestInst) 
							+ '&w=' + 'InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.2'
							+ getWlanPskPath()
							+ getWlanWepPath()
							+ '&RequestFile=html/amp/wlanbasic/VDFWlanGuestWifi.asp');
		}
	}

    Form.submit();
	setDisable('btnApplySubmit', 1);
}

function getWlanPath(wlcInst)
{
	if (!(0< wlcInst && wlcInst < 8))
	{
		return 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.' + '2';
	}
	return 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.' + wlcInst;
}

function getWlanPskPath()
{
	if((GuestInst == 1)||(GuestInst == 2))
	{
		if((1 == IfAutoGen())&&(1 == DoubleWlanFlag))
		{
			return '&z' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.PreSharedKey.1'+
			'&z' + wlaninstext + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninstext+ '.PreSharedKey.1';
			
		}
		else
		{
			return '&z' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.PreSharedKey.1';
		}
	}
	else
	{
		return '&z' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.PreSharedKey.1' + 
				'&z' + wlaninstext + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninstext+ '.PreSharedKey.1';
	}
}

function getWlanWepPath()
{
	if(GuestInst == 1)
	{
		if((1 == IfAutoGen())&&(1 == DoubleWlanFlag))
		{
			return '&k' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.WEPKey.' + GetWepKeyIndex("ath1")+
			'&k' + wlaninstext + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninstext+ '.WEPKey.' + GetWepKeyIndex("ath5");
		}
		else
		{
			return '&k' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.WEPKey.' + GetWepKeyIndex("ath1");
		}
	}
	else if(GuestInst == 2)
	{
		if((1 == IfAutoGen())&&(1 == DoubleWlanFlag))
		{
			return '&k' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.WEPKey.' + GetWepKeyIndex("ath5")+
			'&k' + wlaninstext + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninstext+ '.WEPKey.' + GetWepKeyIndex("ath1");
		}
		else
		{
			return '&k' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.WEPKey.' + GetWepKeyIndex("ath5");
		}
	}
	else
	{
		return '&k' + wlaninst + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninst+ '.WEPKey.' + GetWepKeyIndex("ath1")+
				'&k' + wlaninstext + '=' + 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.'+ wlaninstext+ '.WEPKey.' + GetWepKeyIndex("ath5");
	}
}

function getGuestPath(GuestInst)
{
	if((GuestInst == 1)||(GuestInst == 2))
	{
		if((1 == IfAutoGen())&&(1 == DoubleWlanFlag))
		{
			return '&y1' + '=' + 'InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.1'+ 
			'&y2'+ '=' + 'InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.2';
		}
		else
		{
			return '&y' + GuestInst + '=' + 'InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.'+ GuestInst;
		}
	}
	else
	{
		return '&y' + '1' + '=' + 'InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.'+ '1' +'&y' + '2' + '=' + 'InternetGatewayDevice.LANDevice.1.X_HW_WLANForGuest.'+ '2';
	}
}

function cancelValue()
{
	LoadFrame();
}

function displayPasswordEnable()
{
	if(0 == curUserType)
	{
		setCheck('displaypassword',0);
		setCheck('hidewlKeys',0);
		setDisable('displaypassword',1);
		setDisable('hidewlKeys',1);
	}
	else
	{
		setDisable('displaypassword',0);
		setDisable('hidewlKeys',0);
	}
}

function wlanSetSelect(id, val)
{
	setSelect(id, val);
}


function getEncryLevel(encrylevel)
{
    var level = '';
    for (var i = 0; i < encrylevel.length; i++)
    {
        if (encrylevel.charAt(i) != '-')
        {
            level += encrylevel.charAt(i);
        }
        else
        {
            break;
        }
    }
    return level;
}

function beaconTypeChange(authMode,wlanloop)
{
	if (authMode == 'Basic')
	{
		var BasicAuthenticationMode = Wlan[wlanloop].BasicAuthenticationMode;
		if ((BasicAuthenticationMode == 'None') || (BasicAuthenticationMode == 'OpenSystem'))
		{
			wlanSetSelect('wlAuthMode','open');
			setDisplay('wpakeyInfo', 0);
			setDisplay('wepkeyInfo', 0);
			setDisplay('wepkeylength', 0);
		}
		else
		{
			var level = getEncryLevel(Wlan[wlanloop].EncypBit);
			var mode = WlanWifi.mode; 
			
			if ((mode == "11n") || (mode == "11ac"))
            { 
			      setDisplay('wpakeyInfo', 0);			
                  setDisplay('wepkeyInfo', 0);   
				  setDisplay('wepkeylength', 0);				  
            }
			else
			{
				wlanSetSelect('wlAuthMode','shared');
				wlanSetSelect('wlKeyBit', parseInt(level)+24);
				setDisplay('wpakeyInfo', 0);
				setDisplay('wepkeyInfo', 1);
				setDisplay('wepkeylength', 1);
				
				var keyIndex = Wlan[wlanloop].KeyIndex;
				
				setText('wlKeys1', g_keys[wlanloop*4+(keyIndex-1)].value);
				setText('twlKeys1',g_keys[wlanloop*4+(keyIndex-1)].value);
			}
		}
	}
	else if(authMode == 'WPA')
	{
            setDisplay("wpakeyInfo", 1);
			setDisplay('wepkeyInfo', 0);
			setDisplay('wepkeylength', 0);	
            wlanSetSelect('wlAuthMode','wpa-psk');
            setText('pwd_ssidpassword',wpaPskKey[wlanloop].value); 
			setText('txt_ssidpassword',wpaPskKey[wlanloop].value);
            wpapskpassword = wpaPskKey[wlanloop].value; 
	}
	else if((authMode == 'WPA2')||(authMode == '11i'))
	{
            setDisplay("wpakeyInfo", 1);
			setDisplay('wepkeyInfo', 0);
			setDisplay('wepkeylength', 0);
            wlanSetSelect('wlAuthMode','wpa2-psk');
            setText('pwd_ssidpassword',wpaPskKey[wlanloop].value); 
            wpapskpassword = wpaPskKey[0].value; 
            setText('txt_ssidpassword',wpaPskKey[wlanloop].value);    
	}
	else if((authMode == 'WPAand11i')||(authMode == 'WPA/WPA2'))
	{
            setDisplay("wpakeyInfo", 1);
			setDisplay('wepkeyInfo', 0);
			setDisplay('wepkeylength', 0);
            wlanSetSelect('wlAuthMode','wpa/wpa2-psk');
            setText('pwd_ssidpassword',wpaPskKey[wlanloop].value); 
            wpapskpassword = wpaPskKey[0].value; 
            setText('txt_ssidpassword',wpaPskKey[wlanloop].value);
	}
	else
	{
		    wlanSetSelect('wlAuthMode','open');
			setDisplay('wpakeyInfo', 0);
			setDisplay('wepkeyInfo', 0);
			setDisplay('wepkeylength', 0);
	}
	
	if (1 == getCheckVal('displaypassword'))
    {
        setDisplay('pwd_ssidpassword', 0);
        setDisplay('txt_ssidpassword', 1);
    }
    else
    {
        setDisplay('pwd_ssidpassword', 1);
        setDisplay('txt_ssidpassword', 0);
    }
}


function RadioEnableByBand(band)
{
    if(0 == WlanEnable[0].enable)
    {
        return false;
    }
    if(band == "2G")
    {
        return enbl2G;
    }
    else if(band == "5G")
    {
        return enbl5G;
    }
    return false;
}

var GuestInst = 1;
var selectRadioFlag = 0;
var IfSelectRadio = 0;
function funGuestwifiRadioSelect(id)
{
	IfSelectRadio = 1; 
	var loop = 0;
   if(0 == getSelectVal(id))
   {
		selectRadioFlag = 0;
		loop = getwlanloopbyath("ath1");
   }
   else if(1 == getSelectVal(id))
   {
		selectRadioFlag = 1;
		loop = getwlanloopbyath("ath5");

   }
   else if(2 == getSelectVal(id))
   {
		selectRadioFlag = 2;
		loop = getwlanloopbyath("ath1");
   }
   
   InitGuestWifiInfo(loop);
   GetSelectWlanInst();
   displayPasswordEnable();
   
   if(1 == IfAutoGen())
   {
	   if((2 == getSelectVal(id))||(0 == getSelectVal(id)))
	   {
			selectRadioDisplayRandomSsidAndKey('2G');
	   }
	   else
	   {
			selectRadioDisplayRandomSsidAndKey('5G');
	   }
   }
}

function selectRadioDisplayRandomSsidAndKey(radio)
{
	if(1 == DoubleWlanFlag)
	{
		if('2G' == radio)
		{
			setText('ssidname',guestrandomssid2G);
			setText('pwd_ssidpassword',wpakey2G);           
			setText('txt_ssidpassword',wpakey2G);
		}
		else if('5G' == radio)
		{
			setText('ssidname',guestrandomssid5G);
			setText('pwd_ssidpassword',wpakey5G);           
			setText('txt_ssidpassword',wpakey5G);
		}
	}
}

var pskPsdModFlag = false;
var wep1PsdModFlag = false;

function InitGuestWifiInfo(wlanloop)
{
    setText('ssidname', Wlan[wlanloop].SSID);
	setCheck('displaypassword', 0); 
	
	var authMode = Wlan[wlanloop].BeaconType;
	beaconTypeChange(authMode,wlanloop); 
	
	$('#pwd_ssidpassword').bind("propertychange input", function(){ 
	if(getValue('pwd_ssidpassword') != "********") 
	{
		pskPsdModFlag = true;
	} 
	} );
	
	$('#wlKeys1').bind("propertychange input", function(){ 
	var KeyBit = getSelectVal('wlKeyBit');
	if (KeyBit == '128')
	{
		if (getValue('wlKeys1') != "*************")
		{
			wep1PsdModFlag = true;
		}            
	}
	else 
	{	
		if(getValue('wlKeys1') != "*****") 
		{
			wep1PsdModFlag = true;
		}
	}
	} );
	
	
	if(Wlan[wlanloop].SSIDAdvertisementEnabled == 1)
	{
		$("#swithicon").attr("src", "../../../images/checkon.jpg");
	}
	else
	{
		$("#swithicon").attr("src", "../../../images/checkoff.jpg");
	}
	

	if((0 == getSelectVal('GuestwifiRadio'))||(2 == getSelectVal('GuestwifiRadio')))
	{
		setText('ActivationTimeLimit', GuestWifi[0].Duration);
		setText('wlUpRate', GuestWifi[0].UpRateLimit);
		setText('wlDownRate', GuestWifi[0].DownRateLimit);
	}
	else
	{
		setText('ActivationTimeLimit', GuestWifi[1].Duration);
		setText('wlUpRate', GuestWifi[1].UpRateLimit);
		setText('wlDownRate', GuestWifi[1].DownRateLimit);
	}

	if(GuestWifiFlag == 0)
	{
    	var guestwifiroute = LanIpInfos[0].ipaddr.split('.');
		setText('StartIPaddress', guestwifiroute[0] + '.' + guestwifiroute[1] + '.' + guestwifiroute[2] + '.' + '2');
		setText('EndIPaddress', guestwifiroute[0] + '.' + guestwifiroute[1] + '.' + guestwifiroute[2] + '.' + '63'); 
	}
	else
	{
		setText('StartIPaddress', SlaveDhcpInfo[0].startIP);
		setText('EndIPaddress', SlaveDhcpInfo[0].endIP);
	
	}
}

var enable2G = 0;
var enable5G = 0;
function GetEnableGuestInst()
{
	for(var loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == 'ath1')
		{
			enable2G = WlanArr[loop].enable;
		}
		
		if(WlanArr[loop].name == 'ath5')
		{
			enable5G = WlanArr[loop].enable;
		}
	}
	
	if(((enable2G == 1)&&(enable5G == 0))||((enable2G == 0)&&(enable5G == 0))||((enable2G == 1)&&(enable5G == 1)))
	{
		return getwlanloopbyath("ath1");
	}
	else
	{
		return getwlanloopbyath("ath5");		
	}
}

function EnableGuestWifi()
{
	var GuestWifi5GSSID;
	var GuestWifi2GSSID;
	
	if(0 == getCheckVal('EnableGuestWifi'))
	{
		setDisplay('GuestWifiInfo',0);
	}
	else
	{
		setDisplay('GuestWifiInfo',1);
		AutoGenSsidAndKey();
	}
}

function LoadGuestWifiInfo()
{
	if((enable5G == 1)||(enable2G == 1))
	{
		setCheck('EnableGuestWifi',1);
		setDisplay('GuestWifiInfo',1);
	}
	else
	{
		setCheck('EnableGuestWifi',0);
		setDisplay('GuestWifiInfo',0);
	}
}

function LoadSelectRadio()
{
	if(((enable5G == 1)&&(enable2G == 1))||((enable5G == 0)&&(enable2G == 0)))
	{
		setSelect('GuestwifiRadio', 2);
	}
	else if((enable5G == 1)&&(enable2G == 0))
	{
		setSelect('GuestwifiRadio', 1);
	}
	else
	{
		setSelect('GuestwifiRadio', 0);
	}
}

function InitBroadEnable()
{
	for(var loop=0;loop < WlanArr.length-1;loop++)
	{
		if(WlanArr[loop].name == 'ath1')
		{
			broadenable2g = WlanArr[loop].SSIDAdvertisementEnabled;
		}
		
		if(WlanArr[loop].name == 'ath5')
		{
			broadenable5g = WlanArr[loop].SSIDAdvertisementEnabled;
			
		}
	}
}

function GetPrivateSSID(athindex)
{
	for (var i = 0; i < Wlan.length; i++)
	{
		if(getWlanPortNumber(Wlan[i].name) == athindex)
		{
			if(Wlan[i].SSID.length > 26)
			{
				return Wlan[i].SSID.substring(0,26);
			}
			else
			{
				return Wlan[i].SSID;
			}
		}
	}
}

var wpakey2G;
var wpakey5G;
var wepkey2G;
var wepkey5G;
var guestrandomssid2G;
var guestrandomssid5G;

var DefaultKeyFlag = 0;

function GetDefaultKeyFlag()
{
	DefaultKeyFlag = '<%HW_WEB_GetKeyIsDefault();%>'; 
	if(1 == DefaultKeyFlag)
	{
		return true;
	}
	else
	{
		return false;
	}
}

function IfAutoGen()
{
	if((0 == GuestWifi[0].AutoGenFlag)
	&&((true == GetDefaultKeyFlag())&&('Vodafone-GuestWifi' == Wlan[getwlanloopbyath("ath1")].SSID)))
	{
		return true;
	}
	else
	{
		return false;
	}
}

var SetAutoGenFlag = 0;
function AutoGenSsidAndKey()
{
	if(1 == IfAutoGen())
	{
		SetAutoGenFlag = 1;
		guestrandomssid2G = GetPrivateSSID(0)+"-Guest";
		wpakey2G = '<%HW_WEB_GetRandomKey();%>';
		wepkey2G = '<%HW_WEB_GetRandomKey();%>';
		wepkey2G = wepkey2G.substring(wepkey2G.length-13);
		displayRandomSsidAndKey();
			
		if(1 == DoubleWlanFlag)
		{
			guestrandomssid5G = GetPrivateSSID(4)+"-Guest";
			wpakey5G = '<%HW_WEB_GetRandomKey();%>';
			wepkey5G = '<%HW_WEB_GetRandomKey();%>';
			wepkey5G = wepkey5G.substring(wepkey5G.length-13);
		}	
	}
}

function displayRandomSsidAndKey()
{
	setText('ssidname',guestrandomssid2G);
	setText('pwd_ssidpassword',wpakey2G);           
	setText('txt_ssidpassword',wpakey2G);
	setText('wlKeys1',wepkey2G);
	setText('twlKeys1',wepkey2G);
}

function LoadFrame()
{
	var loop = GetEnableGuestInst();
	IfSelectRadio = 0; 
	LoadGuestWifiInfo();
	LoadSelectRadio();
	NoSelectRadioGetWlanInst();
	InitGuestWifiInfo(loop);
	displayPasswordEnable();
	InitBroadEnable();
}
</script>
</head>
<body class="mainbody" onload="LoadFrame();">
<table width="100%" height="5" border="0" cellpadding="0" cellspacing="0"><tr> <td></td></tr></table>  
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("Guest WiFi", GetDescFormArrayById(cfg_wlanguestwifi_language, "amp_wlan_ptvdf_guestwifi_header"), GetDescFormArrayById(cfg_wlanguestwifi_language, "amp_wlan_ptvdf_guestwifi_tittle"), false);
</script>
<table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr ><td class="height5p"></td></tr>
</table>
<div id="GuestWifiDetail" >
	<tr width="100%" border="0" cellpadding="0" cellspacing="0" >
		<td>
			<input type="checkbox" name="EnableGuestWifi" id="EnableGuestWifi" onclick="EnableGuestWifi()"; value="OFF"/>
			<script> document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_enable']);</script>
		</td>
	</tr >	
	<table id="GuestWifiInfo" height="50" cellspacing="1" cellpadding="0" width="100%" border="0" class="tabal_noborder_bg">	
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script> document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_frequency']);</script></td>
			<td class="table_right width_per75">
				<select name="GuestwifiRadio" id="GuestwifiRadio" onchange="funGuestwifiRadioSelect(this.id);">
					<script>
						if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>' != '1')
						{
							document.write('<option value='+0+'>' +"2.4GHz"+'</option>');
						}
						else
						{
							document.write('<option value='+0+'>' +"2.4GHz"+'</option>');
							document.write('<option value='+1+'>' +"5GHz"+'</option>');
							document.write('<option value='+2+'>' +"2.4GHz/5GHz"+'</option>');
						}
					</script>
				</select>
			</td>
		</tr >
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script> document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_ssid']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="ssidname" id="ssidname" class="tb_input" maxlength="32"/>
				</label>
				<font class="color_red">*</font>
			</td>
		</tr >
		
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_auth']);</script></td>
			<td class="table_right width_per75">
				<select name="wlAuthMode" id="wlAuthMode" onchange="funProtectionmodeSelect();">
				<script>
					document.write('<option value='+'wpa-psk'+'>' +"WPA"+'</option>');
					document.write('<option value='+'wpa2-psk'+'>' +"WPA2"+'</option>');
					document.write('<option value='+'wpa/wpa2-psk'+'>' +"WPA+WPA2"+'</option>');
					document.write('<option value='+'shared'+'>' +"WEP"+'</option>');
					document.write('<option value='+'open'+'>' +"off"+'</option>');
				</script>
				</select>
			</td>
		</tr >
		
		<tr name="wepkeylength" id='wepkeylength'  class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_keylength']);</script></td>
			<td class="table_right width_per75">
				<select name="wlKeyBit" id="wlKeyBit">
				<script>
					document.write('<option value='+'128'+'>' +"128bits"+'</option>');
					document.write('<option value='+'64'+'>' +"64bits"+'</option>');
				</script>
				</select>
			</td>
		</tr >
		
		<tr name="wepkeyInfo" id='wepkeyInfo' class="tabal_01">	
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_password']);</script>
				<td class="table_right width_per75">
					<script language="JavaScript" type="text/javascript">
						if (g_keys[0] != null)
						{
							document.write("<input type='password' id='wlKeys1' name='wlKeys1' size='20' maxlength=26 onchange=\"wep1password=getValue('wlKeys1');getElById('twlKeys1').value=wep1password\" value='" + htmlencode(g_keys[4].value) + "'>")
							document.write("<input type='text' id='twlKeys1' name='twlKeys1' size='20' maxlength=26 style='display:none;'  onchange=\"wep1password=getValue('twlKeys1');getElById('wlKeys1').value=wep1password\" value='" + htmlencode(g_keys[4].value) + "'>");
						}
					</script><font class="color_red">*</font>
			    <input type='checkbox' id='hidewlKeys' name='hidewlKeys' value='on' onClick="ShowOrHideText('hidewlKeys', 'wlKeys1', 'twlKeys1');"/>
				<script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_displaypassword']);</script>
				</td>
			</td>
		</tr >

		<tr id='wpakeyInfo' class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_password']);</script></td>
			<td class="table_right width_per75">	
				<input class="textbox" type='password' id='pwd_ssidpassword' name='pwd_ssidpassword' onchange="wpapskpassword=getValue('pwd_ssidpassword');getElById('txt_ssidpassword').value=wpapskpassword;"/>
			    <input class="textbox" type='text' id='txt_ssidpassword' name='txt_ssidpassword' maxlength='64' style='display:none' onchange="wpapskpassword=getValue('txt_ssidpassword');getElById('pwd_ssidpassword').value=wpapskpassword;"/>
				<script></script><font class="color_red">*</font>
				<input type="checkbox" name="displaypassword" id="displaypassword" value='on' onClick="ShowOrHideText('displaypassword', 'pwd_ssidpassword', 'txt_ssidpassword');"/>
				<script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_displaypassword']);</script>
			</td>
		</tr >
		
		<tr>
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_broadcast']);</script></td>
			<td class="table_right width_per75">
			<div class="contentItem contentSwitchicon">
			<img height="20px;"  src="../../../images/checkon.jpg" id="swithicon" onClick='SetWifiBroadcastEnable();'/></div></td>
		</tr>
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_time']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="ActivationTimeLimit" id="ActivationTimeLimit" />
				</label><font class="color_red">*</font>
				 <script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_minutes']);</script>
			</td>

		</tr >
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_upspeed']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="wlUpRate" id="wlUpRate" />
				</label><font class="color_red">*</font>
				<script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_speedcontext']);</script>
			</td>

		</tr >
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_downspeed']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="wlDownRate" id="wlDownRate" />
				</label><font class="color_red">*</font>
				<script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_speedcontext']);</script>
			</td>
		</tr >
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script> document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_startip']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="StartIPaddress" id="StartIPaddress" />
				</label><font class="color_red">*</font>
			</td>
		</tr >
		<tr class="tabal_01">
			<td class="table_submit width_per25"><script>document.write(cfg_wlanguestwifi_language['amp_wlan_ptvdf_guestwifi_endip']);</script></td>
			<td class="table_right width_per75">
				<label>
					<input type="text" name="EndIPaddress" id="EndIPaddress" />
				</label><font class="color_red">*</font>
			</td>
		</tr >
	</table>
    <table width="100%" border="0" cellpadding="0" cellspacing="0"  >
      <tr><td>
        <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
          <tr>
            <td class="table_submit width_per25"></td>
            <td class="table_submit">
              <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
              <button id="btnApplySubmit" name="btnApplySubmit" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="btnApplySubmit();"><script>document.write(cfg_wlancfgother_language['amp_wlancfg_apply']);</script></button>
              <button id="cancel" name="cancel" type="button" class="CancleButtonCss buttonwidth_100px" onClick="cancelValue();"><script>document.write(cfg_wlancfgother_language['amp_wlancfg_cancel']);</script></button>
            </td>
          </tr>
        </table>
        </td> 
      </tr>
    </table>
</div>

</body>
</html>
