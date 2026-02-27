<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="X-UA-Compatible" content="IE=8,9,10">
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/wlan_list.asp"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<title>Wlan information</title>
<script language="JavaScript" type="text/javascript">

var curUserType='<%HW_WEB_GetUserType();%>';
var sysUserType='0';
var sptUserType ='1';
var curWebFrame='<%HW_WEB_GetWEBFramePath();%>';
var CfgMode = '<%HW_WEB_GetCfgMode();%>';

var CurrentBin = '<%HW_WEB_GetBinMode();%>';
var wlaninfo_channel_display = 0;

var TELMEX = false;
var TelMexFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_TELMEX);%>';

var isStaWorkingModeShow = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_PTVDF);%>';

var PCCW = false;
var PCCWFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_PCCW);%>';

var BjcuFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_BJCU);%>';

if (typeof top.changeWlanClick == 'undefined')
{
    top.changeWlanClick = 1;
}
var IspSSIDVisibility = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_ISPSSID_VISIBILITY);%>';
var ChanInfo = '<%HW_WEB_GetChanInfo();%>';
var Wlan11acFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_11AC);%>';

var channelArray = new Array(cfg_wlancfgadvance_language['amp_chlwidth_auto2040'],cfg_wlancfgadvance_language['amp_chlwidth_20'],cfg_wlancfgadvance_language['amp_chlwidth_40'],
							 cfg_wlancfgadvance_language['amp_chlwidth_auto204080'], cfg_wlancfgadvance_language['amp_chlwidth_160'], cfg_wlancfgadvance_language['amp_chlwidth_80and80']);

var channelWideArray = new Array('20 MHz','40 MHz','80 MHz','160 MHz');
							 
var standardArr = { '11a' : '802.11a', 
	                  '11b' : '802.11b', 
	                  '11g' : '802.11g', 
	                  '11n' : '802.11n', 
	                  '11bg' : '802.11b/g', 
					  '11gn' : '802.11g/n',
	                  '11bgn' : '802.11b/g/n', 
	                  '11na' : '802.11a/n', 
	                  '11ac' : '802.11a/n/ac',
					  '11aconly' : '802.11ac'
	                };							 
	
var staNumArray = [0,0,0,0,0,0,0,0];
					
var transmitPower = 0;
var transmitPower5g = 0;
var WlanChannel5g = -2;
var WlanChannel2g = ChanInfo.split(',')[0];
if (1 == DoubleFreqFlag)
{
    WlanChannel5g = ChanInfo.split(',')[1];
}
var staNum = 0;
var weakerSta = 0;
var staNum5g = 0;
var weakerSta5g = 0;

var nAPNum = 0;
var strongNAPNum = 0;
var nAPNum5g = 0;
var strongNAPNum5g = 0;


var TwoSsidCustomizeGroup = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GZCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JSCT);%>' 
                             | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_NXCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HUNCT);%>' 
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GSCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SZCT);%>' 
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_QHCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HLJCT);%>' 
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JXCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_XJCT);%>'
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JLCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HAINCT);%>'
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SCCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_YNCT);%>'
							 | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_CQCT);%>' | '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_TJCT);%>';
if (1 == TelMexFlag)
{
	TELMEX = true;
}
else
{
	TELMEX = false;
}

if (1 == PCCWFlag)
{
	PCCW = true;
}
else
{
	PCCW = false;
}

function getRadarMode()
{
  $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "./getradar.asp",
            success : function(data) {
               	WlanWorkMode = data;
            }
        });
}

if (!((curWebFrame == 'frame_CMCC') && (curUserType == sptUserType)))
{
	wlaninfo_channel_display = 1;
}

var SsidPerBand = '<%HW_WEB_GetSPEC(AMP_SPEC_SSID_NUM_MAX_BAND.UINT32);%>';
var possibleChannels = "";
function stWlan(domain,enable,name,ssid,BeaconType,BasicEncrypt,BasicAuth,WPAEncrypt,WPAAuth,IEEE11iEncrypt,IEEE11iAuth,WPAand11iEncrypt,WPAand11iAuth,Channel,LowerLayers, X_HW_Standard, RegulatoryDomain, X_HW_HT20, TransmitPower, X_HW_ServiceEnable, wlHide, wmmEnable, DeviceNum)
{
    this.domain = domain;
    this.enable = enable;
    this.name = name;
    this.ssid = ssid;
    this.BeaconType = BeaconType;    
    this.BasicAuth = BasicAuth;
	this.BasicEncrypt = BasicEncrypt;    
    this.WPAAuth = WPAAuth;
	this.WPAEncrypt = WPAEncrypt;    
    this.IEEE11iAuth = IEEE11iAuth;
	this.IEEE11iEncrypt = IEEE11iEncrypt;
	this.WPAand11iAuth = WPAand11iAuth;
	this.WPAand11iEncrypt = WPAand11iEncrypt;
	this.Channel = Channel;	
	this.LowerLayers = LowerLayers;
    this.X_HW_Standard = X_HW_Standard;
    this.RegulatoryDomain = RegulatoryDomain;
    this.X_HW_HT20 = X_HW_HT20;
    this.TransmitPower = TransmitPower;
	this.X_HW_ServiceEnable = X_HW_ServiceEnable;
	this.wlHide = wlHide;
	this.wmmEnable = wmmEnable;
	this.DeviceNum = DeviceNum;
}

function stWlanTb(wlanInst, ssid, wetherConfig, auth, encrypt)
{
	this.wlanInst = wlanInst;
	this.ssid = ssid;
	this.wetherConfig = wetherConfig;
	this.auth = auth;
	this.encrypt = encrypt;
}

function stPacketInfo(domain,totalBytesSent,totalPacketsSent,totalBytesReceived,totalPacketsReceived)
{
    this.domain = domain;
    this.totalBytesSent = totalBytesSent;
	this.totalPacketsSent = totalPacketsSent;
	this.totalBytesReceived = totalBytesReceived;
	this.totalPacketsReceived = totalPacketsReceived;
}

function stStats(domain,errorsSent,errorsReceived,discardPacketsSent,discardPacketsReceived)
{
    this.domain = domain;
    this.errorsSent = errorsSent;
    this.errorsReceived = errorsReceived;
    this.discardPacketsSent = discardPacketsSent;
    this.discardPacketsReceived = discardPacketsReceived;
}

function stRadio(domain,OperatingFrequencyBand,Enable)
{
    this.domain = domain;
    this.OperatingFrequencyBand = OperatingFrequencyBand;
    this.Enable = Enable;
}


function stIndexMapping(index,portIndex)
{
    this.index = index;
    this.portIndex = portIndex;
}

function stAssociatedDevice(domain,AssociatedDeviceMACAddress,X_HW_Uptime,X_HW_RxRate,X_HW_TxRate,X_HW_RSSI,X_HW_Noise,X_HW_SNR,X_HW_SingalQuality,X_HW_WorkingMode,X_HW_WMMStatus,X_HW_PSMode)
{
	this.domain = domain;
	this.AssociatedDeviceMACAddress = AssociatedDeviceMACAddress;
    this.X_HW_Uptime = X_HW_Uptime;
    this.X_HW_RxRate = X_HW_RxRate;
    this.X_HW_TxRate = X_HW_TxRate;
    this.X_HW_RSSI   = X_HW_RSSI;
    this.X_HW_Noise  = X_HW_Noise;
    this.X_HW_SNR    = X_HW_SNR;
    this.X_HW_SingalQuality  = X_HW_SingalQuality;
    this.X_HW_WorkingMode  = X_HW_WorkingMode;
    this.X_HW_WMMStatus  = X_HW_WMMStatus;
    this.X_HW_PSMode  = X_HW_PSMode;
    this.ssidname = 0;
}

function stNeighbourAP(domain,SSID,BSSID,NetworkType,Channel,RSSI,Noise,DtimPeriod,BeaconPeriod,Security,Standard,MaxBitRate)
{
	this.domain = domain;
	this.SSID = SSID;
    this.BSSID = BSSID;
    this.NetworkType = NetworkType;
    this.Channel = Channel;
    this.RSSI = RSSI;
    this.Noise = Noise;
    this.DtimPeriod = DtimPeriod;
    this.BeaconPeriod = BeaconPeriod;
    this.Security = Security;
    this.Standard = Standard;
    this.MaxBitRate = MaxBitRate;
}

var WlanInfo = new Array();
WlanInfo = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Enable|Name|SSID|BeaconType|BasicEncryptionModes|BasicAuthenticationMode|WPAEncryptionModes|WPAAuthenticationMode|IEEE11iEncryptionModes|IEEE11iAuthenticationMode|X_HW_WPAand11iEncryptionModes|X_HW_WPAand11iAuthenticationMode|Channel|LowerLayers|X_HW_Standard|RegulatoryDomain|X_HW_HT20|TransmitPower|X_HW_ServiceEnable|SSIDAdvertisementEnabled|WMMEnable|X_HW_AssociateNum,stWlan,STATUS);%>;  

var ChannelSet = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|Channel,Array);%>;  

var WlanChannel = '';

var PacketInfo = new Array();
PacketInfo = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},TotalBytesSent|TotalPacketsSent|TotalBytesReceived|TotalPacketsReceived,stPacketInfo,STATUS);%>; 

var Stats = new Array();
Stats = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.Stats,ErrorsSent|ErrorsReceived|DiscardPacketsSent|DiscardPacketsReceived,stStats,STATUS);%>;
	
var wlanEnbl = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.X_HW_WlanEnable);%>';

var AssociatedDevice = new stAssociatedDevice("0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0");

var NeighbourAP = new stNeighbourAP("0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0");

function getWlanPortNumber(name)
{
    var length = name.length;
    var number;
    var str = parseInt(name.charAt(length-1));
    return str;
}


var WlanMap = new Array();

for (var i = 0; i < WlanInfo.length-1; i++)
{
    var index = getWlanPortNumber(WlanInfo[i].name);
	WlanMap[i] = new stIndexMapping(i, index);
}

if (WlanMap.length >= 2)
{
    for (var i = 0; i < WlanMap.length-1; i++)
    {
        for( var j =0; j < WlanMap.length-i-1; j++)
        {
            if (WlanMap[j+1].portIndex < WlanMap[j].portIndex)
            {
                var middle = WlanMap[j+1];
                WlanMap[j+1] = WlanMap[j];
                WlanMap[j] = middle;
            }
        }
    }
}

var macStateObject;
var WlanInfo2G = new Array();
var WlanInfo5G = new Array();
var ssidStart2G = 0;
var ssidEnd2G = 3;
var ssidStart5G = 4;
var ssidEnd5G = 7;
for (var i = 0; i < WlanInfo.length - 1; i++ )
{
	var athindex = getWlanPortNumber(WlanInfo[i].name);
    if (( athindex >= ssidStart2G )&&( athindex <= ssidEnd2G ))	
	{
		WlanInfo2G.push(WlanInfo[i]);
	}
	else if (( athindex >= ssidStart5G )&&( athindex <= ssidEnd5G )) 
	{
		WlanInfo5G.push(WlanInfo[i]);
	}
}

var channelSet2G = 0 ;
var channelSet5G = 0 ;
for (var i = 0; i < ChannelSet.length - 1; i++ )
{
	var athindex = getWlanPortNumber(ChannelSet[i][1]);
    if (( athindex >= ssidStart2G )&&( athindex <= ssidEnd2G ))	
	{
		channelSet2G = ChannelSet[i][2];
		break;
	}
}

for (var i = 0; i < ChannelSet.length - 1; i++ )
{
	var athindex = getWlanPortNumber(ChannelSet[i][1]);
	if (( athindex >= ssidStart5G )&&( athindex <= ssidEnd5G )) 
	{
		channelSet5G = ChannelSet[i][2];
		break;
	}
}

if (true == TELMEX)
{
	var wifiMac = "--:--:--:--:--:--";
	function stDeviceMac(domain,LanMac,WLanMac)
	{
		this.domain = domain;
		this.LanMac = LanMac;
		this.WLanMac = WLanMac;		
	}	
	var deviceMacs = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, X_HW_LanMac|X_HW_WlanMac, stDeviceMac);%>; 
	wifiMac = deviceMacs[0].WLanMac;
	
	if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
    {
        wifiMac = '<%HW_WEB_GetWlanMac_5G();%>';
    }
}

var channelWideArr = new Array("Auto 20/40 MHz","20 MHz","40 MHz");

function getEncrypt(wlanInfo)
{
	var auth;
	var encrypt;
	
	if ((wlanInfo.BeaconType == 'Basic')|| (wlanInfo.BeaconType == 'None'))
    {
		auth = wlanInfo.BasicAuth;
        encrypt = wlanInfo.BasicEncrypt;
    }
    else if (wlanInfo.BeaconType == 'WPA')
    {
        auth = wlanInfo.WPAAuth;
        encrypt = wlanInfo.WPAEncrypt;
    }
    else if ( (wlanInfo.BeaconType == '11i') || (wlanInfo.BeaconType == 'WPA2') )
	{
        auth = wlanInfo.IEEE11iAuth;
        encrypt = wlanInfo.IEEE11iEncrypt;
    }
    else if ( (wlanInfo.BeaconType == 'WPAand11i') || (wlanInfo.BeaconType == 'WPA/WPA2'))
    {
        auth = wlanInfo.WPAand11iAuth;
        encrypt = wlanInfo.WPAand11iEncrypt;
    }
	
	if(encrypt == 'NONE' || encrypt == 'None')
    {  
        if (auth == 'Both')
        {
            encrypt = cfg_wlaninfo_detail_language['amp_encrypt_wep'];
        }
        else
        {
            encrypt = cfg_wlaninfo_detail_language['amp_encrypt_none'];
        }
    }
    else if(encrypt == 'WEPEncryption')
    {
        encrypt = cfg_wlaninfo_detail_language['amp_encrypt_wep'];
    }
    else if(encrypt == 'AESEncryption') 
    {
        encrypt = cfg_wlaninfo_detail_language['amp_encrypt_aes'];
    }
    else if(encrypt == 'TKIPEncryption')
    {
        encrypt = cfg_wlaninfo_detail_language['amp_encrypt_tkip'];
    }
    else if(encrypt == 'TKIPandAESEncryption')
    {
        encrypt = cfg_wlaninfo_detail_language['amp_encrypt_tkipaes'];
    }
	
	return encrypt;
}

function getIndexFromPort(index)
{
    for (var i = 0; i < WlanMap.length; i++)
    {
        if (index == WlanMap[i].portIndex)
        {
            return WlanMap[i].index;
        }
    }
}

function getPortFromIndex(index)
{
    for (var i = 0; i < WlanMap.length; i++)
    {
        if (index == WlanMap[i].index)
        {
            return WlanMap[i].portIndex;
        }
    }
} 

function onClickMethod()
{   
    if ((1 == getRadioVal("WlanMethod")))
    {   
        top.changeWlanClick = 1;
    }
    else if (2 == getRadioVal("WlanMethod"))
    {   
        top.changeWlanClick = 2;
    }
	else
    {
        top.changeWlanClick = 1;	
    }
	
	
	if ('none' != getElementById('WifiStatusShow').style.display)
	{
		writeInfo();
	}
	else 
	{
		window.location = "/html/amp/wlaninfo/wlaninfo.asp";
	}
}

function LoadFrame()
{ 		
	if ((curWebFrame == 'frame_CTCOM') && ('E8C' == CurrentBin.toUpperCase()))
	{
		setDisplay("DivSSIDStats",0);
	}
	
	if (1 == DoubleFreqFlag)
	{
		setDisplay("WlanDoubleChannel",1);
	}
	else
	{
		setDisplay("WlanDoubleChannel",0);
	}

	var all = document.getElementsByTagName("td");
	for (var i = 0; i <all.length ; i++) 
	{
		var b = all[i];
		if(b.getAttribute("BindText") == null)
		{
			continue;
		}

		b.innerHTML = status_wlaninfo_language[b.getAttribute("BindText")];
	}

    if (TELMEX == true)
	{
		setDisplay("divTelmexMacInfo",1);
	}
	else
	{
		setDisplay("divTelmexMacInfo",0);
	}

    if ((TELMEX == true) || (BjcuFlag == '1'))
	{
		setDisplay("DivStaInfo",0);
        setDisplay("DivNAPInfo",0);
	}
    else if (IsSonetSptUser())
    {
        setDisplay("DivStaInfo",1);
        setDisplay("DivNAPInfo",0);
    }
    else
    {
        setDisplay("DivStaInfo",1);
        setDisplay("DivNAPInfo",1);
    }

    if (curWebFrame == 'frame_UNICOM')
    {
    	var currentPageURLFlag = document.URL.split('?')[1];
    	if(currentPageURLFlag == 'statistics')
    	{    		
    		setDisplay("divWlanInfo", 0); 
			setDisplay("btn_health_check", 0);
    		setDisplay("divSSIDInfo", 0);      	
    	}
    }
	
	if (0 == isStaWorkingModeShow)
    {
		setDisplay("amp_stainfo_working_mode", 0);
		setDisplay("amp_stainfo_wmm_status", 0);
		setDisplay("amp_stainfo_ps_mode", 0);
    }


	fixIETableScroll("DivPacketStatistics_Table_Container", "wlan_pkts_statistic_table");
	
}

function expandMenu()
{
    if (curUserType == sysUserType)
    {
       var menuID = 'link_Admin_3';
    }
    else
    {
       var menuID = 'link_User_3';
    }
   
    window.parent.frames["menufrm"].clickMenuLink(menuID);
}
function setControl()
{
}

function WlanStatusRefresh(band)
{
    if(0 == WlanEnable[0].enable)
    {
        return false;
    }
    if(band == '2g')
    {
        return enbl2G;
    }
    else if(band == '5g')
    {
        return enbl5G;
    }
    return false;
}

function retPossibleChannels(band)
{
    var freq = '2G';

    var country;
    var mode;
    var width;
    var ssidindex = 0;
    
    if (1 == DoubleFreqFlag && band == '5G')
    {
        ssidindex = 4;
        freq = '5G';
    }
    for (var k = 0; k < WlanInfo.length - 1; k++)
    {
        var wlanInst = getWlanInstFromDomain(WlanInfo[k].domain);
        if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                        
        {
            continue;
        }	

        var athindex = getWlanPortNumber(WlanInfo[k].name);
        
        if (athindex == ssidindex)
        {
            country = WlanInfo[k].RegulatoryDomain;
            mode = WlanInfo[k].X_HW_Standard;
            width = WlanInfo[k].X_HW_HT20;
            
            if (athindex == 0)
            {
                transmitPower = WlanInfo[k].TransmitPower;                
            }
            else
            {
                transmitPower5g = WlanInfo[k].TransmitPower;
            }            
            break;
        }
       
    }
    
    getPossibleChannels(freq, country, mode, width);
    var ShowChannels = possibleChannels.split(',');
    for (var j=1; j<=ShowChannels.length; j++)
    {
        if(j==ShowChannels.length)
        {
            for(i = 0; i < ShowChannels[ShowChannels.length-1].length;i++)
            {
                if((ShowChannels[ShowChannels.length-1].charCodeAt(i)< 0x30)||(ShowChannels[ShowChannels.length-1].charCodeAt(i) > 0x39))
                {
                    index = i;
                    break;
                    
                }
            }
            ShowChannels[j-1] = ShowChannels[ShowChannels.length-1].substring(0,index);
        }
    }
    return ShowChannels;
}
    
function calQualityLevel(cRssi)
{
    var level = new Array(-94, -82, -78, -74, -66, -56, -46, -38, -34, -32, -21);
    
    /* 无干扰 */
    if (cRssi == 0)
    {
        return 0;
    }

    /* 最大干扰 */
    if (cRssi >= -21)
    {
        return 10;
    }

    for (var uiLoop = 0; uiLoop < level.length; uiLoop++)
    {
        if (cRssi < level[uiLoop])
        {
            return uiLoop;
        }
    }    
}

function FillChannelInfoItem(band)
{
    var channelarr;
    channelarr = retPossibleChannels(band);
    
    var InterferDegree = 0;
    var minInterfer = 0;
    var minInterferCh = 1;
    for (var i=0;i<channelarr.length;i++)
    {
        InterferDegree = 0;
        for (var j = 0; j < NeighbourAP.length - 1; j++)
        {
            if (NeighbourAP[j].Channel == channelarr[i])
            {
                InterferDegree += calQualityLevel(NeighbourAP[j].RSSI);
            }
            if (band == '2.4G')
            {
                var tch3 = parseInt(channelarr[i]) - 1;
                var tch4 = parseInt(channelarr[i]) + 1;
                if(NeighbourAP[j].Channel == tch3 || NeighbourAP[j].Channel == tch4)
                {
                    var rssi = (parseFloat(NeighbourAP[j].RSSI) + 95)*17/22-95;
                    InterferDegree += calQualityLevel(rssi);
                }
            }
        }
        if(InterferDegree == 0)
        {
            return channelarr[i];
        }
        if(minInterfer < InterferDegree)
        {
            minInterfer = InterferDegree;
            minInterferCh = channelarr[i];
        }
    }
    return minInterferCh;
}

function getStaInfo()
{
    if(0 == WlanEnable[0].enable)
    {
        return;
    }
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        url : "./getassociateddeviceinfo.asp",
        success : function(data) {
        AssociatedDevice = eval(data);	
        }
    }); 
    staNum = 0;
    weakerSta = 0;
    staNum5g = 0;
    weakerSta5g = 0;
    
    var ssidstart = 0;
    var ssidend   = SsidPerBand - 1; 
    var ssidend5g = 7;
    if (1 == DoubleFreqFlag)
    {
        ssidstart = 0;
        ssidend   = 3;
    }
	
	for (var i = 0; i < staNumArray.length - 1; i++)
	{
		staNumArray[i] = 0;
	}
	
    for (var i = 0; i < AssociatedDevice.length - 1; i++)
    {
        
        var ssid = getWlanInstFromDomain(AssociatedDevice[i].domain); 
        for (j = 0; j < WlanInfo.length - 1; j++)
        {
            var ret = WlanInfo[j].domain.indexOf("InternetGatewayDevice.LANDevice.1.WLANConfiguration."+ssid);
            if (ret == 0)
            {
                var wlanInst = getWlanInstFromDomain(WlanInfo[j].domain);
                if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                        
                {
                    continue;
                }
                var athindex = getWlanPortNumber(WlanInfo[j].name);
                if (( athindex >= ssidstart )&&( athindex <= ssidend ))
                {
                    if (AssociatedDevice[i].X_HW_RSSI < -75)
                    {
                        weakerSta ++;
                    }
                    staNum ++;
                }
                if (1 == DoubleFreqFlag && athindex > ssidend && athindex <= ssidend5g)
                {
                    if (AssociatedDevice[i].X_HW_RSSI < -75)
                    {
                        weakerSta5g ++;
                    }
                    staNum5g ++;
                }

				staNumArray[wlanInst-1] ++;
            }
        }
    }
    
}

function getAPInfo()
{
    if(0 == WlanEnable[0].enable)
    {
        return;
    }
    
    $.ajax({
        type : "post",
        async : false,
        cache : false,
        url : "./getneighbourAPinfo.asp",
        success : function(data) {            
        NeighbourAP = eval(data);
        }
    }); 
    
    nAPNum = 0;
    strongNAPNum = 0;
    nAPNum5g = 0;
    strongNAPNum5g = 0;
    var uich2g1 = parseInt(WlanChannel2g) - 1;
    var uich2g2 = parseInt(WlanChannel2g) + 1;
    var uich5g1 = parseInt(WlanChannel5g) - 1;
    var uich5g2 = parseInt(WlanChannel5g) + 1;
    for (var i = 0; i < NeighbourAP.length - 1; i++)
    {
        var trssi = parseFloat(NeighbourAP[i].RSSI);

        if (NeighbourAP[i].Channel <= uich2g2 && NeighbourAP[i].Channel >= uich2g1)
        {
            nAPNum ++;
            if (NeighbourAP[i].Channel != WlanChannel2g)
            {
                trssi = (trssi + 95) * 17/22 - 95;
            }
            if (trssi > -56)
            {
                strongNAPNum ++;
            }
        }   
        if (1 == DoubleFreqFlag && NeighbourAP[i].Channel <= uich5g2 && NeighbourAP[i].Channel >= uich5g1)
        {
            if (NeighbourAP[i].domain.indexOf(node5G) == 0)
            {
                nAPNum5g ++;
                if (NeighbourAP[i].RSSI > -56)
                {
                    strongNAPNum5g ++;
                }
            }
            
        }
    }
}

function writeAPInfo(band)
{
    var bestChannel =0;
	var dividTitle = "nAPInfoTitle";
    var divid = "nAPInfo";
    var dividsugg = "nAPInfoSugg";
	var dividstrTitle = "nStroAPInfoTitle";
    var dividstr = "nStroAPInfo";
    var dividstrsugg = "nStroAPInfoSugg";
    var workchannel = WlanChannel2g;
    var tnAPNum = nAPNum;
    var tstrongNAPNum = strongNAPNum;
	var normal = '';
    if (band == '5G')
    {
        workchannel = WlanChannel5g;
        tnAPNum = nAPNum5g;
        tstrongNAPNum = strongNAPNum5g;        
    }
	
	var td1 = getElementById(dividTitle);
	var htmlap = status_wlaninfo_language['amp_health_check_wlanchannelap'] + '&nbsp;&nbsp;';
	td1.innerHTML = '';
	td1.innerHTML = htmlap;
	
	var td2 = getElementById(divid);
	td2.innerHTML = '';
	td2.innerHTML = tnAPNum;
	
    bestChannel = FillChannelInfoItem(band);
    var td3 = getElementById(dividsugg);
    td3.innerHTML = '';
    if (tnAPNum >= 10)
    {        
        var htmlapsugg;
        if(bestChannel == workchannel)
        {
            htmlapsugg = status_wlaninfo_language['amp_health_check_apsugg2'];
        }
        else
        {
            htmlapsugg = status_wlaninfo_language['amp_health_check_apsugg'] + '&nbsp;' + bestChannel;
        }
        td3.innerHTML = htmlapsugg;
		td3.style.color = '#ff0000';
    }
    else
    {        
        td3.innerHTML = normal;
		td3.style.color = '#000000';
    }
    
	var td4 = getElementById(dividstrTitle);
	var htmlstrap = status_wlaninfo_language['amp_health_check_wlanchannelstrap'] + '&nbsp;';
	td4.innerHTML = '';
    td4.innerHTML = htmlstrap;
	
	var td5 = getElementById(dividstr);
	td5.innerHTML = '';
	td5.innerHTML = tstrongNAPNum;
	    
    var td6 = getElementById(dividstrsugg);
    td6.innerHTML = '';
    if (tstrongNAPNum >= 1)
    {        
        var htmlstrapsugg;
        if(bestChannel == workchannel)
        {
            htmlstrapsugg = status_wlaninfo_language['amp_health_check_apsugg2'];
        }
        else
        {
            htmlstrapsugg = status_wlaninfo_language['amp_health_check_apsugg'] + '&nbsp;' + bestChannel;
        }
        td6.innerHTML = htmlstrapsugg;
		td6.style.color = '#ff0000';
    }
    else
    {
        td6.innerHTML = normal;
		td6.style.color = '#000000';
    }
}

function writeStrAPInfo(band)
{
    var divid = "DivStrAPMAC";
    var workchannel = WlanChannel2g;
    
    if (band == '5G')
    {
        workchannel = WlanChannel5g;        
    }
    var tdapmac=document.getElementById(divid); 

	var ColumnNum = 2;
    var mac = '';
    var rssi;
	var SSIDInfoArr = new Array();
	var SSIDConfiglistInfo = new Array(new stTableTileInfo("amp_stainfo_macadd","align_right","mac",false),
				new stTableTileInfo("amp_stainfo_rssi","align_left","rssi",false),
                null);
                
    var tch1 = parseInt(workchannel) - 1;
    var tch2 = parseInt(workchannel) + 1;        
    for (var i = 0; i < NeighbourAP.length - 1; i++)
    {
        if ((1 == DoubleFreqFlag) && ('2.4G' == band))
        {
            if (NeighbourAP[i].domain.indexOf(node2G) != 0)
            {
                continue;                
            }
        }
        if ((1 == DoubleFreqFlag) && ('5G' == band))
        {
            if (NeighbourAP[i].domain.indexOf(node5G) != 0)
            {
                continue;
            }
        }
        var napch = NeighbourAP[i].Channel;
        if (napch > tch2 || napch < tch1)
        {
            continue;
        }
        
        var trssi = parseFloat(NeighbourAP[i].RSSI);
        if (NeighbourAP[i].Channel != workchannel)
        {
            trssi = (trssi + 95) * 17/22 - 95;
        }
        
        if (trssi <= -56)
        {
            continue;
        }
        
        mac = htmlencode(NeighbourAP[i].SSID) + '(' + NeighbourAP[i].BSSID + ')&nbsp;';
        rssi = status_wlaninfo_language['amp_napinfo_channel'] + '&nbsp;' + NeighbourAP[i].Channel + ',&nbsp;&nbsp;' + status_wlaninfo_language['amp_health_check_rssi'] + '&nbsp;&nbsp;' + NeighbourAP[i].RSSI + '&nbsp;dBm';
        SSIDInfoArr.push(new stWlanMacTb(mac, rssi));
    }
	if(SSIDInfoArr.length != 0)
		SSIDInfoArr.push(null);
	var tableAP = '';
	tableAP = HWShowTableListByType2("ap_table", ColumnNum, SSIDInfoArr, SSIDConfiglistInfo);
    tdapmac.innerHTML = '';
    tdapmac.innerHTML = tableAP;
}

function writeSTAInfo(band)
{
	var dividTitle = "staInfoTitle";
    var divid = "staInfo";
    var dividsugg = "staInfoSugg";
	var dividweakTitle = "weakStaInfoTitle";
    var dividweak = "weakStaInfo";
    var dividweaksugg = "weakStaInfoSugg";
    var workchannel = WlanChannel2g;
    var tstaNum = staNum;
    var tweakerSta = weakerSta;
    var ttransmit = transmitPower;
	var normal = '';
    if (band == '5G')
    {
        tstaNum = staNum5g;
        tweakerSta = weakerSta5g;
        ttransmit = transmitPower5g;
    }
	var td1 = getElementById(dividTitle);
	var htmlDividTitle = band + '&nbsp;' + status_wlaninfo_language['amp_health_check_sta'] + '&nbsp;&nbsp;';
	td1.innerHTML = '';
	td1.innerHTML = htmlDividTitle;
	
	var td2 = getElementById(divid);
	td2.innerHTML = '';
	td2.innerHTML = tstaNum + '&nbsp;&nbsp;';
    
    var td3 = getElementById(dividsugg);
    td3.innerHTML = '';
    if (tstaNum >= 10)
    {        
        var htmlstasugg = status_wlaninfo_language['amp_health_check_stasugg'] + '&nbsp;&nbsp;'                     
        
        td3.innerHTML = htmlstasugg;
		td3.style.color = '#ff0000';
    }
    else
    {
        td3.innerHTML = normal;
		td3.style.color = '#000000';
    }
	
    var td4 = getElementById(dividweakTitle);
	var htmlWeakStaTitle = band + '&nbsp;' + status_wlaninfo_language['amp_health_check_weaksta'] + '&nbsp;&nbsp;';
	td4.innerHTML = '';
	td4.innerHTML = htmlWeakStaTitle;
	
	var td5 = getElementById(dividweak);
	td5.innerHTML = '';
	td5.innerHTML = tweakerSta;
	
    var td6 = getElementById(dividweaksugg);
    td6.innerHTML = '';
    if (tweakerSta >= 1)
    {        
        var htmlweakstasugg;
        if (ttransmit == 100)
        {
            htmlweakstasugg = status_wlaninfo_language['amp_health_check_weakstasugg'];
        }
        else
        {
            htmlweakstasugg = status_wlaninfo_language['amp_health_check_weakstasugg2'];
        }
        
        td6.innerHTML = htmlweakstasugg;
		td6.style.color = '#ff0000';
    }
    else
    {
        td6.innerHTML = normal;
		td6.style.color = '#000000';
    }
}

function stWlanMacTb(mac, rssi)
{
	this.mac = mac;
	this.rssi = rssi;
}

function writeWeakSTAInfo(band)
{
    var divid = "DivWeakStaMAC";
    
    var tdmac=document.getElementById(divid); 

	var ColumnNum = 2;
    var mac = '';
    var rssi;
	var SSIDInfoArr = new Array();
	var SSIDConfiglistInfo = new Array(new stTableTileInfo("amp_stainfo_macadd","align_right","mac",false),
				new stTableTileInfo("amp_stainfo_rssi","align_left","rssi",false),
                null);
		
    var ssidstart = 0;
    var ssidend   = SsidPerBand - 1; 

    if ((1 == DoubleFreqFlag) && ('2.4G' == band))
    {
        ssidstart = 0;
        ssidend   = 3;
    }

    if ((1 == DoubleFreqFlag) && ('5G' == band))
    {
        ssidstart = 4;
        ssidend   = 7;				
    }
    for (var i = 0; i < AssociatedDevice.length - 1; i++)
    {
        if (AssociatedDevice[i].X_HW_RSSI >= -75 
			&& AssociatedDevice[i].X_HW_TxRate >= 10 
			&& AssociatedDevice[i].X_HW_RxRate >= 10)
        {
            continue;
        }        
        var ssid = getWlanInstFromDomain(AssociatedDevice[i].domain); 
        for (j = 0; j < WlanInfo.length - 1; j++)
        {
            var ret = WlanInfo[j].domain.indexOf("InternetGatewayDevice.LANDevice.1.WLANConfiguration."+ssid);
            if (ret == 0)
            {
                var wlanInst = getWlanInstFromDomain(WlanInfo[j].domain);
                if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                        
                {
                    continue;
                }
                var athindex = getWlanPortNumber(WlanInfo[j].name);
                if (( athindex >= ssidstart )&&( athindex <= ssidend ))
                {
                    mac = AssociatedDevice[i].AssociatedDeviceMACAddress + '&nbsp;&nbsp;&nbsp;';
                    rssi = status_wlaninfo_language['amp_health_check_rssi'] + '&nbsp;&nbsp;' + AssociatedDevice[i].X_HW_RSSI + '&nbsp;dBm';
                    SSIDInfoArr.push(new stWlanMacTb(mac, rssi));
                }
            }
        }
    }
	if(SSIDInfoArr.length != 0)
		SSIDInfoArr.push(null);
	var tableSTA = '';
	tableSTA = HWShowTableListByType2("wlan_table", ColumnNum, SSIDInfoArr, SSIDConfiglistInfo);
    tdmac.innerHTML = '';
    tdmac.innerHTML = tableSTA;
}

function getMacState()
{
	var ObjPath = "x=InternetGatewayDevice.X_HW_DEBUG.AMP.WifiGlobleParam&RequestFile=html/amp/wlaninfo/wlaninfo.asp";	
	var ParaList = 'MACCheck2G&MACCheck5G&x.X_HW_Token=' + getValue('onttoken');
	macStateObject = HwAjaxGetPara(ObjPath, ParaList);
}

function writeWlanInfo(band)
{
	var diganosisInfo = htmlencode('<%HW_WEB_GetWlanDiganosis();%>');
	var diganosisArray = diganosisInfo.split(',');
	var macStateInfoParse = $.parseJSON(macStateObject);
	var macState = macStateInfoParse.MACCheck2G;			
	
	var currentChannelWide = diganosisArray[0];
	var ceState = diganosisArray[1];
	var rssiState = diganosisArray[2];
	var falseCCA = diganosisArray[3];
	var ccaNoise = diganosisArray[4];
	var calibration = diganosisArray[5];
	var sugChannelMode = 0;
	var bandShow = '2g';
	var wlanHtmlInfo  = WlanInfo2G;
	var useChannel = WlanChannel2g;
	var wlanChannelSet = channelSet2G;
	if ('5G' == band)
	{
		bandShow = '5g';
		wlanHtmlInfo = WlanInfo5G;
		useChannel = WlanChannel5g;
		wlanChannelSet = channelSet5G;
		macState = macStateInfoParse.MACCheck5G;
		
		sugChannelMode = 3;
		currentChannelWide = diganosisArray[6];
		ceState = diganosisArray[7];
		rssiState = diganosisArray[8];
		falseCCA = diganosisArray[9];
		ccaNoise = diganosisArray[10];
		calibration = diganosisArray[11];
	}
	
	var td1 = getElementById('wlanStatusTitle');
	var td2 = getElementById('wlanStatus');
	var td3 = getElementById('wlanStatusSug');
	var td4 = getElementById('wlanCETitle');
	var td5 = getElementById('wlanCE');
	var td6 = getElementById('wlanCESug');
	var td7 = getElementById('workingModeTitle');
	var td8 = getElementById('workingMode');
	var td9 = getElementById('workingModeSug');
	var td10 = getElementById('wlanChannelTitle');
	var td11 = getElementById('wlanChannel');
	var td12 = getElementById('wlanChannelSug');
	var td13 = getElementById('channelWideModeTitle');
	var td14 = getElementById('channelWideMode');
	var td15 = getElementById('channelWideModeSug');
	var td16 = getElementById('channelWideTitle');
	var td17 = getElementById('channelWide');
	var td18 = getElementById('channelWideSug');
	var td19 = getElementById('macFilterTitle');
	var td20 = getElementById('macFilter');
	var td21 = getElementById('macFilterSug');
	var td22 = getElementById('macAddTitle');
	var td23 = getElementById('macAdd');
	var td24 = getElementById('macAddSug');
	var td25 = getElementById('rssiTitle');
	var td26 = getElementById('rssi');
	var td27 = getElementById('rssiSug');
	var td28 = getElementById('falseccaTitle');
	var td29 = getElementById('falsecca');
	var td30 = getElementById('falseccaSug');
	var td31 = getElementById('calibrationTitle');
	var td32 = getElementById('calibration');
	var td33 = getElementById('calibrationSug');

	var htmlwlanStatusTitle = band + '&nbsp;' + status_wlaninfo_language['amp_wlanlink_status'] + '&nbsp;&nbsp'; 
	var htmlwlanStatus = '';
	var htmlwlanSug = '';
	if (1 == WlanStatusRefresh(bandShow))
	{
		htmlwlanStatus += status_wlaninfo_language['amp_wlanlink_on'] + '&nbsp;&nbsp';
	}
	else 
	{
		htmlwlanStatus += status_wlaninfo_language['amp_wlanlink_off'] + '&nbsp;&nbsp';
		htmlwlanSug = status_wlaninfo_language['amp_health_check_wlanstatus2'] + '&nbsp;&nbsp';
		td3.style.color = '#ff0000';
	}
		
	td1.innerHTML = '';
	td1.innerHTML = htmlwlanStatusTitle;
	td2.innerHTML = '';
	td2.innerHTML = htmlwlanStatus;
	td3.innerHTML = '';
	td3.innerHTML = htmlwlanSug;
	
	var htmlCEStatusTitle = status_wlaninfo_language['amp_health_check_CE'] + '&nbsp;&nbsp';
	var htmlCEStatus = '';
	var htmlCESug = '';
	if (9 == ceState)
	{
		getElementById('global_Status_table2').style.display = 'none';
	}
	else 
	{
		if (1 == ceState)
		{
			htmlCEStatus += status_wlaninfo_language['amp_health_check_CE_safe'] + '&nbsp;&nbsp';
			htmlCESug = status_wlaninfo_language['amp_health_check_CE_status1'] + '&nbsp;&nbsp';
			td6.style.color = '#ff0000';
		}
		else 
		{
			htmlCEStatus += status_wlaninfo_language['amp_health_check_CE_unsafe'] + '&nbsp;&nbsp';
		}
	
		td4.innerHTML = '';
		td4.innerHTML = htmlCEStatusTitle;
		td5.innerHTML = '';
		td5.innerHTML = htmlCEStatus;
		td6.innerHTML = '';
		td6.innerHTML = htmlCESug;
	}
	
	var mode;
	if ( wlanHtmlInfo.length > 0 )
	{
		mode = wlanHtmlInfo[0].X_HW_Standard;
	}
	
	var htmlWorkingModeTitle = status_wlaninfo_language['amp_stainfo_working_mode'] + ":&nbsp;&nbsp";
	var htmlWorkingMode = standardArr[mode] + '&nbsp;&nbsp';
	var htmlWorkingModeSug = '';
	
	if ('11bgn' != mode && '2.4G' == band)
	{	
		htmlWorkingModeSug = status_wlaninfo_language['amp_stainfo_working_mode_sug1'] + '&nbsp;&nbsp';
		td9.style.color = '#ff0000';
	}
	else if ('11ac' != mode && '5G' == band && 1 == Wlan11acFlag)
	{
		htmlWorkingModeSug = status_wlaninfo_language['amp_stainfo_working_mode_sug2'] + '&nbsp;&nbsp';
		td9.style.color = '#ff0000';
	}
	else if ('11na' != mode && '5G' == band && 1 != Wlan11acFlag)
	{
		htmlWorkingModeSug = status_wlaninfo_language['amp_stainfo_working_mode_sug3'] + '&nbsp;&nbsp';
		td9.style.color = '#ff0000';
	}
	
	td7.innerHTML = '';
	td7.innerHTML = htmlWorkingModeTitle;
	td8.innerHTML = '';
	td8.innerHTML = htmlWorkingMode;
	td9.innerHTML = '';
	td9.innerHTML = htmlWorkingModeSug;
	
	var htmlChannelTitle = status_wlaninfo_language['amp_health_check_channel'] + '&nbsp;&nbsp';	
	var htmlChannel = '';
	var htmlChannelSug = '';
	if (useChannel == wlanChannelSet)
	{
		htmlChannel = useChannel + '&nbsp;&nbsp';
	}
	else if (0 == wlanChannelSet)
	{
		htmlChannel = useChannel + '(' + status_wlaninfo_language['amp_health_check_channel_auto'] + ')' + '&nbsp;&nbsp';
	}
	else 
	{
		htmlChannel = status_wlaninfo_language['amp_health_check_channel_wrong'] + '&nbsp;&nbsp';
		htmlChannelSug = status_wlaninfo_language['amp_health_check_channel_sug'] + '&nbsp;&nbsp';
		td12.style.color = '#ff0000';
	}
	
	td10.innerHTML = '';
	td10.innerHTML = htmlChannelTitle;
	td11.innerHTML = '';
	td11.innerHTML = htmlChannel;
	td12.innerHTML = '';
	td12.innerHTML = htmlChannelSug;
	
	var htmlWideModeTitle = status_wlaninfo_language['amp_health_check_channelwidemode'] + '&nbsp;&nbsp';
	var htmlWideMode = channelArray[wlanHtmlInfo[0].X_HW_HT20] + '&nbsp;&nbsp';
	var htmlWideModeSug = '';
	if (sugChannelMode != wlanHtmlInfo[0].X_HW_HT20)
	{
		td15.style.color = '#ff0000';
		htmlWideModeSug = status_wlaninfo_language['amp_health_check_channelwidemode_sug1'] + '&nbsp;&nbsp' + channelArray[wlanHtmlInfo[0].X_HW_HT20] + ',&nbsp;&nbsp';
		if ('5G' != band)
		{
			htmlWideModeSug += status_wlaninfo_language['amp_health_check_channelwidemode_sug2'] + '&nbsp;&nbsp';
		}
		else 
		{
			htmlWideModeSug += status_wlaninfo_language['amp_health_check_channelwidemode_sug3'] + '&nbsp;&nbsp';
		}
	}
	
	td13.innerHTML = '';
	td13.innerHTML = htmlWideModeTitle;
	td14.innerHTML = '';
	td14.innerHTML = htmlWideMode;
	td15.innerHTML = '';
	td15.innerHTML = htmlWideModeSug;
	
	var htmlChannelWideTitle = status_wlaninfo_language['amp_health_check_channelwide'] + '&nbsp;&nbsp';
	var htmlChannelWide = channelWideArray[currentChannelWide] + '&nbsp;&nbsp';
	var htmlChannelWideSug = '';
	
	if (0 != currentChannelWide)
	{
		td18.style.color = '#ff0000';
		htmlChannelWideSug = status_wlaninfo_language['amp_health_check_channelwide_sug'] + '&nbsp;&nbsp' + channelWideArray[currentChannelWide];
	}
	
	td16.innerHTML = '';
	td16.innerHTML = htmlChannelWideTitle;
	td17.innerHTML = '';
	td17.innerHTML = htmlChannelWide;
	td18.innerHTML = '';
	td18.innerHTML = htmlChannelWideSug;
	
	var enableFilter = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Security.WlanMacFilterRight);%>';
	var htmlMacFilterTitle = status_wlaninfo_language['amp_health_check_wlanmacfilterright'] + '&nbsp;&nbsp';
	var htmlMacFilter = '';
	var htmlMacFilterSug = '';
	if (1 == enableFilter)
	{
		htmlMacFilter = status_wlaninfo_language['amp_health_check_wlanmacfilterright_on'] + '&nbsp;&nbsp';
		htmlMacFilterSug = status_wlaninfo_language['amp_health_check_wlanmacfilterright_info'] + '&nbsp;&nbsp';
		td21.style.color = '#ff0000';
	}
	else 
	{
		htmlMacFilter = status_wlaninfo_language['amp_health_check_wlanmacfilterright_off'] + '&nbsp;&nbsp';
	}
	
	td19.innerHTML = '';
	td19.innerHTML = htmlMacFilterTitle;
	td20.innerHTML = '';
	td20.innerHTML = htmlMacFilter;
	td21.innerHTML = '';
	td21.innerHTML = htmlMacFilterSug;
	
	var htmlMacAddTitle = status_wlaninfo_language['amp_health_check_macadd'] + '&nbsp;&nbsp';
	var htmlMacAdd = '';
	var htmlMacAddSug = '';
	if (0 == macState)
	{
		htmlMacAdd = status_wlaninfo_language['amp_health_check_macadd_ok'] + '&nbsp;&nbsp';
	}
	else 
	{
		td24.style.color = '#ff0000';
		htmlMacAdd = status_wlaninfo_language['amp_health_check_macadd_error'] + '&nbsp;&nbsp';
		if (0 != macState & 2)
		{
			htmlMacAddSug += status_wlaninfo_language['amp_health_check_macadd_sug1'] + '&nbsp;&nbsp';
		}
		else if (0 != macState & 8)
		{
			htmlMacAddSug += status_wlaninfo_language['amp_health_check_macadd_sug2'] + '&nbsp;&nbsp';
		}
		else if (0 != macState & 16)
		{
			htmlMacAddSug += status_wlaninfo_language['amp_health_check_macadd_sug3'] + '&nbsp;&nbsp';
		}
	}
	
	td22.innerHTML = '';
	td22.innerHTML = htmlMacAddTitle;
	td23.innerHTML = '';
	td23.innerHTML = htmlMacAdd;
	td24.innerHTML = '';
	td24.innerHTML = htmlMacAddSug;
	
	var htmlRssiTitle = status_wlaninfo_language['amp_health_rssi_check'] + '&nbsp;&nbsp';
	var htmlRssi = '';
	var htmlRssiSug = '';
	if (0 == rssiState)
	{
		htmlRssi = status_wlaninfo_language['amp_health_check_rssi_pass'] + '&nbsp;&nbsp';
	}
	else 
	{
		htmlRssi = status_wlaninfo_language['amp_health_check_rssi_error'] + '&nbsp;&nbsp';
		htmlRssiSug = status_wlaninfo_language['amp_health_check_rssi_sug'] + '&nbsp;&nbsp';
		td27.style.color = '#ff0000';
	}
	
	td25.innerHTML = '';
	td25.innerHTML = htmlRssiTitle;
	td26.innerHTML = '';
	td26.innerHTML = htmlRssi;
	td27.innerHTML = '';
	td27.innerHTML = htmlRssiSug;
	
	var htmlFalseccaTitle = status_wlaninfo_language['amp_health_check_falsecca'] + '&nbsp;&nbsp';
	var htmlFalsecca = '';
	var htmlFalseccaSug = '';
	if (9 == falseCCA)
	{
		getElementById('global_Status_table10').style.display = 'none';
	}
	else 
	{
		if (0 == falseCCA)
		{		
			htmlFalsecca = ccaNoise + '&nbsp;&nbsp';
		}
		else 
		{
			htmlFalsecca = status_wlaninfo_language['amp_health_check_falsecca_error'] + '&nbsp;&nbsp';
			htmlFalseccaSug = status_wlaninfo_language['amp_health_check_falsecca_sug'] + '&nbsp;&nbsp';
			td30.style.color = '#ff0000';
		}
	
		td28.innerHTML = '';
		td28.innerHTML = htmlFalseccaTitle;
		td29.innerHTML = '';
		td29.innerHTML = htmlFalsecca;
		td30.innerHTML = '';
		td30.innerHTML = htmlFalseccaSug;
	}
	
	var htmlCalibrationTitle = status_wlaninfo_language['amp_health_check_calibration'] + '&nbsp;&nbsp';
	var htmlCalibration = '';
	var htmlCalibrationSug = '';
	if (9 == calibration)
	{
		getElementById('global_Status_table11').style.display = 'none';
	}
	else 
	{
		if (0 == calibration)
		{
			htmlCalibration = status_wlaninfo_language['amp_health_check_calibration_pass'] + '&nbsp;&nbsp';
		}
		else 
		{
			htmlCalibrationSug = status_wlaninfo_language['amp_health_check_calibration_sug'] + '&nbsp;&nbsp';
			td33.style.color = '#ff0000';
			if (1 == calibration)
			{
				htmlCalibration = status_wlaninfo_language['amp_health_check_calibration_error1'] + '&nbsp;&nbsp';
			}
			else if (2 == calibration)
			{
				htmlCalibration = status_wlaninfo_language['amp_health_check_calibration_error2'] + '&nbsp;&nbsp';
			}
		}
	
		td31.innerHTML = '';
		td31.innerHTML = htmlCalibrationTitle;
		td32.innerHTML = '';
		td32.innerHTML = htmlCalibration;
		td33.innerHTML = '';
		td33.innerHTML = htmlCalibrationSug;
	}
}

function writeSSIDInfo(band)
{
	var divSsid=document.getElementById('DIVSsid'); 	
	var wlanHtmlInfo;
	if ('2.4G' == band)
	{
		wlanHtmlInfo = WlanInfo2G;
	}
	else if('5G' == band)
	{
		wlanHtmlInfo = WlanInfo5G;
	}
	
	var headHtml1 = '<table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg"><tbody>';
	headHtml1 += '<tr><td class="table_title width_per30" style="color: #000000;" >';
	var headHtml2 = '<td class="table_title width_per20" style="color: #000000;">';
	var headHtml3 = '<td class="table_right" ';
	var styleNormalHtml = 'style="color: #000000;">';
	var styleRedHtml = 'style="color: #ff0000;">';
	var styleHtml = '';
	var footHtml1 = '<\/td>';
	var footHtml2 = '<\/td><\/tr><\/tbody><\/table>';	
	var ssidTitle = status_wlaninfo_language['amp_info_title'];
	var tableHtml = '';
	var ssidEnableInfo;
	var ssidEnableInfo2;
	var bcastInfo;
	var bcastInfo2;
	var wmmEnableInfo;
	var wmmEnableInfo2;
	var encrypt;
	var encryptInfo;
	var staNumInfo ;
	var staHtmlNum = 0;
	var wlanInst = 0;
	for (var i = 0; i < wlanHtmlInfo.length; i++)
	{
		wlanInst = getWlanInstFromDomain(wlanHtmlInfo[i].domain);
		tableHtml += '<table width="100%" border="0" cellpadding="0" cellspacing="0">';
		tableHtml += '<tbody><tr class="tabal_head" id="SSID' + wlanInst +'_Status">';
		tableHtml += '<td class="block_title">' + 'SSID' + wlanInst + ssidTitle + '<\/td>';
		tableHtml += '<\/tr><\/tbody><\/table>';
		
		tableHtml += headHtml1 + status_wlaninfo_language['amp_wlanstat_name'] + ':&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + wlanHtmlInfo[i].ssid + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml3 + styleNormalHtml + footHtml2;
		
		if (1 == wlanHtmlInfo[i].enable && 1 == wlanHtmlInfo[i].X_HW_ServiceEnable)
		{
			ssidEnableInfo = status_wlaninfo_language['amp_wlanlink_on'] + '&nbsp;&nbsp';
			ssidEnableInfo2 = '';
			styleHtml = styleNormalHtml;
		}
		else 
		{
			ssidEnableInfo = status_wlaninfo_language['amp_wlanlink_off'] + '&nbsp;&nbsp';
			ssidEnableInfo2 = status_wlaninfo_language['amp_health_check_wlanstatus2'];
			styleHtml = styleRedHtml;
		}
		tableHtml += headHtml1 + status_wlaninfo_language['amp_wlanstat_status'] + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + ssidEnableInfo + footHtml1;
		tableHtml += headHtml3 + styleHtml + ssidEnableInfo2 + footHtml2;
		
		if (1 == wlanHtmlInfo[i].wlHide)
		{
			bcastInfo = status_wlaninfo_language['amp_wlanlink_on'] + '&nbsp;&nbsp';
			bcastInfo2 = '';
			styleHtml = styleNormalHtml;
		}
		else 
		{
			bcastInfo = status_wlaninfo_language['amp_wlanlink_off'] + '&nbsp;&nbsp';
			bcastInfo2 = status_wlaninfo_language['amp_health_check_wlanstatus2'];
			styleHtml = styleRedHtml;
		}
		tableHtml += headHtml1 + status_wlaninfo_language['amp_wlanstat_ratio_status'] + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + bcastInfo + footHtml1;
		tableHtml += headHtml3 + styleHtml + bcastInfo2 + footHtml2;
		
		wmmEnableInfo2 = '';	
		if (1 == wlanHtmlInfo[i].wmmEnable)
		{
			wmmEnableInfo = status_wlaninfo_language['amp_stainfo_wmm_on'] + '&nbsp;&nbsp';
			wmmEnableInfo2 = '';
			styleHtml = styleNormalHtml;
		}
		else
		{
			wmmEnableInfo = status_wlaninfo_language['amp_stainfo_wmm_off'] + '&nbsp;&nbsp';
			wmmEnableInfo2 = status_wlaninfo_language['amp_health_check_wlanstatus2'];
			styleHtml = styleRedHtml;
		}
		
		tableHtml += headHtml1 + status_wlaninfo_language['amp_stainfo_wmm_status'] + ':&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + wmmEnableInfo + footHtml1;
		tableHtml += headHtml3 + styleHtml + wmmEnableInfo2 + footHtml2;
		
		encrypt = getEncrypt(wlanHtmlInfo[i]);	
		encryptInfo = '';
		styleHtml = styleNormalHtml;
		if (cfg_wlaninfo_detail_language['amp_encrypt_tkipaes'] != encrypt)
		{
			encryptInfo = status_wlaninfo_language['amp_ssidinfo_encry_status1'] ;
			styleHtml = styleRedHtml;
		}
		
		tableHtml += headHtml1 + status_wlaninfo_language['amp_ssidinfo_encry'] + ':&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + encrypt + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml3 + styleHtml + encryptInfo + footHtml2;
		
		staNumInfo = '';
		styleHtml = styleNormalHtml;
			
		staHtmlNum = staNumArray[wlanInst-1];
		if (staHtmlNum > 10)
		{
			staNumInfo = status_wlaninfo_language['amp_health_check_sta_status1'];
			styleHtml = styleRedHtml;
		}
		else if (wlanHtmlInfo[i].DeviceNum - staHtmlNum < 3)
		{
			staNumInfo = status_wlaninfo_language['amp_health_check_sta_status2'];
			styleHtml = styleRedHtml;
		}
		
		tableHtml += headHtml1 + status_wlaninfo_language['amp_health_check_sta_max'] + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + wlanHtmlInfo[i].DeviceNum + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml3 + 'rowspan = 2' + styleHtml + staNumInfo + '<\/td><\/tr>' ;
		tableHtml +=  '<tr>' + headHtml2 + status_wlaninfo_language['amp_health_check_sta'] + '&nbsp;&nbsp' + footHtml1;
		tableHtml += headHtml2 + staHtmlNum + '&nbsp;&nbsp' + footHtml1;
		tableHtml += footHtml2;
	}
	
	divSsid.innerHTML = '';
	divSsid.innerHTML = tableHtml;
}

function DisplayResult()
{
    setDisplay("WifiStatusShow", 1);
    
    setDisable("btn_health_check", 0);
}

function writeInfo()
{
	var band = '2.4G';
	if(2 == top.changeWlanClick)
	{
		band = '5G';
	}
	
	writeAPInfo(band);
	writeStrAPInfo(band);
	writeSTAInfo(band);
	writeWeakSTAInfo(band);
	writeWlanInfo(band);
	writeSSIDInfo(band);
	
	getElementById('WifiStatusShow').style.width = getElementById('wlanlink_status_table').offsetWidth + 'px' ;
	var h1 = $("#WifiStatusShow").height();
    var h2 = $("#amp_wlaninfo_desc").height(); 
	
    $("body").height(h2+h1+100);   
}

function onHealthCheck()
{
    setDisable("btn_health_check", 1);
    getAPInfo(); 
	getStaInfo();
    getMacState();
	writeInfo();
	
    setTimeout("DisplayResult()", 10);
}

function FillTableDataWithByForm2(TableName, ColumnTitleDesArray, TableDataInfo)
{
    var retHtml = '';
	var LIneDate;
    
	for( var Data_j = 0; Data_j < TableDataInfo.length - 1; Data_j++)
	{
		var LIneDate = TableDataInfo[Data_j];
		if( Data_j%2 == 0 )
		{
			var LineHtml = '<TR id="' + TableName + '_record_' + Data_j + '" class="tabal_01" onclick="selectLine(this.id);">';
		}
		else
		{
			var LineHtml = '<TR id="' + TableName + '_record_' + Data_j + '" class="tabal_02" onclick="selectLine(this.id);">';
		}

		for(var Title_j = 0; Title_j < ColumnTitleDesArray.length - 1; Title_j++)
		{
			var TitleAttrName = ColumnTitleDesArray[Title_j].ShowAttrName;
			var ShowFlag = ColumnTitleDesArray[Title_j].IsNotShowFlag;
			var TdMaxNum = ColumnTitleDesArray[Title_j].MaxNum;
			var Td_i_Class = (null == ColumnTitleDesArray[Title_j].TableClass ? "" : ColumnTitleDesArray[Title_j].TableClass);

			if(true == ShowFlag || "summary" == ShowFlag)
			{
				continue;
			}

			if("DomainBox" == TitleAttrName)
			{
				var onclickstr = GetCheckboxFuncString(TableName);
				LineHtml += '<TD class="' + Td_i_Class + '" ><input id = "' + TableName + '_rml'+ Data_j + '" type="checkbox" name="' + TableName + 'rml"'  + onclickstr + ' value="' + TableDataInfo[Data_j].domain + '"></TD>';
				continue;
			}

			var TdId = ' id="' + TableName + "_" + Data_j + "_" + Title_j + '" ';
			if("NumIndexBox" == TitleAttrName)
			{
				LineHtml += '<td class="' + Td_i_Class + '" ' + TdId + '>' + (Data_j+1) + '</td>';
				continue;
			}

			var ShowAttrValue = LIneDate[TitleAttrName];
			if (ShowAttrValue != null)
			{
				var InnerHtml = (TdMaxNum == "undefined") ? ShowAttrValue : GetStringContent(ShowAttrValue, TdMaxNum);
				if (ShowAttrValue === InnerHtml)
				{
					LineHtml += '<TD class="' + Td_i_Class + '" ' + TdId +'>' + InnerHtml + '</TD>';
				}
				else
				{
					LineHtml += '<TD class="' + Td_i_Class + '" title="' + ShowAttrValue + '"' + TdId +'>' + InnerHtml + '</TD>';
				}
			}
		}
		LineHtml+='</tr>';
        retHtml += LineHtml;
	}
    
    return retHtml;
}


function HWShowTableListByType2( TableName, ColumnNum, TableDataInfo, ColumnTitleDesArray)
{
	var tabwidth = "100%";
    var tabTitle = TableName + "_head";
    var tabId = TableName + "_tbl";
	var htmlhead = "<table";

	if (tabId != null)
	{
		htmlhead += " id=\"" + tabId + "\"";
	}

	htmlhead += " width=\"" + tabwidth + "\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">"
			+ "<tr class=\"alignment_rule\">"
			+ "<td>";

	htmlhead += "<\/td>"
			+ "<\/tr>"
			+ "<tr>"
			+ "<td id=\"" + tabTitle + "\">";

	var LineRowDataNum = TableDataInfo.length - 1;
    var LineHtml;
	if (LineRowDataNum != 0)
	{
		LineHtml = FillTableDataWithByForm2(TableName, ColumnTitleDesArray, TableDataInfo);	
	}

    htmlhead += LineHtml + '</table>' + '<\/td><\/tr><\/table>'
    
    return htmlhead;
}
</script>

</head>
<body class="mainbody" onLoad="LoadFrame();">

<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("amp_wlaninfo_desc", 
	GetDescFormArrayById(status_wlaninfo_language, "amp_wlaninfo_desc_head"), 
	GetDescFormArrayById(status_wlaninfo_language, "amp_wlaninfo_desc"), false);
</script>

<div class="title_spread"></div>

<div style="overflow:auto;overflow-y:hidden">
    <input id="btn_health_check" name="btn_health_check" type="button" value="" class="ApplyButtoncss buttonwidth_120px_220px" onclick="onHealthCheck();"/>
    <script>
        document.getElementById('btn_health_check').value = status_wlaninfo_language['amp_health_check'];
    </script>
</div>

<div class="title_spread"></div>
<div id="WlanDoubleChannel" style="display:none;">
<table id="DoubleChannel" width="100%" cellspacing="1" class="tabal_noborder_bg" style="font-size:14px;">
    <tr>       	
    <td height = "30px"> <input name="WlanMethod" id="WlanMethod" type="radio" value="1" checked="checked" onclick="onClickMethod()"/>
    <script>document.write(cfg_wlaninfo_db_language['amp_wlan_display2g_info']);</script></td>
    <td height = "30px"> <input name="WlanMethod" id="WlanMethod" type="radio"  value="2"  onclick="onClickMethod()" />
    <script>document.write(cfg_wlaninfo_db_language['amp_wlan_display5g_info']); </script></td> 
    <script>
        var Method = top.changeMethod;
        if (1 ==top.changeWlanClick)
        {   
            setRadio("WlanMethod",1);
        }
        else if (2 == top.changeWlanClick)
        {
            setRadio("WlanMethod",2);
        }
        else
        {    
            setRadio("WlanMethod",1);
        }
    </script>
    </tr> 
</table>
</div>

<div class="func_spread"></div>

<!-- begin 一键信息诊断 -->
<div id="WifiStatusShow" style='display:none;
	position:absolute;
    z-index:100;
	text-align:left;    
	padding:0px;
    background:#ffffff;'>
    
    <div class="WifiConfigUI-title" style= 'margin-left:0px;	
	height:60px;
	line-height:60px;
	vertical-align:middle;
	color:#0;
	background-color:#FDF5E6;'><SCRIPT>document.write(status_wlaninfo_language["amp_health_check_title"]);</SCRIPT></div>
    
	<table width="100%" border="0" cellpadding="0" cellspacing="1" id="wifiStatus_table">
		 <tbody>
			<tr>
				 <table width="100%" border="0" cellpadding="0" cellspacing="0">
					<tbody>
						<tr class="tabal_head" id="global_Status">
							<td class="block_title"><script>document.write(status_wlaninfo_language['amp_wlaninfo_desc_head']);</script></td>
						</tr>
					</tbody>
				</table>
			
				<table id="global_Status_table1" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							
							<td id="wlanStatusTitle"  class="table_title width_per30" style="color: #000000;" ></td>
							<td id="wlanStatus"  class="table_title width_per20" style="color: #000000;" ></td>
							<td id="wlanStatusSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table2" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="wlanCETitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="wlanCE" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="wlanCESug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table3" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="workingModeTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="workingMode" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="workingModeSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>					
			
				<table id="global_Status_table4" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="wlanChannelTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="wlanChannel" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="wlanChannelSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table5" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="channelWideModeTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="channelWideMode" class="table_title width_per20" style="color: #000000;" ></td>
							<td  id="channelWideModeSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table6" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="channelWideTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="channelWide" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="channelWideSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table7" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="macFilterTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="macFilter" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="macFilterSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table8" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="macAddTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="macAdd" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="macAddSug"  class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table9" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="rssiTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="rssi" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="rssiSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table10" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="falseccaTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="falsecca" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="falseccaSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
				<table id="global_Status_table11" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					<tbody>
						<tr>
							<td id="calibrationTitle" class="table_title width_per30" style="color: #000000;" ></td>
							<td id="calibration" class="table_title width_per20" style="color: #000000;" ></td>
							<td id="calibrationSug" class="table_right" style="color: #000000;"></td>
						</tr>
					</tbody>
				</table>
				
			</tr>
			
			<tr>
				<div id = 'DIVSsid'></div>
			</tr>
			
			<tr>
				<table width="100%" border="0" cellpadding="0" cellspacing="0">
					<tbody>
						<tr class="tabal_head" id="sta_Status">
							<td class="block_title"><script>document.write(status_wlaninfo_language['amp_stainfo_title']);</script></td>
						</tr>
					</tbody>
				</table>
				
				<table id="wlanlink_status_table3" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
					</tr>
						<td id='staInfoTitle' class="table_title width_per30" style="color: #000000; vertical-align: top;" ></td>
						<td id='staInfo' class="table_title width_per20" style="color: #000000; vertical-align: top;" ></td>
						<td id='staInfoSugg' class="table_right" style="color: #000000; vertical-align: top;"></td>
					</tr>
					<tr>
						<td id='weakStaInfoTitle' class="table_title width_per30" style="color: #000000; vertical-align: top;" ></td>
						<td id='weakStaInfo' class="table_title width_per20" style="color: #000000; vertical-align: top;" ></td>
						<td id='weakStaInfoSugg' class="table_right" style="color: #000000; vertical-align: top;"></td>
					</tr>
				</table>
				
				 <div id='DivWeakStaMAC' ></div> 
			</tr>
    
			<tr>
				<table width="100%" border="0" cellpadding="0" cellspacing="0">
					<tbody>
						<tr class="tabal_head" id="disturb_Status">
							<td class="block_title"><script>document.write(status_wlaninfo_language['amp_napinfo_title']);</script></td>
						</tr>
					</tbody>
				</table>
				<table id="wlanlink_status_table5" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">  
					<tr>
						<td id='nAPInfoTitle' class="table_title width_per30" style="color: #000000; vertical-align: top;" ></td>
						<td id='nAPInfo' class="table_title width_per20" style="color: #000000; vertical-align: top;" ></td>
						<td id='nAPInfoSugg' class="table_right" style="color: #000000; vertical-align: top;"> </td>
					</tr>
					<tr>
						<td id='nStroAPInfoTitle' class="table_title width_per30" style="color: #000000; vertical-align: top;" ></td>
						<td id='nStroAPInfo' class="table_title width_per20" style="color: #000000; vertical-align: top;" ></td>
						<td id='nStroAPInfoSugg' class="table_right" style="color: #000000; vertical-align: top;"> </td>
					</tr>
				</table>
				
				<div id='DivStrAPMAC' ></div> 
			</tr>
		</tbody>
	</table>
    
    <table >
        <tr>            
            <td id='null4' class="table_right" style="color: #000000;"></td>
        </tr>
    </table>
</div>
  
<!-- end 一键信息诊断 -->

<!-- begin Telmex 定制 -->
<div id="divTelmexMacInfo" style="display:none;"> 

<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_wifimacinfo_title"]);</SCRIPT></div>

<table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
<tr> 
	<td class="table_title width_per35" style="color: #000000;" BindText='amp_wifimac'></td>
	<td class="table_right" style="color: #000000;">
		<script language="JavaScript" type="text/javascript">
		if (true == TELMEX)
		{
			document.write(wifiMac);
		}
		</script>
	</td> 
</tr> 
</table>

<div class="func_spread"></div>

</div>
<!-- end Telmex 定制 -->

<div id="divWlanInfo">

<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_wlaninfo_title"]);</SCRIPT></div>

<table id="wlanlink_status_table" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
    <tr>
        <td class="table_title width_per35" style="color: #000000;" BindText='amp_wlanlink_status'></td>
        <td class="table_right" style="color: #000000;"> 
	        <script language="JavaScript" type="text/javascript">
			   if ((1 == getRadioVal("WlanMethod")))
               {   
                   top.changeWlanClick = 1;
                }
                else if (2 == getRadioVal("WlanMethod"))
                {   
                   top.changeWlanClick = 2;
                }
	            else
                {
                   top.changeWlanClick = 1;	
                }	
				
				WlanInfoRefresh();

	            if (wlanEnbl == 1)
				{
					document.write(status_wlaninfo_language['amp_wlanlink_on'] + '&nbsp;&nbsp;')
				}
				else
				{
					document.write(status_wlaninfo_language['amp_wlanlink_off'] + '&nbsp;&nbsp;')
				}
	        </script>
	    </td>
    </tr>

    <script language="JavaScript" type="text/javascript">
    if(true == TELMEX)
    {	      
       
        $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "./getassociateddeviceinfo.asp",
            success : function(data) {
            AssociatedDevice = eval(data);	
            }
        });

    }

	if (wlaninfo_channel_display == 1)
	{
        document.write('<tr>');
        document.write('<td class="table_title width_per35" style="color: #000000;">' + status_wlaninfo_language['amp_wlaninfo_channel'] + '</td>');
        document.write('<td class="table_right" style="color: #000000;">');
		document.write(WlanChannel);
	    document.write('</td>');
        document.write('</tr>');	
	}
	</script>
</table>

<div class="func_spread"></div>

</div>

<div id="DivSSIDStats" >

<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_wlanstat_title"]);</SCRIPT></div>

<div id="DivPacketStatistics_Table_Container" style="overflow:auto;overflow-y:hidden">

<table id="wlan_pkts_statistic_table" width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_bg">
  <tr class="head_title"> 
    <td class="width_per10" rowspan="2" BindText='amp_wlanstat_id'></td>
    <td class="width_per25" rowspan="2" BindText='amp_wlanstat_name'></td>
    <td colspan="4" BindText='amp_wlanstat_rx'></td>
    <td colspan="4" BindText='amp_wlanstat_tx'></td>
  </tr>
  <tr class="head_title"> 
    <td BindText='amp_wlanstat_bytes'></td>
    <td BindText='amp_wlanstat_pkts'></td>
    <td BindText='amp_wlanstat_err'></td>
    <td BindText='amp_wlanstat_drop'></td>
    <td BindText='amp_wlanstat_bytes'></td>
    <td BindText='amp_wlanstat_pkts'></td>
    <td BindText='amp_wlanstat_err'></td>
    <td BindText='amp_wlanstat_drop'></td>
  </tr>
    <script language="JavaScript" type="text/javascript">
    if (wlanEnbl != '')
    {
        if ((wlanEnbl == 1) && (WlanMap.length != 0))
        {
            for (i = 0; i < WlanMap.length; i++)
            {			
                var index = getIndexFromPort(WlanMap[i].portIndex);
                var wlanInst = getWlanInstFromDomain(WlanInfo[index].domain);

                if ((1 == DoubleFreqFlag) && (1 == top.changeWlanClick))
                {
                    if (WlanMap[i].portIndex > 3)
                    {
                        continue;
                    }					
                }
					
                if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
                {
                    if (WlanMap[i].portIndex < 4)
                    {
                        continue;
                    }					
                }
					
                if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                
                {
                    continue;
                }
					
                if ((PacketInfo[index] != null) && (Stats[index] != null))
                {   
                    if (i%2 == 0)
                    {
                        document.writeln("<tr class='tabal_01'>");
                    }
                    else
                    {
                        document.writeln("<tr class='tabal_02'>");
                    }
					
                    document.writeln("<td class='align_center'>" + wlanInst + "</td>");
                    document.writeln("<td class='align_center'>" + htmlencode(WlanInfo[index].ssid) + "</td>");
                    document.writeln("<td class='align_center'>" + PacketInfo[index].totalBytesReceived + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + PacketInfo[index].totalPacketsReceived + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + Stats[index].errorsReceived + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + Stats[index].discardPacketsReceived + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + PacketInfo[index].totalBytesSent + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + PacketInfo[index].totalPacketsSent + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + Stats[index].errorsSent + "&nbsp;</td>");
                    document.writeln("<td class='align_center'>" + Stats[index].discardPacketsSent  + "&nbsp;</td>");
                    document.writeln("</tr>");
                }
            }
        }
    }

    </script>
</table>

</div>

<div class="func_spread"></div>

</div>

<div id="divSSIDInfo">

<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_ssidinfo_title"]);</SCRIPT></div>

<div id="DivSSIDInfo_Table_Container" style="overflow:auto;overflow-y:hidden">

<script language="javascript">

	var ShowTableFlag = 1;
	var ShowButtonFlag = 0;
	var ColumnNum = 5;
	var SSIDInfoArr = new Array();
	var SSIDConfiglistInfo = new Array(new stTableTileInfo("amp_wlanstat_id","align_center","wlanInst",false),
				new stTableTileInfo("amp_wlanstat_name","align_center","ssid",false),
				new stTableTileInfo("amp_ssidinfo_secu","align_center","wetherConfig",false),
				new stTableTileInfo("amp_ssidinfo_auth","align_center","auth",false),
				new stTableTileInfo("amp_ssidinfo_encry","align_center","encrypt",false),null);
		
    if (wlanEnbl != '')
    {	
        if ((wlanEnbl == 1) && (WlanMap.length != 0))
        {
            var wlanlen = WlanMap.length;
		
            if (curWebFrame == 'frame_CTCOM')
			{
				if (1 == TwoSsidCustomizeGroup)
				{
					if (wlanlen >= 2)
					{
						wlanlen = 2;
					}
				}
				else
				{
				    if (wlanlen >= 1)
					{
						wlanlen = 1;
					}
				}
				if(1 == DoubleFreqFlag) 
				{
					wlanlen = wlanlen + 1;
				}
			}

            for (i = 0; i < wlanlen; i++)
            {
                var index = getIndexFromPort(WlanMap[i].portIndex);
                var wlanInst = getWlanInstFromDomain(WlanInfo[index].domain);
				
				if ('' == WlanInfo[i].name)
				{
					continue;
				}

                if ((1 == DoubleFreqFlag) && (1 == top.changeWlanClick))
                {
                    if (WlanMap[i].portIndex > 3)
                    {
                        continue;
                    }					
                }
					
                if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
                {
                    if (WlanMap[i].portIndex < 4)
                    {
                        continue;
                    }					
                }
				
                if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                
                {
					continue;
                }
					
                if ((WlanInfo[index].BeaconType == 'Basic')|| (WlanInfo[index].BeaconType == 'None'))
                {
                    Auth = WlanInfo[index].BasicAuth;
                    Encrypt = WlanInfo[index].BasicEncrypt;
                }
                else if (WlanInfo[index].BeaconType == 'WPA')
                {
                    Auth = WlanInfo[index].WPAAuth;
                    Encrypt = WlanInfo[index].WPAEncrypt;
                }
                else if ( (WlanInfo[index].BeaconType == '11i') || (WlanInfo[index].BeaconType == 'WPA2') )
                {
                    Auth = WlanInfo[index].IEEE11iAuth;
                    Encrypt = WlanInfo[index].IEEE11iEncrypt;
                }
                else if ( (WlanInfo[index].BeaconType == 'WPAand11i') || (WlanInfo[index].BeaconType == 'WPA/WPA2'))
                {
                    Auth = WlanInfo[index].WPAand11iAuth;
                    Encrypt = WlanInfo[index].WPAand11iEncrypt;
                }
                else
                {
                }
                   				
                if (Auth == 'None')
                {
                    Auth = cfg_wlaninfo_detail_language['amp_auth_open'];
                }
                else if (Auth == 'SharedAuthentication')
                {
                    Auth = cfg_wlaninfo_detail_language['amp_auth_shared'];
                }
                else if(Auth == 'PSKAuthentication')
                {
                    if (WlanInfo[index].BeaconType == 'WPA')
                    {
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpapsk'];
                    }
                    else if( (WlanInfo[index].BeaconType == '11i') || (WlanInfo[index].BeaconType == 'WPA2') )
                    {
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpa2psk'];
                    }
                    else if( (WlanInfo[index].BeaconType == 'WPAand11i') || (WlanInfo[index].BeaconType == 'WPA/WPA2') )
                    {
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpawpa2psk'];
                    }
                    else
                    {
                    }
                }
                else if(Auth == 'EAPAuthentication')
                {   
                    if(WlanInfo[index].BeaconType == 'WPA')
                    {  
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpa'];
                    }
                    else if( (WlanInfo[index].BeaconType == '11i') || (WlanInfo[index].BeaconType == 'WPA2') )
                    { 
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpa2'];
                    }
                    else if( (WlanInfo[index].BeaconType == 'WPAand11i') || (WlanInfo[index].BeaconType == 'WPA/WPA2') )
                    { 
                        Auth = cfg_wlaninfo_detail_language['amp_auth_wpawpa2'];
                    }
                }
				
                if(Encrypt == 'NONE' || Encrypt == 'None')
                {  
                    if (Auth == 'Both')
                    {
                        Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_wep'];
                    }
                    else
                    {
                        Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_none'];
                    }
                }
                else if(Encrypt == 'WEPEncryption')
                {
                    Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_wep'];
                }
                else if(Encrypt == 'AESEncryption') 
                {
                    Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_aes'];
                }
                else if(Encrypt == 'TKIPEncryption')
                {
                    Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_tkip'];
                }
                else if(Encrypt == 'TKIPandAESEncryption')
                {
                    Encrypt = cfg_wlaninfo_detail_language['amp_encrypt_tkipaes'];
                }

				if ((Auth == cfg_wlaninfo_detail_language['amp_auth_open'] || Auth =="OpenSystem") && 
						Encrypt == cfg_wlaninfo_detail_language['amp_encrypt_none'])
                {
                    wetherConfig = status_wlaninfo_language['amp_authencry_off'];
                }
                else
                {
                    wetherConfig = status_wlaninfo_language['amp_authencry_on'];
                }  

                if (1 == DTHungaryFlag)
                {
                    if (Auth == cfg_wlaninfo_detail_language['amp_auth_open'])
                    {
                        Auth = 'WEP open';
                    }
                    else if (Auth == cfg_wlaninfo_detail_language['amp_auth_shared'])
                    {
                        Auth = 'WEP shared';
                    }
                }

				SSIDInfoArr.push(new stWlanTb(wlanInst, WlanInfo[index].ssid, wetherConfig, Auth, Encrypt));
            }
        }
		
    }
	
	if(SSIDInfoArr.length != 0)
		SSIDInfoArr.push(null);
	
	HWShowTableListByType(ShowTableFlag, "wlan_ssidinfo_table", ShowButtonFlag, ColumnNum, SSIDInfoArr, SSIDConfiglistInfo, status_wlaninfo_language, null);

	fixIETableScroll("DivSSIDInfo_Table_Container", "wlan_ssidinfo_table");
</script>

</div>

<div class="func_spread"></div>

</div>

<div id="DivStaInfo">

<div id="ApplyBthSTA" >
	<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_stainfo_title"]);</SCRIPT></div>

	<input id="btn_sta_query" name="btnCheck" type="button" value="" class="NewDelbuttoncss">
	<script>
	  document.getElementById('btn_sta_query').value = status_wlaninfo_language['amp_stainfo_query'];
	</script>
		
	<div class="button_spread"></div>
	
</div>

<div id="DivStaQueryInfo_Table_Container" style="overflow:auto;overflow-y:hidden;">

<script language="javascript">
  $(document).ready(function () {
        var viewModel = {
            $DivStaInfo: $('#DivStaInfo'),
            $btn_sta_query: $('#btn_sta_query'),
            $StaInfoTable: $('#wlan_stainfo_table'),
            
             appendStaInfo: function(record) {

			 var TbHtml = '';

			 var STATShowableFlag = 1;
  			 var STAShowButtonFlag = 0;
  			 var STAColumnNum = 12;
			 var STAArray = new Array();
  			 var STAConfiglistInfo = new Array(
			 			new stTableTileInfo("amp_stainfo_macadd","align_center","AssociatedDeviceMACAddress",false),
  						new stTableTileInfo("amp_wlanstat_name","align_center","ssidname",false),
  						new stTableTileInfo("amp_stainfo_uptime","align_center","X_HW_Uptime",false),
  						new stTableTileInfo("amp_stainfo_txrate","align_center","X_HW_TxRate",false),
  						new stTableTileInfo("amp_stainfo_rxrate","align_center","X_HW_RxRate",false),
  						new stTableTileInfo("amp_stainfo_rssi","align_center","X_HW_RSSI",false),
  						new stTableTileInfo("amp_stainfo_noise","align_center","X_HW_Noise",false),
  						new stTableTileInfo("amp_stainfo_snr","align_center","X_HW_SNR",false),
  						new stTableTileInfo("amp_stainfo_sigqua","align_center","X_HW_SingalQuality",false),
  						new stTableTileInfo("amp_stainfo_working_mode","align_center","X_HW_WorkingMode",0==isStaWorkingModeShow),
  						new stTableTileInfo("amp_stainfo_wmm_status","align_center","X_HW_WMMStatus",0==isStaWorkingModeShow),
  						new stTableTileInfo("amp_stainfo_ps_mode","align_center","X_HW_PSMode",0==isStaWorkingModeShow),null);

	          var ssidstart = 0;
	          var ssidend   = SsidPerBand - 1; 

	          if ((1 == DoubleFreqFlag) && (1 == top.changeWlanClick))
	          {
	            ssidstart = 0;
	            ssidend   = 3;
	          }

	          if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
	          {
	            ssidstart = 4;
	            ssidend   = 7;				
	          }   
            
            for (i = 0; i < record.length - 1; i++)
            {
                var ssid = getWlanInstFromDomain(record[i].domain);  

                for (j = 0; j < WlanInfo.length - 1; j++)
                {
                    var ret = WlanInfo[j].domain.indexOf("InternetGatewayDevice.LANDevice.1.WLANConfiguration."+ssid);
                    if (ret == 0)
                    {
                        var wlanInst = getWlanInstFromDomain(WlanInfo[j].domain);
                        if (1 == isSsidForIsp(wlanInst) && 1 != IspSSIDVisibility)                        
                        {
                            continue;
                        }	

                        var athindex = getWlanPortNumber(WlanInfo[j].name);
                        if (( athindex >= ssidstart )&&( athindex <= ssidend ))
                        {
                            record[i].ssidname = WlanInfo[j].ssid;
							viewModel.convertStaDataToHtml(record[i]);
				   			STAArray.push(record[i]);
                        }
                    }
                }
            }            

			if(STAArray.length != 0)
            	STAArray.push(null);
			
            var _write = document.write;
			document.write = function( str )
			{
			    TbHtml += str;
			}

			HWShowTableListByType(STATShowableFlag, "wlan_stainfo_table", STAShowButtonFlag, STAColumnNum, STAArray, STAConfiglistInfo, status_wlaninfo_language, null);
			$('#DivStaQueryInfo_Table_Container').html(TbHtml);
			document.write = _write;

			fixIETableScroll("DivStaQueryInfo_Table_Container", "wlan_stainfo_table");
			
			},
            processEmptyValue: function(record) {
          	if(!record || typeof record != 'object') return ;
          	
          	for(var pKey in record) {
          		record[pKey] = record[pKey] || '--';
          		}
          		
          	return record;
          },
            convertStaDataToHtml: function(record) {
            	
       			record = viewModel.processEmptyValue(record);
          		if(!record) return "";
          		
          		if( record.X_HW_RSSI < -80 )
			        {
			            record.X_HW_RSSI += status_wlaninfo_language['amp_stainfo_level1'];  
			        }
			        if(( record.X_HW_RSSI >= -80 )&&( record.X_HW_RSSI <= -75 ))
			        {
			            record.X_HW_RSSI += status_wlaninfo_language['amp_stainfo_level2'];  
			        }
			        if(( record.X_HW_RSSI > -75 )&&( record.X_HW_RSSI <= -69 ))
			        {
			            record.X_HW_RSSI += status_wlaninfo_language['amp_stainfo_level3'];  
			        }
			        if(( record.X_HW_RSSI > -69 )&&( record.X_HW_RSSI <= -63 ))
			        {
			            record.X_HW_RSSI += status_wlaninfo_language['amp_stainfo_level4'];  
			        }
			        if( record.X_HW_RSSI > -63 )
			        {
			           record.X_HW_RSSI += status_wlaninfo_language['amp_stainfo_level5'];  
			        }
					
				if( 1 == record.X_HW_WMMStatus )
				{
					record.X_HW_WMMStatus = status_wlaninfo_language['amp_stainfo_wmm_on'];
				}
				else if( 0 == record.X_HW_WMMStatus )
				{
					record.X_HW_WMMStatus = status_wlaninfo_language['amp_stainfo_wmm_off'];
				}
				else
				{
					record.X_HW_WMMStatus = '--';
				}
				
				if( 1 == record.X_HW_PSMode )
				{
					record.X_HW_PSMode = status_wlaninfo_language['amp_stainfo_ps_on'];
				}
				else if( 0 == record.X_HW_PSMode )
				{
					record.X_HW_PSMode = status_wlaninfo_language['amp_stainfo_ps_off'];
				}
				else
				{
					record.X_HW_PSMode = '--';
				}
    	  
          		record.AssociatedDeviceMACAddress = record.AssociatedDeviceMACAddress.toUpperCase();
				record.ssidname = record.ssidname;
          	}
        };

		viewModel.$btn_sta_query.click(function(){
			    
				if (wlanEnbl == 0)
		        {
		            return;
		        }

				viewModel.$btn_sta_query.attr('disabled', 'disabled');

           		$.ajax({
					type : "post",
					async : true,
					url : "./getassociateddeviceinfo.asp",
					success : function(data) {	
					
					AssociatedDevice = eval(data);	

					viewModel.appendStaInfo(AssociatedDevice);	

					viewModel.$btn_sta_query.removeAttr('disabled');
					}		
				});
			});

		viewModel.appendStaInfo(new Array());
    }); 

</script>

</div>

<div class="func_spread"></div>

</div>

<div id="DivNAPInfo">

<div id="ApplyBthNAP" >

	<div class="func_title"><SCRIPT>document.write(status_wlaninfo_language["amp_napinfo_title"]);</SCRIPT></div>
	
	<input id="btn_nap_query" name="btnCheck" type="button" value="" class="NewDelbuttoncss">
	
	<script>
	  document.getElementById('btn_nap_query').value = status_wlaninfo_language['amp_stainfo_query'];
	</script>
		
	<span style="font-size: 12px;margin-left:20px;" ><script>document.write(status_wlaninfo_language['amp_stainfo_napinfoprompt']);</script></span>

	<div class="button_spread"></div>
	
</div>

<div id="DivNAPQueryInfo_Table_Container" style="overflow:auto;overflow-y:hidden;">

<script type="text/javascript">
	    $(document).ready(function () {
        var ap_viewModel = {      
            $DivNAPInfo: $('#DivNAPInfo'),
            $btn_nap_query: $('#btn_nap_query'),
            $ApInfoTable: $('#wlan_napinfo_table'),

            appendApInfo: function(info) {

			 var TbHtml = '';
			 
			 var APShowableFlag = 1;
  			 var APShowButtonFlag = 0;
  			 var APColumnNum = 11;
			 var APArray = new Array();
  			 var APConfiglistInfo = new Array(
			 			new stTableTileInfo("amp_wlanstat_name","align_center","SSID",false),
  						new stTableTileInfo("amp_stainfo_macadd","align_center","BSSID",false),
  						new stTableTileInfo("amp_napinfo_type","align_center","NetworkType",false),
  						new stTableTileInfo("amp_napinfo_channel","align_center","Channel",false),
  						new stTableTileInfo("amp_stainfo_rssi","align_center","RSSI",false),
  						new stTableTileInfo("amp_stainfo_noise","align_center","Noise",false),
  						new stTableTileInfo("amp_napinfo_dtim","align_center","DtimPeriod",false),
  						new stTableTileInfo("amp_napinfo_beacon","align_center","BeaconPeriod",false),
  						new stTableTileInfo("amp_napinfo_security","align_center","Security",false),
  						new stTableTileInfo("amp_napinfo_standard","align_center","Standard",false),
  						new stTableTileInfo("amp_napinfo_maxrate","align_center","MaxBitRate",false),null);
                          
            	if(info instanceof Array) {
            		$.each(info, function(index, item) {
            			item = ap_viewModel.processEmptyValue(item);
            			if(!item) return false;
            			
            			if ((1 == DoubleFreqFlag) && (1 == top.changeWlanClick))
		                {
                        
		                    if (item.domain.indexOf(node2G) != 0)
		                    {
		                       return true;
		                    }
		                }
		                if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
		                {
		                    if (item.domain.indexOf(node5G) != 0)
		                    {
		                       return true;
		                    }				
		                }
	               
            			ap_viewModel.convertApDataToHtml(item);
						APArray.push(item);
            		});

					if(APArray.length != 0)
						APArray.push(null);

					var _write = document.write;
					document.write = function( str ){TbHtml += str;}

					HWShowTableListByType(APShowableFlag, "wlan_napinfo_table", APShowButtonFlag, APColumnNum, APArray, APConfiglistInfo, status_wlaninfo_language, null);
					$('#DivNAPQueryInfo_Table_Container').html(TbHtml);
					
					document.write = _write;

					fixIETableScroll("DivNAPQueryInfo_Table_Container", "wlan_napinfo_table");
            	}
            },
          processEmptyValue: function(record) {
          	if(!record || typeof record != 'object') return;
          	
          	for(var pKey in record) {
          		record[pKey] = record[pKey] || '--';
          		}
          		
          	return record;
          },
			convertApDataToHtml: function(record) {
				
				if(!record) return "";
				
				if( record.RSSI < -80 )
				{
				    record.RSSI += status_wlaninfo_language['amp_stainfo_level1'];  
				}
				if(( record.RSSI >= -80 )&&( record.RSSI <= -75 ))
				{
				    record.RSSI += status_wlaninfo_language['amp_stainfo_level2'];  
				}
				if(( record.RSSI > -75 )&&( record.RSSI <= -69 ))
				{
				    record.RSSI += status_wlaninfo_language['amp_stainfo_level3'];  
				}
				if(( record.RSSI > -69 )&&( record.RSSI <= -63 ))
				{
				    record.RSSI += status_wlaninfo_language['amp_stainfo_level4'];  
				}
				if( record.RSSI > -63 )
				{
				    record.RSSI += status_wlaninfo_language['amp_stainfo_level5'];  
				}

				record.BSSID = record.BSSID.toUpperCase();
				record.SSID = record.SSID;
          	}
        };
        
        ap_viewModel.$btn_nap_query.click(function(){
				if (wlanEnbl == 0)
        		{
            		return;
        		}

		        if ((1 == DoubleFreqFlag) && (2 == top.changeWlanClick))
		        {
		            getRadarMode();
		        	 if(1 == WlanWorkMode )
			        {
			        	AlertEx(status_wlaninfo_language['amp_stainfo_workmodeprompt']);
			        	return;
			        }
                    if (2 == WlanWorkMode )
			        {
			        	AlertEx(status_wlaninfo_language['amp_stainfo_workmodescan']);
			        	return;
			        }
		        }

				ap_viewModel.$btn_nap_query.attr('disabled', 'disabled');
              
				$.ajax({
					type : "post",
					async : true,
					url : "./getneighbourAPinfo.asp",
					success : function(data) {	
					
					NeighbourAP = eval(data);	
					
					ap_viewModel.appendApInfo(NeighbourAP);		

					ap_viewModel.$btn_nap_query.removeAttr('disabled');
					}
				});
			});

		ap_viewModel.appendApInfo(new Array());
    });

</script> 

</div>


</div>

<script language="JavaScript" type="text/javascript">
function backupSetting()
{
  var Form = new webSubmitForm();
	Form.addParameter('logtype', "opt");
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('staeventlog.cgi?FileType=wifilog&RequestFile=html/amp/wlaninfo/wlaninfo.asp');
	Form.submit();
}
</script>


<div class="title_spread"></div>
<div id="blank_line">
	<div class="title_spread">
		<SCRIPT>
			setDisplay('blank_line',(1 == curUserType));
		</SCRIPT>
	</div>
</div>
<div id='sta_event_view'>
<div class="func_title"><SCRIPT>
	setDisplay('sta_event_view', (0 == curUserType));		
	document.write(status_wlaninfo_language["amp_stainfo_event_log"]);
</SCRIPT></div>
	<div>
		<tr>
			<td>
				<input id="btn_sta_event" name="btnCheck" type="button" value="" class="NewDelbuttoncss" onClick='backupSetting()'>
				<input type="hidden" name="onttoken" id="onttoken" value="<%HW_WEB_GetToken();%>">
				<script>
						document.getElementById('btn_sta_event').value = status_wlaninfo_language['amp_stainfo_event_log_download'];
				</script>
			</tr>
		</td>
	</div>

<div class="button_spread"></div>
<div id="logviews"> 
  <textarea name="logarea" id="logarea" class="text_log" wrap="off" readonly="readonly">
  </textarea> 
	<script type="text/javascript">
		document.getElementById("logarea").value = '<%HW_WEB_GetStaEventLog();%>';
	</script> 
</div> 
</div>

</body>
</html>
