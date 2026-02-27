<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  id="Page" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />

<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<style type="text/css">
.nomargin {
    margin-left: 0px;
    margin-right:0px;
    margin-top: 0px;
}
.firstOntIcon,.firstOntStruct,.firstConnectLine,.secondOntStruct,.firstMountDevType{
    float:left;
}
.firstConnectLine{
    padding: 0px 5px;
    width: 22px;
    height:2px;
    background-color:#d3d3d3;
    margin-top: 35px;
}
.firstOntIcon{
    width: 60px;
    height: 60px;
    background-image:url(../../../images/wifiseticon.png);
    background-position: left center;
    background-size: 60px 60px;
    background-repeat: no-repeat;
    padding: 0px 5px;
    margin-top:8px;
}
.firstMountDevType{
    margin-top: 25px;
    line-height: 14px;
}
.ssss{
    min-height:70px;
    height: auto;
    background-position: 0px 35px;
    background-repeat: no-repeat;
}
.PageTitle_content{
    width:calc(100% - 5px);
}
</style>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../../bbsp/common/lanmodelist.asp"></script>
<script language="javascript" src="../../bbsp/common/managemode.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<script language="JavaScript" type="text/javascript">
var LANPath = "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.";
var SSIDPath = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.";
var LANPortInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_APService.MultiSrvPortList.PhyPortName);%>'.toUpperCase();
var WLANInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}, SSIDReference, stWLANInfo);%>;
var WanIpList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i}, ConnectionType|Name|X_HW_SERVICELIST|X_HW_BindPhyPortInfo|X_HW_IPv4Enable|X_HW_IPv6Enable,stWANIP);%>;
var WanPppList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i},ConnectionType|Name|X_HW_SERVICELIST|X_HW_BindPhyPortInfo|X_HW_IPv4Enable|X_HW_IPv6Enable,stWANPPP);%>;
var TopoInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_Topo,X_HW_EthNum|X_HW_SsidNum,TopoInfo);%>;
var DoubleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
var RegNewPageFlag = "<%HW_WEB_GetFeatureSupport(FT_MULTI_SERVICE_IPTV_PORT_NEW);%>";
var RegPageFlag = "<%HW_WEB_GetFeatureSupport(FT_MULTI_SERVICE_IPTV_PORT);%>";
var SupportIPv6 = "<%HW_WEB_GetFeatureSupport(BBSP_FT_IPV6);%>";
var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';
var UpportDetectFlag ='<%HW_WEB_GetFeatureSupport(FT_UPPORT_DETECT);%>';
var UpUserPortID = '<%HW_WEB_GetCurUpUserPortID();%>';
var PonUpportConfig ='<%HW_WEB_GetFeatureSupport(FT_PON_UPPORT_CONFIG);%>';
var upMode = '<%HW_WEB_GetUpMode();%>';
var TopoInfo = TopoInfoList[0];
var lanPortNum = '<%GetLanPortNum();%>';
var APInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, DeviceType|ApOnlineFlag|UplinkType|APMacAddr|SyncStatus|LanPortNum, stApDevice);%>;
var APSetInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APService.MultiSrvPortList.AP.{i}, Mac|StbPort, APSetInfo);%>;
var Advancedconfig = "<%HW_WEB_GetFeatureSupport(FT_IPTV_PORT_ADVANCE_CONFIG);%>";
var IPTVUpPortInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_APService.IPTVUpPort);%>'.toUpperCase();
var MAINUpPortInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.X_HW_MainUpPort);%>'.toUpperCase();
var CurrentMAINUpInfo = "";
var CurrentIPTVUpInfo = "";
var notSupportPON = '<%HW_WEB_GetFeatureSupport(FT_WEB_DELETE_PON);%>';
GetIPTVPortInfo();
GetMAINPortInfo();
var fttrmain = "<%HW_WEB_GetFeatureSupport(FT_FTTR_MAIN_ONT);%>";
var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
var APMacSelectList = new Array();
var TableName = "APConfigList";
var selectIndex = -1;
var numpara = "";
APMacSelectList[0] = portmapping_language['bbsp_hostName_select'];
var var_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var curUserType = '<%HW_WEB_GetUserType();%>';
var currentBin = '<%HW_WEB_GetBinMode();%>';
var isSupportWLAN = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_WLAN);%>';
var rosunionGame = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_ROSUNION_GAME);%>';
var curWebFrame='<%HW_WEB_GetWEBFramePath();%>';
var TypeWord='<%HW_WEB_GetTypeWord();%>';
var isBponFlag = '<%HW_WEB_GetFeatureSupport(HW_FEATURE_ZQ);%>';
var UserDevices = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecialGetUserDevInfo,InternetGatewayDevice.LANDevice.1.X_HW_UserDev.{i},MacAddr|PortID,USERDevice);%>;

if( window.location.href.indexOf("?") > 0) {
    numpara = window.location.href.split("?")[1]; 
}

var APDeviceInfos = {};
for (var i = 0; i < APInfoList.length - 1; i++) {
    APDeviceInfos[mac2Str(APInfoList[i].APMacAddr)] = APInfoList[i].LanPortNum;
}

var initAPSetInfoList = {};
for (var i = 0; i < APSetInfoList.length - 1; i++) {
    initAPSetInfoList[mac2Str(APSetInfoList[i].Mac)] = APSetInfoList[i];
}

function TopoInfo(Domain, EthNum, SSIDNum) {   
    this.Domain = Domain;
    this.EthNum = EthNum;
    this.SSIDNum = SSIDNum;
}

function stConfigPort(domain,X_HW_MainUpPort) {
	this.domain = domain;
	this.X_HW_MainUpPort = X_HW_MainUpPort;
}

function USERDevice(Domain, MacAddr, PortID) {
    this.Domain = Domain;
    this.MacAddr = MacAddr;
    this.PortID = PortID;
}
var macPortMapping = {};
for (var i = 0; i < UserDevices.length - 1; i++) {
    macPortMapping[mac2Str(UserDevices[i].MacAddr).toLowerCase()] = UserDevices[i].PortID;
}

function GetIPTVPortInfo() {
	if (IPTVUpPortInfo.length != 0) {
		var tempIPTVUpValue = IPTVUpPortInfo.replace(LANPath.toUpperCase(), "LAN");
		var tempIPTVUpList = tempIPTVUpValue.split(".");
		CurrentIPTVUpInfo = tempIPTVUpList[0];
	}
}

function GetMAINPortInfo() {
	if (MAINUpPortInfo.length != 0) {
		var tempMAINUpList = MAINUpPortInfo.split(".");
		CurrentMAINUpInfo = tempMAINUpList[0];
	}
}

function wifiConfig() {
    if (isSupportWLAN == 0) {
        return;
    }
    Form = window.parent.parent.wifiForm;
    Form.submit();
}

function PortNextPage() {
    if ((IsCTRG == 1) && (currentBin.toUpperCase() != "COMMON")) {
        window.top.location = "/CustomApp/Aindex.asp"
        return;
    }

    if (var_singtel == true) {
        if (TypeWord_com == "COMMON") {
            window.top.location = "/index.asp";
        } else {
            window.top.location = "/mainpage.asp";
        }
    } else {
        window.top.location = "/index.asp";
    }
}

function onindexpage(val)
{
    if (isSupportWLAN == 0) {
        AddConfigFlag();
    }
    if ((fttrmain == 1) && (window.parent.isGuidePage == 1) && (curUserType == 1)) {
        wifiConfig();
    }
    setTimeout("PortNextPage()", 300);
}

function stWANIP(domain, ConnectionType, Name, X_HW_SERVICELIST, X_HW_BindPhyPortInfo, X_HW_IPv4Enable, X_HW_IPv6Enable) {
	this.domain 	  = domain;
	this.ConnectionType = ConnectionType;
	this.Name = Name;
	this.ServiceList = X_HW_SERVICELIST;
	this.BindPhyPort  = X_HW_BindPhyPortInfo;
	this.IPv4Enable = X_HW_IPv4Enable;
    this.IPv6Enable = X_HW_IPv6Enable;
	if (0 == SupportIPv6) {
        this.IPv6Enable = 0;
        this.IPv4Enable = 1;
    }
}

function stWANPPP(domain, ConnectionType, Name, X_HW_SERVICELIST, X_HW_BindPhyPortInfo, X_HW_IPv4Enable, X_HW_IPv6Enable) {
	this.domain 	  = domain;
	this.ConnectionType = ConnectionType;
	this.Name = Name;
	this.ServiceList = X_HW_SERVICELIST;
	this.BindPhyPort  = X_HW_BindPhyPortInfo;
	this.IPv4Enable = X_HW_IPv4Enable;
    this.IPv6Enable = X_HW_IPv6Enable;
	if (0 == SupportIPv6) {
        this.IPv6Enable = 0;
        this.IPv4Enable = 1;
    }
}

GetLANPortListInfo();

function stWLANInfo(Domain, SSIDReference) {
	this.Domain = Domain;
    this.SSIDReference = SSIDReference.replace("Device.WiFi.SSID.", "SSID");;
}

function APSetInfo(domain, Mac, StbPort) {
	this.domain = domain;
	this.Mac = Mac;
	this.StbPort = StbPort;
}

function DisableLanAndSSID(BindPhyPort) {
	var i;
	var tempLanList = BindPhyPort.split(",");
	for (i = 0; i < tempLanList.length; i++)
	{
		if ((RegPageFlag == 0) && (RegNewPageFlag == 1)) {	
			setCheck(tempLanList[i], 0);
		}
		setDisable(tempLanList[i], 1);
	}
}

function DisplayLanAndSSID(BindPhyPort) {
	var i;
	var tempLanList = BindPhyPort.split(",");
	for (i = 0; i < tempLanList.length; i++) {
		if ((RegPageFlag == 0) && (RegNewPageFlag == 1)) {	
			setCheck(tempLanList[i], 0);
		}
		setDisplay("Div_" + tempLanList[i], 0);
	}
}

function EnableLanAndSSID(BindPhyPort) {
	var i;
	var tempLanList = BindPhyPort.split(",");
	for (i = 0; i < tempLanList.length; i++)
	{
		setDisable(tempLanList[i], 0);
	}
}

function InitWANPhyPort() {
	var i = 0;
	if ((RegPageFlag == 0) && (RegNewPageFlag == 1)) {
		if ((WanIpList.length == 1) && (WanPppList.length == 1)) {
			for (var i = 1; i <= 8; i++)
			{
				setCheck("LAN"+i, 0);
				setDisable("LAN"+i, 1);
			}
			for (var i = 1; i <= 8; i++)
			{
				setCheck("SSID"+i, 0);
				setDisable("SSID"+i, 1);
			}
		} else {	
			for (i = 0; i < WanIpList.length -1; i++)
			{	
				if ((WanIpList[i].BindPhyPort != "") && (WanIpList[i].ConnectionType == "IP_Routed") && (WanIpList[i].ServiceList.toString().toUpperCase().indexOf("INTERNET") >= 0) && (WanIpList[i].IPv6Enable.toUpperCase() == 0)
					&& (WanIpList[i].ServiceList.toString().toUpperCase().indexOf("IPTV") < 0 )) {
					EnableLanAndSSID(WanIpList[i].BindPhyPort);
				}
				else if (WanIpList[i].BindPhyPort != "" && WanIpList[i].ConnectionType == "IP_Bridged" && (WanIpList[i].ServiceList.toString().toUpperCase().indexOf("IPTV") >= 0 || WanIpList[i].ServiceList.toString().toUpperCase().indexOf("OTHER") >= 0) && WanIpList[i].IPv6Enable.toUpperCase() == 0) {
					EnableLanAndSSID(WanIpList[i].BindPhyPort);
				} else {
					DisableLanAndSSID(WanIpList[i].BindPhyPort);
				}
			}
			for (i = 0; i < WanPppList.length -1; i++)
			{			
				if ((WanPppList[i].BindPhyPort != "") && ((WanPppList[i].ConnectionType == "IP_Routed") || (WanPppList[i].ConnectionType == "PPPoE_Routed")) && (WanPppList[i].ServiceList.toString().toUpperCase().indexOf("INTERNET") >= 0) && (WanPppList[i].IPv6Enable.toUpperCase() == 0)
					&& (WanPppList[i].ServiceList.toString().toUpperCase().indexOf("IPTV") < 0 )) {
					EnableLanAndSSID(WanPppList[i].BindPhyPort);
				}
				else if (WanPppList[i].BindPhyPort != "" && WanPppList[i].ConnectionType == "PPPoE_Bridged" && (WanPppList[i].ServiceList.toString().toUpperCase().indexOf("IPTV") >= 0 || WanPppList[i].ServiceList.toString().toUpperCase().indexOf("OTHER") >= 0) && WanPppList[i].IPv6Enable.toUpperCase() == 0) {
					EnableLanAndSSID(WanPppList[i].BindPhyPort);
				} else {
					DisableLanAndSSID(WanPppList[i].BindPhyPort);
				}
			}
		}
		for (var i = 1; i <= 8; i++)
		{
			if (getElById("LAN"+i).disabled == true) {
				setCheck("LAN"+i, 0);
			}
		}
		for (var i = 1; i <= 8; i++)
		{
			if (getElById("SSID"+i).disabled == true) {
				setCheck("SSID"+i, 0);
			}
		}
	} else {
		for (i = 0; i < WanIpList.length -1; i++)
		{
			if (WanIpList[i].BindPhyPort != "" && WanIpList[i].ConnectionType == "IP_Routed" && WanIpList[i].ServiceList.toUpperCase().indexOf("INTERNET") >= 0) {
				DisableLanAndSSID(WanIpList[i].BindPhyPort);
			}
		}
		
		for (i = 0; i < WanPppList.length -1; i++)
		{
			if (WanPppList[i].BindPhyPort != "" && WanPppList[i].ConnectionType == "IP_Routed" && WanPppList[i].ServiceList.toUpperCase().indexOf("INTERNET") >= 0) {
				DisableLanAndSSID(WanPppList[i].BindPhyPort);
			}
		}
	}
}

function stApDevice(domain, type, ApOnlineFlag, UplinkType, APMacAddr, SyncStatus, LanPortNum) {
    this.domain = domain;
    this.type = type;
	this.ApOnlineFlag = ApOnlineFlag;
	this.UplinkType = UplinkType;
    this.APMacAddr = APMacAddr;
    this.SyncStatus = SyncStatus;
    this.LanPortNum = LanPortNum;
}

var onLineApNum = 0;
var offLineApNum = 0;
var offLineApList = new Array();
function GetOffLineApList() {
    for (var i = 0; i < APInfoList.length - 1; i++) {
        if ((APInfoList[i].ApOnlineFlag == 1) && (APInfoList[i].SyncStatus == 3)) {
            onLineApNum++;
        } else {
            offLineApList[offLineApNum] = APInfoList[i];
            offLineApNum++;
        }
    }
}

function GetLANPortListInfo() {
	var tempLANPortValue = "";
	var tempLANPortList = LANPortInfo.split(",");
	var CurLANPortList = new Array();
	for (var i = 0; i < tempLANPortList.length; i++)
	{		
		if (tempLANPortList[i].indexOf(LANPath.toUpperCase()) != -1) {
			tempLANPortValue = tempLANPortList[i].replace(LANPath.toUpperCase(), "LAN");
		} else {
			tempLANPortValue = tempLANPortList[i].replace(SSIDPath.toUpperCase(), "SSID");
		}

		var tempLANPortInfoList = tempLANPortValue.split(".");
		CurLANPortList[i] = tempLANPortInfoList[0];
	}
	
	self.parent.CurrentLANPortList = CurLANPortList;
}

function InitLANPortFromValue() {
	setCheck("LAN1", 0);
	setCheck("LAN2", 0);
	setCheck("LAN3", 0);
	setCheck("LAN4", 0);
	setCheck("LAN5", 0);
    setCheck("LAN6", 0);
    setCheck("LAN7", 0);
    setCheck("LAN8", 0);
	setCheck("SSID1", 0);
	setCheck("SSID2", 0);
	setCheck("SSID3", 0);
	setCheck("SSID4", 0);
	setCheck("SSID5", 0);
	setCheck("SSID6", 0);
	setCheck("SSID7", 0);
	setCheck("SSID8", 0);
	setDisable("SSID1", 1);
	setDisable("SSID2", 1);
	setDisable("SSID3", 1);
	setDisable("SSID4", 1);
	setDisable("SSID5", 1);
	setDisable("SSID6", 1);
	setDisable("SSID7", 1);
	setDisable("SSID8", 1);

	if (notSupportPON == "1") {
        setDisplay("Div_LAN4", 0);
	}
	for(var i = 0; i < self.parent.CurrentLANPortList.length; i++)
	{
		setCheck(self.parent.CurrentLANPortList[i].toUpperCase(), 1);
	}
	
	for(i = 0; i < WLANInfoList.length - 1; i++)
	{
		setDisable(WLANInfoList[i].SSIDReference, 0);
	}
		
	return;
}

function LANPortSubmit() {
	var tempLANID = "";
	var tempLANValue = "";
	var tempSSIDID = "";
	var tempSSIDValue = "";
	var tempLANPortValue = "";
	var iCount = 0;
	var i = 0;
	for (i = 1; i <= TopoInfo.EthNum; i++) {
		tempLANID = "LAN" + i;
		tempLANValue = LANPath + i;
		if (1 == getCheckVal(tempLANID)) {
			if (iCount == 0) {
				tempLANPortValue = tempLANValue;
			} else {	
				tempLANPortValue = tempLANPortValue + "," + tempLANValue;
			}
			iCount = iCount + 1;
		}
	}

	for (i = 1; i <= self.parent.TopoInfo.SSIDNum; i++)
	{
		tempSSIDID = "SSID" + i;
		tempSSIDValue = SSIDPath + i;
		if (1 == getCheckVal(tempSSIDID)) {
			if (iCount == 0) {
				tempLANPortValue = tempSSIDValue;
			} else {	
				tempLANPortValue = tempLANPortValue + "," + tempSSIDValue;
			}
			iCount = iCount + 1;
		}
	}
    if (fttrmain == '1') {
        if (getCheckVal("PON1") == 1) {
            if (tempLANPortValue == "") {
                tempLANPortValue = "PON1";
            } else {
                tempLANPortValue = tempLANPortValue + ",PON1";
            }
        }

        if (LANPortInfo != tempLANPortValue.toUpperCase()) {
            if (ConfirmEx(lanservicecfg_language['bbsp_lanservice_config_tips']) == false) {
                return;
            }
        }
    }
	
	var Form = new webSubmitForm();
	Form.addParameter('x.PhyPortName', tempLANPortValue);
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=' + 'InternetGatewayDevice.X_HW_APService.MultiSrvPortList' + '&RequestFile=html/bbsp/lanservicecfg/lanportcfg.asp');
	Form.submit();
	return;
}

function LANPortCancle() {
	LoadFrame();
	return;
}

function InitLANPortShow() {
	for (var i = 1; i <= 8; i++) {
		setDisable("LAN"+i, 1);
	}
	for (var i = 1; i <= 8; i++) {
		setDisable("SSID"+i, 1);
	}
}

function InitAPInfoForm() {
	if (APInfoList.length - 1 == 0) {
	   selectLine('record_no');
	   setDisplay('form_APConfigInfo',0);
	} else {
	   selectLine(TableName + '_record_0');
	   setDisplay('form_APConfigInfo', 0);
	}
	setDisable('btnApply_ex',0);
	setDisable('cancel',0);

	if(isValidMacAddress(numpara) == true) {
		clickAdd(TableName + '_head');
		setText('li_APMACAddr', numpara);
	}
	
	checkboxfunc();
	setDisable('li_APMACAddr',1);
	selectIndex = 0;
}

function LoadFrame() {
    $("#APInfo_content").addClass("PageTitle_content_left");
	InitLANPortFromValue();
	if ((RegPageFlag == 0) && (RegNewPageFlag == 1)) {
		InitLANPortShow();
		InitWANPhyPort();
	}
	setDisplay('div_APInfo', 0);
	DisableLanAndSSID(CurrentMAINUpInfo);
	DisplayLanAndSSID(CurrentIPTVUpInfo);
	if(Advancedconfig == 1) {
		InitAPInfoForm();
	}

	if (window.parent.isGuidePage) {		
		$(".mainbody").css("background-color", "#FFFFFF");
		$("#APInfo").css("margin-left", "0");
		$("#APInfo_content").css("color", "#666666");
		top.setDisplay("framepageContent", 1);
	}

    GetOffLineApList();
    if (isBponFlag == 1) {
        setDisplay("apNumDiv", 1);
        getElementById("onLineApNum").innerHTML = onLineApNum;
        getElementById("offLineApNum").innerHTML = offLineApNum;
    }
	return;
}

var prefixWord = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i','j',
                  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's','t',
                  'u', 'v', 'w', 'x', 'y', 'z'];
var prefixWordIndex = 0;
function getPrefixWordIndex() {
    var integerPart = parseInt(prefixWordIndex / prefixWord.length);
    var remainder = prefixWordIndex % prefixWord.length;
    var res = '';
    if (integerPart !== 0) {
        res += prefixWord[integerPart - 1];
    }
    res += prefixWord[remainder];
    prefixWordIndex++;
    return res;
}

function AddSubmitParam() {
    var addList = [];
    var setList = [];
    var delList = [];

    for (var key in selectedAPSetInfoList) {
        if (Object.prototype.hasOwnProperty.call(selectedAPSetInfoList, key)) {
            var value = selectedAPSetInfoList[key];
            value = value.substring(0, value.length - 1);
            if (initAPSetInfoList[key] === undefined) {
                addList.push(new APSetInfo('', str2Mac(key), value));
            } else {
                if (initAPSetInfoList[key].StbPort === value) {
                    continue;
                }
                setList.push(new APSetInfo(initAPSetInfoList[key].domain, initAPSetInfoList[key].Mac, value));
            }
        }
    }

    for (var key in initAPSetInfoList) {
        if (Object.prototype.hasOwnProperty.call(initAPSetInfoList, key)) {
            if (selectedAPSetInfoList[key] === undefined) {
                delList.push(initAPSetInfoList[key]);
            }
        }
    }
    
    var url = 'complexajax.cgi?';
    var formDate = '';
    var prefix = '';
    if (addList.length > 0) {
        for (var i = 0; i < addList.length; i++) {
            prefix = 'Add_' + getPrefixWordIndex();
            url += prefix + '=InternetGatewayDevice.X_HW_APService.MultiSrvPortList.AP' + '&';
            formDate += prefix + '.Mac=' + addList[i].Mac + '&';
            formDate += prefix + '.StbPort=' + addList[i].StbPort + '&';
        }
    }

    if (setList.length > 0) {
        for (var i = 0; i < setList.length; i++) {
            prefix = 'Set_' + getPrefixWordIndex();
            url += prefix + '=' + setList[i].domain + '&';
            formDate += prefix + '.Mac=' + setList[i].Mac + '&';
            formDate += prefix + '.StbPort=' + setList[i].StbPort + '&';
        }
    }

    if (delList.length > 0) {
        for (var i = 0; i < delList.length; i++) {
            prefix = 'Del_' + getPrefixWordIndex();
            url += prefix + '=' + delList[i].domain + '&';
        }
    }

    if (prefix === '') {
        return;
    }

    url = url.substring(0, url.length - 1);
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        data : formDate + 'x.X_HW_Token=' + getValue('hwonttoken'),
        url : url + '&RequestFile=html/bbsp/lanservicecfg/lanportcfg.asp',
        success : function(data) {
            if (data.indexOf('200') === -1) {
                AlertEx(lanservicecfg_language['bbsp_lanservice_save_failed']);
            }
            window.location.reload();
        },
    });
}

function SubmitEx() {
    AddSubmitParam();
}

function setAllStbDisable() {
    for (var i = 0; i < APInfoList.length - 1; i++) {
        for (var j = 1; j <= 3; j++) {
            setSTBDisable(mac2Str(APInfoList[i].APMacAddr) + '_LAN' + j);
        }
    }
    selectedAPSetInfoList = {};
}

function CancelValue() { 
    setAllStbDisable();
    initSTBPort();
}

function removeClick() {
   var rml = getElement('rml');
  
   if (rml == null)
   	   return;
 
   var Form = new webSubmitForm();

   var k;	   
   if (rml.length > 0) {
      for (k = 0; k < rml.length; k++) {
         if ( rml[k].checked == true ) {
			 Form.addParameter(rml[k].value,'');
		 }	
      }
   }  
   else if ( rml.checked == true ) {
	  Form.addParameter(rml.value,'');
   }
   Form.addParameter('x.X_HW_Token', getValue('onttoken'));	  
   Form.setAction('del.cgi?RequestFile=html/bbsp/lanservicecfg/lanportcfg.asp.asp');
   Form.submit();
}

function OnDeleteButtonClick(TableID) { 
    if ((APSetInfoList.length - 1) == 0) {
	    AlertEx(lanservicecfg_language['bbsp_lanservice_choose_ap_noapfilter']);
	    return;
	}

	if (selectIndex == -1) {
	    AlertEx(lanservicecfg_language['bbsp_lanservice_choose_ap_saveapfilter']);
	    return;
	}

    var CheckBoxList = document.getElementsByName(TableName+'rml');
	var Form = new webSubmitForm();
	var Count = 0;
	for (var i = 0; i < CheckBoxList.length; i++) {
		if (CheckBoxList[i].checked != true) {
			continue;
		}
		
		Count++;
		Form.addParameter(CheckBoxList[i].value,'');
	}
	if (Count <= 0) {
		AlertEx(lanservicecfg_language['bbsp_lanservice_choose_ap_selectapfilter']);
		return;
	}

	if (ConfirmEx(lanservicecfg_language['bbsp_lanservice_choose_ap_filterconfirm1']) == false) {
		document.getElementById("DeleteButton").disabled = false;
		return;
	}
	
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('del.cgi?' +'x=InternetGatewayDevice.X_HW_APService.MultiSrvPortList.AP' + '&RequestFile=html/bbsp/lanservicecfg/lanportcfg.asp');
	Form.submit();
	setDisable('DeleteButton',1);
	setDisable('btnApply_ex',1);
	setDisable('cancel',1);
}

function AddConfigFlag()
{
	if ((IsCTRG == 1) && (currentBin.toUpperCase() != "COMMON")) {
		$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : '/smartguide.cgi?1=1&RequestFile=/CustomApp/Aindex.asp',
		data: getDataWithToken('Parainfo=0', true),
		success : function(data) {
		 ;
		}
		}); 
	} else {
		$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : '/smartguide.cgi?1=1&RequestFile=index.asp',
		data: getDataWithToken('Parainfo=0', true),
		success : function(data) {
		 ;
		}
		}); 
	}
	
}

var changeUrl = "";
function PortGuideNext() {
    if ((IsCTRG == 1) && (currentBin.toUpperCase() != "COMMON")) {
        window.top.location = "/CustomApp/Aindex.asp";
        return;
    }
    top.onchangestep(changeUrl);
}

function guideNext(val)
{
    changeUrl = val;
    AddConfigFlag();
    if ((fttrmain == 1) && (curUserType == 0) && (IsCTRG == 1)) {
        wifiConfig();
    }
    setTimeout("PortGuideNext()", 300);
}

function guideSkip(val)
{
    changeUrl = val;
    AddConfigFlag();
    if ((fttrmain == 1) && (curUserType == 0) && (IsCTRG == 1)) {
        wifiConfig();
    }
    setTimeout("PortGuideNext()", 300);
}

function checkboxfunc() {
	if(Advancedconfig != 1) {
		return;
	}
	
	if(LANPortInfo.length > 0) {
		setDisplay('div_APInfo', 1);
	} else {
		setDisplay('div_APInfo', 0);
	}
}

function judgeAcessType(accessType) {
    var accessMode;
    if (accessType === '1') {
        accessMode = "Wi-Fi";
    } else if ((accessType === '2') || (accessType === '5')) {
        accessMode = "Ethernet";
    } else if ((accessType === '3') || (accessType === '0')) {
        accessMode = "G.hn";
    } else if (accessType === '4') {
        accessMode = "FTTR";
    } else {
        accessMode = accessType;
    }
    return accessMode;
}

function isSpeedShowWithTxRx(accessMode) {
    if ((accessMode == "Wi-Fi") || (accessMode == "G.hn") || (accessMode == "PON")) {
        return true;
    }
    return false;
}

function AppendFirstDevInfoFunc(MenuJsonData) {
    for(var FirstMenuindex in MenuJsonData) {
        var DevType = MenuJsonData[FirstMenuindex].DevType;
        var AccessType = MenuJsonData[FirstMenuindex].AccessType;
        var MAC = MenuJsonData[FirstMenuindex].MAC.toUpperCase();
        var IP = MenuJsonData[FirstMenuindex].IP.toUpperCase();
        var FirstDevTypeStr = "";
        var FirstMacStr = "";
        FirstDevTypeStr += '<div class="FirstDevTypeStr" id="firstDevType_' + AccessType + '">'+ DevType;
        if (isBponFlag == 1) {
            FirstDevTypeStr += GetSpecNameByMac(MAC);
        }
        FirstDevTypeStr += '</div>';
        FirstMacStr += '<div class="FirstMacStr" id="firstMAC_' + MAC + '">'+ "MAC:" + MAC +'</div>';

        $("#firstMountDevInfo").append(FirstDevTypeStr);
        $("#firstMountDevInfo").append(FirstMacStr);

        if(DevType == 'STA' && AccessType != 'G.hn') {
            $(".ssss_" +DevType).css('display','none');
        }
        if(MenuJsonData[FirstMenuindex].sub !== undefined) {		
            SecondLevelDevArray = MenuJsonData[FirstMenuindex].sub;
            AppendDevInfoFunc('', SecondLevelDevArray, 1);
        }

        if (offLineApList.length != 0) {
            AppendSecondDevInfoOffFunc();
        }

        break;
    }
}

var selectedAPSetInfoList = {};
function setAPInfoList(id, operateType) {
    var input = id.split('_');
    var selectedPort = '';
    if (selectedAPSetInfoList[input[0]]) {
        selectedPort = selectedAPSetInfoList[input[0]];
    }
    switch (operateType) {
        case 'add' : {
            selectedAPSetInfoList[input[0]] = selectedPort + input[1] + ',';
            break;
        };
        case 'del' : {
            var index = selectedPort.indexOf(input[1]);
            if (index < 0) {
                break;
            } else {
                selectedPort = selectedPort.replace(input[1] + ',', '');
                if (selectedPort === '') {
                    delete selectedAPSetInfoList[input[0]];
                } else {
                    selectedAPSetInfoList[input[0]] = selectedPort;
                }
            }
            break;
        }
    }
}

function setSTBEnable(id) {
    var ele = $("#" + id)[0];
    if (ele === undefined) {
        return;
    }
    var oldPath = $("#" + id)[0].src;
    var newPath = '../../../images/lan_disconnected.png';
    if (oldPath.indexOf("lan_connected.png") > -1) {
        $("#" + id).attr('src', newPath);
        setAPInfoList(id, 'del');
    } else {
        newPath = '../../../images/lan_connected.png';
        $("#" + id).attr('src', newPath);
        setAPInfoList(id, 'add');
    }
}

function setSTBDisable(id) {
    var newPath = '../../../images/lan_disconnected.png';
    $("#" + id).attr('src', newPath);
}

function getStrBaseLanPortNum(portNum, MAC) {
    var str = '';
    for (var i = 1; i <= portNum; i++) {
        str += '<span>LAN' + i + '</span><img height="30px" style="vertical-align:middle" src="../../../images/lan_disconnected.png" id="' + MAC + '_LAN' + i + '" onclick="setSTBEnable(this.id)"/>';
    }
    return str;
}

function mac2Str(mac) {
    return mac.split(':').join('');
}

function str2Mac(str) {
    return str.replace(/\w(?=(\w{2})+$)/g, "$&:");
}

function isShowInTopo(mac) {
    var port = macPortMapping[mac.toLowerCase()];
    if (port == undefined) {
        return false;
    }
    if (port.indexOf('ONU') !== -1) {
        port = 'PON1';
    }
    if (getCheckVal(port) === 1) {
        return true;
    } else {
        return false;
    }
}

function getLanPort(mac) {
    return APDeviceInfos[mac];
}

function getLinkTypeInfoHTMLStr(DevType, AccessMode) {
    var str = '';
    str = '<div class=' + DevType + ' style="float:left; text-align: center; margin-top: 28px; width:60px; padding: 0px 6px;">'
        + '<div' + '" style="margin-top: 6px;width: 60px;word-wrap:break-word;">'+ AccessMode +'</div>'
    return str;
}

function getLanPortHTMLStr(IndexID, lanport, MAC) {
    var str = '';
    var backgroudColor = "#ffffff";
    str = '<div id=' + IndexID + ' style="float:left; cursor: pointer; width: 65px;height: auto; margin: 5px 20px 5px 5px; background: ' + backgroudColor +'"">'
        + getStrBaseLanPortNum(lanport, mac2Str(MAC))
        + '</div>';
    return str;
}

function getDevInfoHTMLStr(DevType, MAC) {
    var str = '';
    str = '<div class="secondDevType_Info" style="float:left; margin-top: 23px;width:145px;">'
        + '<div style="align-items: center";>'+ DevType + '</div>'
        + '<div>'+ "MAC:"+ MAC +'</div>'
        + '</div>';
    return str;
}

function getChildHTMLStr(childId, contentHeiLine) {
    var str = '';
    str ='<div class="firstConnectLine" id="thirdConnectLine"></div>'
        + '<div style="float:left; left:388px; top:0px;" class="divPosition">'
        + '<div class="secondStructLine StructLineClass" id="' + contentHeiLine + '" style="width:2px; background-color:#d3d3d3; float: left; margin-top: 35px;"></div>'
        + '<div class="getSecondLineHei" id="' + childId + '" style="float:left; position: absolute;min-width: 400px;"></div>'
        + '</div>';
    return str;
}

function setHeightBaseLanPort(lanport, indexID) {
    var ssssHeigh = 70 + (lanport - 2) * 30;
    if (ssssHeigh < 70) {
        $('#lanport_' + indexID).css('margin-top', '20px');
        $('#' + indexID).height(70);
        return 70;
    } else {
        $('#' + indexID).height(ssssHeigh);
    }
    return ssssHeigh;
}

var leverMap = ['Second_', '_Third_', '_fourth_'];
function AppendDevInfoFunc(ParentId, DevDateArray, level) {
    if (level > 4) {
        return 0;
    }
    var lastDivIndex = 0;
    for(var index in DevDateArray) {
        var DevType = DevDateArray[index].DevType					
        var AccessType = DevDateArray[index].AccessType;
        var AccessMode = "";
        var childId = "";
        AccessMode = judgeAcessType(AccessType);

        var i = 0;
        var indexID = ParentId + leverMap[level - 1] + index;
        if ((level == 1) && (index == DevDateArray.length -1)) {
            SecondLastDiv = indexID;
        }
        var controlHei = ParentId + leverMap[level - 1] + index + "_Child";
        var secondContentHeiLine = ParentId + leverMap[level - 1] + index + "_Line" + i;
        i++;
        var parentHei = leverMap[level - 1] + index;
        var MAC = DevDateArray[index].MAC.toUpperCase();
        if (level == 1 && !isShowInTopo(mac2Str(MAC))){
            continue;
        }

        var APInst = DevDateArray[index].APInst;
        var DuplexMode = DevDateArray[index].DuplexMode;
        var SecondSpeedInfoStr = "";
        var lanport = getLanPort(mac2Str(MAC));
        if (lanport == 0) {
            continue;
        }
        setDisplay('ConnectLineShow', 1);
        if (ParentId == '') {
            SecondSpeedInfoStr += '<div class="ssss ssss_'+ DevType + '" id="' + indexID + '" style="position: relative;width: 405px;">';
        } else {
            SecondSpeedInfoStr += '<div class="sssDDDDs ssss_'+ DevType + '" id="' + indexID + '" style="position: relative;width: 405px;">';
        }
        SecondSpeedInfoStr += '<div class="firstConnectLine"  style="float:left;"></div>';
        SecondSpeedInfoStr += getLinkTypeInfoHTMLStr('secondAccessType_' + DevType, AccessMode);
        SecondSpeedInfoStr += '<div class="firstConnectLine" id="connectLine" style="float:left;"></div>';
        SecondSpeedInfoStr += getLanPortHTMLStr('lanport_' + indexID, lanport, MAC);
        SecondSpeedInfoStr += getDevInfoHTMLStr(DevType, MAC);

        if(DevDateArray[index].sub != undefined){
            childId = indexID + '_Child';
            SecondSpeedInfoStr += getChildHTMLStr(childId, secondContentHeiLine);
        }
        SecondSpeedInfoStr +='</div>';
        if (ParentId == '') {
            $("#secondOntStruct").append(SecondSpeedInfoStr);
        } else {
            $("#" + ParentId).append(SecondSpeedInfoStr);
        }

        if (DevType === 'STA' && AccessType !== 'G.hn') {
            $(".ssss_" + DevType).css('display','none');
        }
        
        var heig = setHeightBaseLanPort(lanport, indexID);
        
        if(DevDateArray[index].sub != undefined){
            nextLevelDevArray = DevDateArray[index].sub;
            var nextLeverLastIndex = AppendDevInfoFunc(childId, nextLevelDevArray, level + 1);
            var setHei = $('#' + controlHei).height();
            if (setHei > heig) {
                if (level == 1) {
                    $('#' + controlHei).parents('.ssss').css("height", setHei + "px");
                } else {
                    $('#' + controlHei).parents('.sssDDDDs').css("height", setHei + "px");
                }
            } 
            var lastSecondHei = $('#' + childId + leverMap[level] + (nextLeverLastIndex - 1)).height();
            setHei  = setHei - lastSecondHei;
            $('#' + secondContentHeiLine).css("height", setHei + "px");
        }
        
        lastDivIndex++;
    }

    return lastDivIndex;
}

function AppendSecondDevInfoOffFunc() {
    var SecondLastDivIndex = -1;
    if (SecondLastDiv !== '') {
        SecondLastDivIndex = SecondLastDiv.split("_")[1];
    }
    for(var SecondIndex = 0; SecondIndex < offLineApList.length; SecondIndex++) {
        var AccessType = (offLineApList[SecondIndex].UplinkType == "PON") ? "FTTR" : offLineApList[SecondIndex].UplinkType;
        var SecondChildId = "";
        SecondLastDivIndex++;
        var DevType = offLineApList[SecondIndex].type;

        var SecondIndexID = "Second_" + SecondLastDivIndex;
        if (SecondIndex == offLineApList.length -1) {
            SecondLastDiv = SecondIndexID;
        }

        var MAC = offLineApList[SecondIndex].APMacAddr.toUpperCase();
        if (!isShowInTopo(mac2Str(MAC))){
            continue;
        }

        var SecondOfflineStr = "";
        var lanport = getLanPort(mac2Str(MAC));
        if (lanport == 0) {
            continue;
        }
        setDisplay('ConnectLineShow', 1);
        SecondOfflineStr += '<div class="ssss"  id="' + SecondIndexID + '" style="position: relative;">'
                           + '<div class="firstConnectLine"  style="float:left;"></div>';
        SecondOfflineStr += getLinkTypeInfoHTMLStr('apOffLineText', AccessType + lanservicecfg_language['bbsp_lanservice_ap_offline']);
        SecondOfflineStr += '<div class="firstConnectLine" id="connectLine" style="float:left;"></div>'
        SecondOfflineStr += getLanPortHTMLStr('lanport_' + SecondIndexID, lanport, MAC);
        SecondOfflineStr += getDevInfoHTMLStr(DevType, MAC);
        SecondOfflineStr +='</div>';
        $("#secondOntStruct").append(SecondOfflineStr);

        setHeightBaseLanPort(lanport, SecondIndexID);
    }
}

var MenuJsonData = "";
$.ajax({
    type : "POST",
    async : true,
    cache : false,
    url : "../../amp/wificoverinfo/getTopoInfo.asp",
    success : function(data) {
        MenuJsonData = eval(data);
        setTimeout('showMainPage()', 500);
    }
});

function initSTBPort() {
    for (var i = 0; i < APSetInfoList.length - 1; i++) {
        var lanportList = APSetInfoList[i].StbPort.split(',');
        for (var j = 0; j < lanportList.length; j++) {
            setSTBEnable(mac2Str(APSetInfoList[i].Mac) + '_' + lanportList[j]);
        }
    }
}

function showMainPage() {
    setDisplay('DivWifiCoverText', 0);
    setDisplay('divApContralScrool', 1);
    if (curWebFrame == 'frame_UNICOM') {
        getElementById('divApContralScrool').style.width = '112%';
        getElementById('divApContralScrool').style.minHeight = '310px';
    }
    AppendFirstDevInfoFunc(MenuJsonData);
    initSTBPort();

    if (rosunionGame == 1) {
        $(".ApLevelStruct").css("background-color", "#001c45");
        $('.ApContralScrool').css("background-color", "#001c45");
    }
}
</script>
</head>
<body  class="mainbody nomargin" onload="LoadFrame();">
    <form id="LANPortConfigForm" style="display:block">
        <table id="table_LANPortInfo" width="100%" border="0" align="center" cellpadding="0" cellspacing="1" > 
            <tr id="LANPortID" class='align_left'> 
            <td class="LanBg">
                <div id="Div_LAN1"> 
                    <input type="checkbox" id="LAN1" name="cb_Lan1" value="LAN1" onClick="checkboxfunc();">LAN1</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN2"> 
                    <input type="checkbox" id="LAN2" name="cb_Lan2" value="LAN2" onClick="checkboxfunc();">LAN2</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN3"> 
                    <input type="checkbox" id="LAN3" name="cb_Lan3" value="LAN3" onClick="checkboxfunc();">LAN3</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN4"> 
                    <input type="checkbox" id="LAN4" name="cb_Lan4" value="LAN4" onClick="checkboxfunc();">LAN4</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN5"> 
                    <input type="checkbox" id="LAN5" name="cb_Lan5" value="LAN5" onClick="checkboxfunc();">LAN5</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN6"> 
                    <input type="checkbox" id="LAN6" name="cb_Lan6" value="LAN6" onClick="checkboxfunc();">LAN6</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN7"> 
                    <input type="checkbox" id="LAN7" name="cb_Lan7" value="LAN7" onClick="checkboxfunc();">LAN7</input>
                </div> 
            </td>
            <td class="LanBg">
                <div id="Div_LAN8"> 
                    <input type="checkbox" id="LAN8" name="cb_Lan8" value="LAN8" onClick="checkboxfunc();">LAN8</input>
                </div> 
			</td>
            <td class="LanBg">
                <div id="Div_PON1"> 
                    <input type="checkbox" id="PON1" name="cb_pon1" value="PON1" onClick="checkboxfunc();">FTTR</input>
                </div> 
            </td>
            </tr>
            <script>
                var EthNum = TopoInfo.EthNum;
                for (var i = 1; i <= 8; i++) {
                    if (E8CRONGHEFlag == 1) {
                        setDisplay("Div_LAN"+3, 0);
                    }

                    if (i > EthNum) {
                        setDisplay("Div_LAN"+i, 0);
                    }
                }
                if(fttrmain == '0') {
                    setDisplay("Div_PON1", 0);
                }
            </script>
		</table>

		<table id="table_SSIDPortInfo" width="100%" border="0" align="center" cellpadding="0" cellspacing="1" > 
		  <tr id="SSIDPortID" class='align_left'> 
			<td class="LanBg">
				<div id="Div_SSID1"> 
					<input type="checkbox" id="SSID1" name="cb_Ssid1" value="SSID1" onClick="checkboxfunc();">SSID1</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID2"> 
					<input type="checkbox" id="SSID2" name="cb_Ssid2" value="SSID2" onClick="checkboxfunc();">SSID2</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID3"> 
					<input type="checkbox" id="SSID3" name="cb_Ssid3" value="SSID3" onClick="checkboxfunc();">SSID3</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID4"> 
					<input type="checkbox" id="SSID4" name="cb_Ssid4" value="SSID4" onClick="checkboxfunc();">SSID4</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID5"> 
					<input type="checkbox" id="SSID5" name="cb_Ssid5" value="SSID5" onClick="checkboxfunc();">SSID5</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID6"> 
					<input type="checkbox" id="SSID6" name="cb_Ssid6" value="SSID6" onClick="checkboxfunc();">SSID6</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID7"> 
					<input type="checkbox" id="SSID7" name="cb_Ssid7" value="SSID7" onClick="checkboxfunc();">SSID7</input>
				</div> 
			</td>
			<td class="LanBg">
				<div id="Div_SSID8"> 
					<input type="checkbox" id="SSID8" name="cb_Ssid8" value="SSID8" onClick="checkboxfunc();">SSID8</input>
				</div> 
			</td>
          </tr>
		  <script>
		  var SSIDNum = self.parent.TopoInfo.SSIDNum;
		  var i;
		  for (i = 1; i <= 8; i++)
		  {
			  if (i > SSIDNum)
			  {
				setDisplay("Div_SSID"+i, 0);
			  }
		  }
		  </script>
		</table>
		<script>
			var UsbConfigFormList = HWGetLiIdListByForm("LANPortConfigForm", null);
			var TableClass = new stTableClass("width_per25", "width_per75", "ltr");
			HWParsePageControlByID("LANPortConfigForm", TableClass, lanservicecfg_language, null);
		</script>
		<table width="100%" border="0" cellspacing="1" cellpadding="0" class="table_button">
			<tr>
				<script language="JavaScript" type="text/javascript">
					if (window.parent.isGuidePage) {
						document.write('<td class="table_submit width_per40"></td>');
					} else {
						document.write('<td class="table_submit width_per30"></td>');
					}
				</script>
				<td class="table_submit" id="btlanportapply">
					<button type="button" name="btnLANPortApply"  id="btnLANPortApply"  class="ApplyButtoncss  buttonwidth_100px" onClick='LANPortSubmit()'><script>document.write(lanservicecfg_language['bbsp_lanservice_lanportapply']);</script></button> 
					<button type="button" name="btnLANPortCancle" id="btnLANPortCancle" class="CancleButtonCss buttonwidth_100px" onClick='LANPortCancle()'><script>document.write(lanservicecfg_language['bbsp_lanservice_lanportcancle']);</script></button> 
				</td>
			</tr>
		</table>
	</form>
	<br><br>
	<div id="div_APInfo">
		<div id="ChooseApHeadID" style="display:block">
			<table width="100%" height="0" border="0" cellpadding="0" cellspacing="0">
				<script language="JavaScript" type="text/javascript">
				if (window.parent.isGuidePage == 1) {
					document.write('<div id="APInfo" class="PageTitle">');
					document.write('<div id="APInfo_title" class="PageTitle_title">' + lanservicecfg_language["bbsp_lanservice_choose_apcfg"] + '</div>');
					document.write('<div id="APInfo_content" class="PageTitle_content">' + lanservicecfg_language["bbsp_lanservice_choose_ap_note4"] + '</div></div>');
				} else {
					var apnote = lanservicecfg_language['bbsp_lanservice_choose_ap_note5'];
					var LanServiceSummaryArray = new Array( new stSummaryInfo("text",GetDescFormArrayById(lanservicecfg_language, "bbsp_lanservice_choose_ap_title1")),
														new stSummaryInfo("img","../../../images/icon_01.gif", GetDescFormArrayById(lanservicecfg_language, "bbsp_lanservice__note")),
														new stSummaryInfo("text",apnote),
											null);
					HWCreatePageHeadInfo("APInfo", lanservicecfg_language["bbsp_lanservice_choose_ap_note2"], LanServiceSummaryArray, true);
				}
			   </script>
			</table>
		</div>

        <div id='DivWifiCoverText' style='font-size:14px;'>
            <script>document.write(lanservicecfg_language['bbsp_lanservice_loading_text']);</script>
        </div>
		<div id='divApContralScrool' class="ApContralScrool" style="width:100%; min-height:300px; background-color: #f6f6f6; overflow: auto; direction:ltr; display: none;font-size: 12px;">
            <div class="ApLevelStruct">
                <div class="firstOntStruct"  id="firstOntStruct" style="margin-left: 5px;">
                    <div class="firstOntIcon" id="firstOntIcon"></div>
                    <div class="firstMountDevType" id="firstMountDevInfo"></div>
                    <div class="firstConnectLine" id="ConnectLineShow" style = 'display:none;'></div>
                    <div id="apNumDiv" style="margin-top:80px;font-size:16px;display:none;">
                        <script>document.write(lanservicecfg_language['bbsp_lanservice_ap_num1']);</script>
                        <span id="onLineApNum" style="font-weight: bold;"></span>
                        <script>document.write(lanservicecfg_language['bbsp_lanservice_ap_num2']);</script>
                        <span id="offLineApNum" style="font-weight: bold;"></span> 
                    </div>
                </div>

                <div class="secondOntStruct" id="secondOntStructId">
                    <div class="secondStructLine" id="secondStructLine" style="width:2px; background-color:#d3d3d3; float:left; margin-top: 35px;"></div>
                    <div id="secondOntStruct" style="float:left;"></div>
                </div>
                
                <div style="float:left;">
                    <div id="secondOntStructTHIRD" style="float:left"></div>
                </div>	
            </div>
		</div>

        <table cellpadding="0" cellspacing="0" width="100%" class="table_button">
            <tr>
                <td class='width_per30'></td>
                <td class="table_submit">
                    <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
                    <button id='btnApply_ex' name="btnApply_ex" class="ApplyButtoncss buttonwidth_100px" type="button" onClick="SubmitEx();">
                        <script>document.write(lanservicecfg_language['bbsp_lanservice_iptvupapply']);</script>
                    </button>
                    <button id='Cancel' name="cancel" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelValue();">
                        <script>document.write(lanservicecfg_language['bbsp_lanservice_iptvupcancle']);</script>
                    </button>
                </td>
            </tr>
            <tr>
                <td style="display:none"> <input type='text'> </td> 
            </tr>
      </table> 
	</div>

    <script type="text/javascript">	
        var setHeightTime= setInterval("ControlHeight();",500);
        var SecondLastDiv ='';
        var thirdLastDivIndex = 0;
        var fourthLastDivIndex = 0;
        function ControlHeight(){
            var TranverseLineHeight = $('#secondOntStructId').height() + 2;
            var lastDiv = $('.ssss');
            var lastDivheight = $(lastDiv[lastDiv.length - 1]).outerHeight();
            TranverseLineHeight -= lastDivheight;
            var ApContralHei = $('#secondOntStructId').height() + 100;
            $('#secondStructLine').css("height", TranverseLineHeight+"px");
            $('.ApContralScrool').css("height", ApContralHei+"px");
            if (0 == $('#secondStructLine').height()){
                $('#secondStructLine').css("width","0px");	
            } else {
                $('#secondStructLine').css("width","2px");
            }
        }
    </script>
	 
	<script>
		if (window.parent.isGuidePage) {
			document.write('<table cellpadding="0" cellspacing="0" width="100%" >');
			document.write('<tr ><td class="table_submit width_per40"></td>');

			if ((window.parent.fttrmainflag == 1) && (window.parent.curUserType == 0)) {
				if ((IsCTRG == 1) && (currentBin.toUpperCase() != "COMMON")) {
					document.write('<td class="table_submit"' + '<input type="hidden" name="gd_onttoken" id="gd_hwonttoken" value="<%HW_WEB_GetToken();%>">');
					document.write('<input id="guidewificfg" type="button" class="CancleButtonCss buttonwidth_100px" style="margin-left:0px;" BindText="" name="/html/amp/wlanbasic/guidewificfg.asp?cfgguide=1" onClick="top.onchangestep(this);">');
					getElById('guidewificfg').value = lanservicecfg_language['bbsp_lanservice_prestep'];
					document.write('<input id="bbsp_skip" type="button" class="CancleButtonCss buttonwidth_100px"  BindText="" name="/html/ssmp/bss/guidebssinfo.asp" onClick="guideSkip(this);"></td></tr></table>');
					getElById('bbsp_skip').value = lanservicecfg_language['bbsp_lanservice_guideover'];
				} else {
					document.write('<td class="table_submit"' + '<input type="hidden" name="gd_onttoken" id="gd_hwonttoken" value="<%HW_WEB_GetToken();%>">');
					document.write('<input id="guidewancfg" type="button" class="CancleButtonCss buttonwidth_100px" style="margin-left:0px;" BindText="" name="/html/bbsp/wan/wan.asp?cfgguide=1" onClick="top.onchangestep(this);">');
					getElById('guidewancfg').value = lanservicecfg_language['bbsp_lanservice_prestep'];
					document.write('<input id="guidecfgdone" type="button" class="ApplyButtoncss buttonwidth_100px" BindText="" name="/html/ssmp/bss/guidebssinfo.asp" onClick="guideNext(this);">');
					document.write('<input id="bbsp_skip" type="button" class="CancleButtonCss buttonwidth_100px"  BindText="" name="/html/ssmp/bss/guidebssinfo.asp" onClick="guideSkip(this);"></td></tr></table>');
					getElById('guidecfgdone').value = lanservicecfg_language['bbsp_lanservice_nexttep'];
					getElById('bbsp_skip').value = lanservicecfg_language['bbsp_lanservice_skip'];
				}
			} else {
				document.write('<td class="table_submit"' + '<input type="hidden" name="gd_onttoken" id="gd_hwonttoken" value="<%HW_WEB_GetToken();%>">');
				document.write('<input id="guidesyscfg" type="button" class="CancleButtonCss buttonwidth_100px" style="margin-left:0px;" BindText="" name="/html/ssmp/accoutcfg/guideaccountcfg.asp" onClick="top.onchangestep(this);">');
				getElById('guidesyscfg').value = lanservicecfg_language['bbsp_lanservice_prestep'];
				document.write('<input id="guidecfgdone" type="button" class="ApplyButtoncss buttonwidth_100px" BindText="" name="/html/ssmp/cfgguide/userguidecfgdone.asp" onClick="onindexpage(this);">');
				document.write('<input id="bbsp_skip" type="button" class="CancleButtonCss buttonwidth_100px"  BindText="" name="/html/ssmp/cfgguide/userguidecfgdone.asp" onClick="onindexpage(this);"></td> </tr></table>');
				getElById('guidecfgdone').value = lanservicecfg_language['bbsp_lanservice_nexttep'];
				getElById('bbsp_skip').value = lanservicecfg_language['bbsp_lanservice_skip'];
			}
		}
	</script>
</body>
</html>