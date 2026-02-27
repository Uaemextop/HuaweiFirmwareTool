<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<title>自检结果</title>

<style type="text/css">
.prompt { position:absolute; top:0px;left:0px;width:96%;height:40px;;border:0px; }
body, td, div, textarea, input, select {
	font-family: "Arial", "";
	font-size: 12px;
}

.table_title{
	background-color: #E7E7E7;
	padding-left: 5px;
	line-height: 22px;
	font-weight: bold;
}

.table_left {
	background-color: #E7E7E7;
	padding-left: 5px;
	height: 24px;
	line-height: 22px;
	font-weight: bolder;
}
.table_right {
	background-color: #FFFFFF;
	padding-left: 5px;
	height: 24px;
	line-height: 22px;
}

.table_head {
	background-color:#C7C7C7;
	font-size: 20px;
	font-weight: bold;
	padding-left: 5px;
	height: 30px;
	line-height: 30px;
}

</style>

<script language="JavaScript" type="text/javascript">
var CurrentBin = '<%HW_WEB_GetBinMode();%>';
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
var SelfCheck = '<%HW_WEB_GetFeatureSupport(FT_SUPPORT_FRAME_DETECTION);%>';
var cpuUsed = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.X_HW_CpuUsed);%>%';
var memUsed = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.X_HW_MemUsed);%>%';
var stbport = '<%HW_WEB_GetSTBPort();%>';
var TianYiFlag = '<%HW_WEB_GetFeatureSupport(FT_AMP_ETH_INFO_TIANYI);%>';
var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';
var jiuzhouFlag = '<%WEB_GetJiuZhouFlag();%>';
function isPortInAttrName()
{
    if((1 == TianYiFlag) && ('E8C' == CurrentBin.toUpperCase()))
	{
		return true;
	}
	return false;
}
function SetFamliyNetworkDisplay()
{
	$("#Table_base12_1_tr").css("display","none");
	$("#Table_base13_1_tr").css("display","none");
	$("#Table_base14_1_tr").css("display","none");
}

function LoadFrame()
{
	if (SelfCheck != 1)
	{
		window.location="/login.asp";
	}
	
	if ((CfgMode.toUpperCase() != 'SCCT') && (CfgMode.toUpperCase() != 'BJCT') && (CfgMode.toUpperCase() != 'TJCT') &&
		(CfgMode.toUpperCase() == "SCSCHOOL"))
	{
		SetFamliyNetworkDisplay();
	}
}
function stDeviceInfo(domain,HardwareVersion,SoftwareVersion,ModelName)
{
	this.domain 			= domain;
	this.HardwareVersion 	= HardwareVersion;		
	this.SoftwareVersion 	= SoftwareVersion;
	this.ModelName 		    = ModelName;
}
function ONTInfo(domain,ONTID,Status)
{
	this.domain 		= domain;
	this.ONTID			= ONTID;
	this.Status			= Status;
}
function stResultInfo(domain, Result, Status, InformStatus)
{
	this.domain = domain;
	this.Result = Result;
	this.Status = Status;
    this.InformStatus	= InformStatus;
}
function OpticInfo(domain,transOpticPower,revOpticPower,temperature)
{
    this.Domain = domain;
	this.TransOpticPower = transOpticPower;
	this.RevOpticPower = revOpticPower;
	this.Temperature = temperature;
}
function GEInfo(domain,Status)
{
	this.domain		= domain;
	if(Status==0)this.Status = "未连接";
	if(Status==1)this.Status = "已连接";
}



function WANPara()
{
	this.domain 	= null;
	this.status 	= "";			
	this.ip			= "";
    this.serviceList = "INTERNET";
    this.modeType = "";
	this.Enable = 1;
	this.MacId = "0";
	this.IPv4Enable = "1";
    this.IPv6Enable = "0";
	this.ConnectionTrigger = "";
	this.ConErr = "";
	this.ConnectionControl = "";
	this.EncapMode    = "IPoE";
}


function IPWANPara(domain,status,ip,serviceList,ExServiceList,modeType,enable,Tr069Flag,MacId,IPv4Enable,IPv6Enable,ConnectionTrigger,ConErr)
{
	this.domain 	= domain;
	this.status 	= status;			
	this.ip			= ip;
    this.serviceList = (ExServiceList.length == 0)?serviceList:ExServiceList;
    this.modeType = modeType;
	this.Enable = enable;
	this.Tr069Flag = Tr069Flag;
	this.MacId = MacId;
	this.IPv4Enable = IPv4Enable;
    this.IPv6Enable = IPv6Enable;
	this.ConnectionTrigger = ConnectionTrigger;
	this.ConErr = ConErr;
}

function PPPWANPara(domain,status,ip,serviceList,ExServiceList,modeType,enable,Tr069Flag,MacId,IPv4Enable,IPv6Enable,ConnectionTrigger,ConErr,ConnectionControl)
{
	this.domain 	= domain;
	this.status 	= status;			
	this.ip			= ip;
    this.serviceList = (ExServiceList.length == 0)?serviceList:ExServiceList;
    this.modeType = modeType;
	this.Enable = enable;
	this.Tr069Flag = Tr069Flag;
	this.MacId = MacId;
	this.IPv4Enable = IPv4Enable;
    this.IPv6Enable = IPv6Enable;
	this.ConnectionTrigger = ConnectionTrigger;
	this.ConErr = ConErr;
	if (parseInt(ConnectionControl, 10) == 0xFFFFFFFF )
    {
        this.ConnectionControl = 0;
    }
    else
    {
        this.ConnectionControl = ConnectionControl;
    }
}


function ConvertIPWan(IPWan, WANPara)
{
	WANPara.domain 	= IPWan.domain;
	WANPara.status 	= IPWan.status;			
	WANPara.ip			= IPWan.ip;
    WANPara.serviceList = IPWan.serviceList;
    WANPara.modeType = IPWan.modeType;
	WANPara.Enable = IPWan.Enable;
	WANPara.MacId = IPWan.MacId;
	WANPara.IPv4Enable = IPWan.IPv4Enable;
    WANPara.IPv6Enable = IPWan.IPv6Enable;
	WANPara.ConnectionTrigger = "AlwaysOn";
	WANPara.ConErr = "";
	WANPara.EncapMode    = "IPoE";
}

function ConvertPPPWan(PPPWan, WANPara)
{
	WANPara.domain 	= PPPWan.domain;
	WANPara.status 	= PPPWan.status;			
	WANPara.ip			= PPPWan.ip;
    WANPara.serviceList = PPPWan.serviceList;
    WANPara.modeType = PPPWan.modeType;
	WANPara.Enable = PPPWan.Enable;
	WANPara.MacId = PPPWan.MacId;
	WANPara.IPv4Enable = PPPWan.IPv4Enable;
    WANPara.IPv6Enable = PPPWan.IPv6Enable;
	WANPara.ConnectionTrigger = PPPWan.ConnectionTrigger;
	WANPara.ConErr = PPPWan.ConErr;
	WANPara.ConnectionControl = PPPWan.ConnectionControl;
	WANPara.EncapMode    = "PPPoE";
}



function IPv6AddressInfo(domain, IPAddressStatus, Origin,IPAddress,PreferredTime,
                        ValidTime,ValidTimeRemaining)
{
    this.WanInstanceId = domain.split(".")[4];
    this.IPAddressStatus = IPAddressStatus;
    this.Origin = Origin;
    this.IPAddress = IPAddress;
	this.PreferredTime = PreferredTime;
	this.ValidTime = ValidTime;
	this.ValidTimeRemaining = ValidTimeRemaining;
}

function IPv6WanInfo(domain, Type, ConnectionStatus, L2EncapType, MACAddress, Vlan, Pri,
                     DNSServers, AFTRName, AFTRPeerAddr,DefaultRouterAddress,V6UpTime)
{
    this.WanInstanceId = domain.split(".")[4];
    this.Type = Type;
    this.ConnectionStatus = ConnectionStatus;
    this.L2EncapType = L2EncapType;
    this.MACAddress = MACAddress;
    this.Vlan = Vlan;
    this.Pri = Pri;
	this.DNSServers = DNSServers;
	this.AFTRName = AFTRName;
	this.AFTRPeerAddr = (AFTRPeerAddr=="::")?"":AFTRPeerAddr;
	this.DefaultRouterAddress = DefaultRouterAddress;
    this.V6UpTime = V6UpTime;
}

function FrameInfo(domain,DetectionsState,ResultNumber,ResultTotal,ResultTotalEx)
{  
    this.domain   = domain;
    this.state    = DetectionsState;
    this.number   = ResultNumber;
	this.result   = ResultTotal;
	this.resultex   = ResultTotalEx;
}
function DevFrameInst(mac, lostrate, delay, jetter)
{  
    this.mac        = mac;
    this.lostrate   = lostrate;
    this.delay      = delay;
	this.jetter     = jetter;
}


function stPhyInterface(Domain, InterfaceID, X_HW_Status )
{
    this.Domain = Domain;
	this.InterfaceID = InterfaceID;
	this.X_HW_Status = X_HW_Status;
}

var deviceInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, HardwareVersion|SoftwareVersion|ModelName, stDeviceInfo);%>;
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
var ontInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.ONT,Ontid|State,ONTInfo);%>;
var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|X_HW_InformStatus, stResultInfo);%>;
if(null != stResultInfos && null != stResultInfos[0])
{
	var Infos = stResultInfos[0];
}
else
{
	var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo","99","99","1"),null);
	var Infos = stResultInfos[0];
}

var ontEPONInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.OAM.ONT,Ontid|State,ONTInfo);%>;
var OpticInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic,TxPower|RxPower|Temperature, OpticInfo);%>; 
var wlanEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.X_HW_WlanEnable);%>';
var geInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig,Link,GEInfo);%>;
var FrameInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo.X_HW_Framedetection, DetectionsState|ResultNumberOfEntries|ResultTotal|ResultTotalEx,FrameInfo);%>;
var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i},ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|X_HW_ExServiceList|ConnectionType|Enable|X_HW_TR069FLAG|X_HW_MacId|X_HW_IPv4Enable|X_HW_IPv6Enable|ConnectionTrigger|LastConnectionError,IPWANPara);%>;
var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i},ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|X_HW_ExServiceList|ConnectionType|Enable|X_HW_TR069FLAG|X_HW_MacId|X_HW_IPv4Enable|X_HW_IPv6Enable|ConnectionTrigger|LastConnectionError|X_HW_ConnectionControl,PPPWANPara);%>;
var IPv6WanInfoList =  <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_GetIPv6WanInfo, InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.{i},Type|ConnectionStatus|L2EncapType|MACAddress|Vlan|Pri|IPv6DNS|AFTRName|PeerAddress|DefaultRouterAddress|V6UpTime,IPv6WanInfo);%>;
var IPv6AddressList =  <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_GetIPv6Address, InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.{i}.IPv6Address.{i},IPAddressStatus|Origin|IPAddress|PreferredTime|ValidTime|ValidTimeRemaining,IPv6AddressInfo);%>;
var AllPhyInterface = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.PhyInterface.{i},InterfaceID|X_HW_Status,stPhyInterface);%>;


var Wan = new Array();
var i=0 , j=0; 

 for ( i=0 , j=0; WanIp.length > 1 && j < WanIp.length - 1; j++ , i++)
{
	if("1" == WanIp[j].Tr069Flag )
	{
		i--;
		continue;
	}
	Wan[i] = new WANPara();
	ConvertIPWan(WanIp[j], Wan[i])
}
	
for ( j=0; WanPpp.length > 1 && j<WanPpp.length - 1; i++ , j++)
{
	if("1" == WanPpp[j].Tr069Flag )
	{
		i--;
		continue;
	}
	Wan[i] = new WANPara();
	ConvertPPPWan(WanPpp[j], Wan[i])
}

var DevFrameArray = new Array();
var state = false;
if (FrameInfos.length > 1)
{
    if (FrameInfos[0].state == "Complete")
	{		
		var Idx = 0;
		var records = FrameInfos[0].result.split('-');
		for (var i = 0; i < records.length; i++)
	    {
		    var temp = records[i].split(':');
	        if (temp.length != 9)
			{
			    continue;
			}
			
		    DevFrameArray[Idx] = new DevFrameInst(temp[0] + ":"+ temp[1] + ":" + temp[2] + ":" + temp[3] +":" + temp[4] +":"+ temp[5], temp[6], temp[7], temp[8]);
			Idx++;
		}
		state =  true;
	}
}

var recordsex = FrameInfos[0].resultex.split('-');
var minRcd;
for (var i = 0; i < recordsex.length; i++)
{
	var temp1 = recordsex[i].split(':');
	if (temp1.length != 10)
	{
		continue;
	}
	for (var j = i+1; j < recordsex.length; j++)
	{
		var temp2 = recordsex[j].split(':');
		if (temp2.length != 10)
		{
			continue;
		}
		
		if (temp1[6] > temp2[6])
		{
			minRcd = recordsex[i];
			recordsex[i] = recordsex[j];
			recordsex[j] = minRcd;
		}
	}
}

function getLanDescByDevFrameIdx(idx)
{
	for (var i = 0; i < recordsex.length; i++)
	{
		if (i != idx)
		{
			continue;
		}

		var temp = recordsex[i].split(':');
		if (temp.length != 10)
		{
			continue;
		}
		
		var lanx = temp[6];
		if (lanx.substr(0, 3) == "Lan")
		{
			var lanid = parseInt(lanx.substr(3));
			return getlandesc(lanid);
		}
	}
	
	return "";
}

function FrameDetectLostInfo()
{
	var output = "";
	var landesc = "";
	if(( false == state ) || (DevFrameArray.length == 0))
	{
		output = output + "--";
	}
	else
	{
		for( i = 0; i < DevFrameArray.length; i++)
		{
			landesc = getLanDescByDevFrameIdx(i);
			if ((landesc == "内置STB") && (E8CRONGHEFlag == 1))
			{
				continue;
			}
            
			output = output + DevFrameArray[i].mac + "  " + DevFrameArray[i].lostrate+ "%";
			if( i < DevFrameArray.length - 1 )
			{
				output = output + "&nbsp;&nbsp;-<br>";
			}  else {
                output = output + "-";
            }
		}
        
		output = output.substring(0,output.lastIndexOf('-'));
	}
	document.write(output);
}

function FrameDetectDelayInfo()
{
	var output = "";
	var landesc = "";
	if(( false == state ) || (DevFrameArray.length == 0))
	{
		output = output + "--";
	}
	else
	{
		for( i = 0; i < DevFrameArray.length; i++)
		{
			landesc = getLanDescByDevFrameIdx(i);
			if ((landesc == "内置STB") && (E8CRONGHEFlag == 1))
			{
				continue;
			}
            
			output = output + DevFrameArray[i].mac + "  " + DevFrameArray[i].delay+ "毫秒";
			if( i < DevFrameArray.length - 1 )
			{
				output = output + "&nbsp;&nbsp;-<br>";
			}  else {
                output = output + "-";
            }
		}
        
		output = output.substring(0,output.lastIndexOf('-'));
	}
	document.write(output);
}

function FrameDetectJetterInfo()
{
	var output = "";
	var landesc = "";
	if(( false == state ) || (DevFrameArray.length == 0))
	{
		output = output + "--";
	}
	else
	{
		for( i = 0; i < DevFrameArray.length; i++)
		{
			landesc = getLanDescByDevFrameIdx(i);
			if ((landesc == "内置STB") && (E8CRONGHEFlag == 1))
			{
				continue;
			}
            
			output = output + DevFrameArray[i].mac + "  " + DevFrameArray[i].jetter + "毫秒";
			if( i < DevFrameArray.length - 1 )
			{
				output = output + "&nbsp;&nbsp;-<br>";
			} else {
                output = output + "-";
            }
		}
        
		output = output.substring(0,output.lastIndexOf('-'));
	}
	document.write(output);
}
	
var deviceInfo = deviceInfos[0];
var ontInfo = ontInfos[0];
var ontEPONInfo = ontEPONInfos[0];
var OpticInfo = OpticInfoList[0];

var UserDevInfo;

function OltRegStatusInfo()
{
	if (ontPonMode == 'gpon' || ontPonMode == 'GPON')
	{ 

		if ((ontInfo != null) && (ontInfo.Status == 'o5AUTH' || ontInfo.Status == 'O5AUTH'))
		{
			document.write("注册失败 ");
		}
		else if ((ontInfo != null) && (ontInfo.Status == 'o5' || ontInfo.Status == 'O5'))
		{
			document.write("已注册");
		}
		else
		{
			document.write("未注册");
		}
	}
	else if (ontPonMode == 'epon' || ontPonMode == 'EPON')
	{
		if (ontEPONInfo != null)
		{
			if ( "OFFLINE" == ontEPONInfo.Status)
			{
				document.write("未注册");
			}
			else if("ONLINE" == ontEPONInfo.Status)
			{
				document.write("已注册");
			}
			else
			{
				document.write("注册失败");
			}
		}
		else
		{
			document.write(''); 
		}
	}
	else
	{
		document.write('');
	}	
}
function IsPonOnline()
{
    if (ontPonMode.toUpperCase() != 'GPON' && ontPonMode.toUpperCase() != 'EPON') return true;
	if (ontPonMode.toUpperCase() == 'GPON' && (ontInfo != null) && (ontInfo.Status.toUpperCase() == 'O5'))  return true;
	if (ontPonMode.toUpperCase() == 'GPON' && ontInfo.Status.toUpperCase() == 'O5AUTH')  return true;
	if (ontPonMode.toUpperCase() == 'EPON' && (ontEPONInfo != null) && (ontEPONInfo.Status.toUpperCase() == 'ONLINE')) return true;
	return false;
}

function ItmsRegStatusInfo()
{
	if( (parseInt(Infos.Status) == 99) && (parseInt(Infos.Result) == 99))
	{
		document.write('未注册');
	}
	else if(IsPonOnline())
	{
		if((parseInt(Infos.Status) == 0) || (parseInt(Infos.Status) == 5))
		{
			document.write('已注册');
		}
		else
		{
			document.write('注册失败');
		}
	}
	else
	{
		document.write('注册失败');
	}
}

function ItmsServiceStatusInfo()
{

	if (parseInt(Infos.Result) == 1)
	{
		document.write('已下发');
	}
	else if (parseInt(Infos.Result) == 2)
	{
		document.write('下发失败');
	}
	else
	{
		document.write('未下发');
	}
}

function GetCpuUsed()
{
	if ((CfgMode.toUpperCase() == 'SCCT') || (CfgMode.toUpperCase() == 'SCSCHOOL'))
	{
		document.write('运行正常');
	}
	else
	{
		if (cpuUsed != null)
		{
			document.write(cpuUsed);
		}
		else
		{
			document.write('');
		}
	}
}

function GetMemUsed()
{
	if ((CfgMode.toUpperCase() == 'SCCT') || (CfgMode.toUpperCase() == 'SCSCHOOL'))
	{
		document.write('运行正常');
	}
	else
	{
		if (memUsed != null)
		{
			document.write(memUsed);
		}
		else
		{
			document.write('');
		}
	}
}

function CheckWLANInfo()
{
	if ('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_WLAN);%>' == 1)
	{
		if (wlanEnable == 1)
		{
			document.write('开启');
		}
		else
		{
			document.write('未开启');
		}
	}
	else
	{
		document.write('无WiFi功能');
	}
}
function OpticStatusInfo(opticItem)
{
	if (opticItem == "sendPower")
	{
		if (OpticInfo.TransOpticPower == '--')
		{
			document.write('发光异常');
		}
		else
		{
			document.write(OpticInfo.TransOpticPower + "dBm" + "（发光正常）");
		}
	}
	else if (opticItem == "receiverPower")
	{
		if (OpticInfo.RevOpticPower == '--')
		{
			document.write('收光无光');
		}
		else
		{
			if (OpticInfo.RevOpticPower > -8 )
			{
				document.write(OpticInfo.RevOpticPower + "dBm" + "（收光过强）");
			}
			else if (OpticInfo.RevOpticPower < -27)
			{
				document.write(OpticInfo.RevOpticPower + "dBm" + "（收光过低）");
			}else
			{
				document.write(OpticInfo.RevOpticPower + "dBm" + "（收光正常）");
			};
		}
	}
	else if (opticItem == "opticTemperature")
	{
		document.write(OpticInfo.Temperature+".0℃");
	}
	else
	{
		document.write('--');
	}
	
}
var lanDscArr = new Array();
var ethTypeArr = '<%HW_WEB_GetEthTypeList();%>';
var GEPortNum = 0;
var PortIndex = 1;

for(var i = 1; i <= parseInt(ethTypeArr.charAt(0)) ; i++)
{
	if ('1' != ethTypeArr.charAt(i))
	{
		GEPortNum++;
	}
}
for(var i = 1; i <= parseInt(ethTypeArr.charAt(0)) ; i++)
{
    if (2 == i && 4 == ethTypeArr.charAt(0) && ('E8C' == CurrentBin.toUpperCase()))
    {
        lanDscArr.push("iTV");
        if (1 != GEPortNum)
        {
            PortIndex++;
        }
    }
    else
    {
        if ('1' != ethTypeArr.charAt(i))
        {
            if (1 == GEPortNum)
            {
                lanDscArr.push("千兆口");
            }
            else
            {
                lanDscArr.push("千兆口" + PortIndex);
            }
            PortIndex++;
        }
        else
        {
            lanDscArr.push("百兆口" + PortIndex);
            PortIndex++;
        }
    }
}

function getTianYilandesc(lanid)
{
	
	if(lanid > parseInt(ethTypeArr.charAt(0)))
	{
		return "";
	}	

	return lanDscArr[lanid - 1];
}

function getlandesc(lanid)
{
	var landesc;
	if(isPortInAttrName())
	{
		landesc = getTianYilandesc(lanid);
		if(lanid == 2)
		{
			landesc = "iTV";
		}
	}
	else
	{
		landesc = "网口" + lanid;
	}

	if ((lanid == 0) || (lanid > geInfos.length - 1))
	{
		landesc = "";
	}
	
	if( lanid == stbport)
	{
		landesc = "内置STB";
	}

	return landesc;
}

function CheckLANStatusInfo()
{
		var lanid;
		var output = "";

		for(i=0; i<geInfos.length - 1; i++)
		{
			lanid = i+1;
			if ((lanid == stbport) && (E8CRONGHEFlag == 1))
			{
				continue;
			}
            
			output = output + getlandesc(lanid);
			output = output + geInfos[i].Status;	
            output = output + "&nbsp;&nbsp;&nbsp";		
		}
		
		document.write(output);
	
}

var PotsNum = '<%HW_WEB_GetPotsNum();%>';

function GetPotsInfo(PotsId)
{
	var Potsdesc = "";
	var PhyState = AllPhyInterface[PotsId-1].X_HW_Status;
	
	if( PhyState == "Normal" )
	{
		Potsdesc = "空闲"
	}
	else
	{
		Potsdesc = "占用"
	}
	
	return Potsdesc;
}


function GetPotsStatus()
{
	var interfaceIndex;
	var output = "";
	
	if( PotsNum == 0 )
	{
		output = "--";
	}
	else
	{
	    for (interfaceIndex = 1; interfaceIndex < AllPhyInterface.length; interfaceIndex++)
		{	
			output = output + "语音端口"  + interfaceIndex;
			output = output + GetPotsInfo(interfaceIndex);	
			output = output + "&nbsp;&nbsp;&nbsp";	
		}
	}
	document.write(output);
}

var VoiceIpAddr = '<%HW_WEB_GetVoiceIP();%>';

function GetVoiceIpAddr()
{
	var output = "";
	
	if( PotsNum  == 0 )
	{
		output = "--";
	}
	
	if( VoiceIpAddr == "-")
	{
		output = "未获取宽带地址";
	}
	else
	{
		output = VoiceIpAddr;
	}
	document.write(output);
}

function stLine(Domain, Status, RegisterError)
{
    this.Domain = Domain;
    this.Status = Status;
    this.RegisterError = RegisterError;
}
var AllLine = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.{i},Status|X_HW_LastRegisterError,stLine);%>;

function GetVoiceLineState(LineIndex)
{
	var Linedesc = "";
	var LineState = AllLine[LineIndex-1].Status;
	var LineError = AllLine[LineIndex-1].RegisterError;
		
	if( LineState == "Up" )
	{
		Linedesc = "注册正常";
		return Linedesc;
	}
	else
	{
		if( LineError == 'ERROR_REGISTRATION_TIME_OUT' )
		{
			Linedesc = "注册超时";
			return Linedesc;
		}
		if( LineError == 'ERROR_REGISTRATION_AUTH_FAIL' )
		{
			Linedesc = "账号密码错误";
			return Linedesc;
		}
		else
		{
			Linedesc = "注册失败";
			return Linedesc;
		}
	}
}

function GetVoiceUsrState()
{
	var LineIndex;
	var output = "";
	
	if( PotsNum == 0 )
	{
		output = "--";
	}
	else
	{
	    for (LineIndex = 1; LineIndex < AllLine.length; LineIndex++)
		{		
			output = output + "语音用户"  + LineIndex;
			output = output + GetVoiceLineState(LineIndex);	
			output = output + "&nbsp;&nbsp;&nbsp";	
		}
	}
	document.write(output);
}


function GetTr069Address()
{
	for(var i=0;i<Wan.length;i++)
	{
		if ((Wan[i].serviceList.toUpperCase().indexOf("TR069") >= 0) && ("CONNECTED" == Wan[i].status.toUpperCase()))
		{
			document.write(Wan[i].ip);
			return;
		}
	}
	document.write("未获取管理地址");
}

function GetIPv6AddressList(WanInstanceId)
{
    var List = new Array();
    var Count = 0;
    
    for (var i = 0; i < IPv6AddressList.length; i++)
    {
        if(IPv6AddressList[i] == null)
        continue;
        
        if (IPv6AddressList[i].WanInstanceId != WanInstanceId)
        continue;
        
        List[Count++] = IPv6AddressList[i];
    } 
    
    return List;
}

function GetIPv6WanInfo(WanInstanceId)
{
    for (var i = 0; i < IPv6WanInfoList.length; i++)
    {
        if (IPv6WanInfoList[i] != null)
        {
            if (IPv6WanInfoList[i].WanInstanceId == WanInstanceId)
            {
                return IPv6WanInfoList[i];
            }
        }
    }    
}

function GetInternetStatus()
{
	var session;
	
	for(var i=0;i<Wan.length;i++)
	{
		session = Wan[i];
		
		if (session.serviceList.toUpperCase().indexOf("INTERNET") >= 0)
		{
			if (session.modeType.indexOf("Bridged") >= 0)
			{
				if( (1 == session.IPv4Enable) && (0 == session.IPv6Enable ) )
				{
					document.write("桥接模式");
				}
				if( (0 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					document.write("IPv6桥接模式");
				}
				if( (1 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					document.write("IPv4桥接模式<br>IPv6桥接模式");
				}	
			}
			else 
			{			
				if( (1 == session.IPv4Enable) && (0 == session.IPv6Enable ) )
				{
					if( "PPPoE" == session.EncapMode )
					{
						if( "OnDemand" == session.ConnectionTrigger )
						{	
							if("CONNECTED" == Wan[i].status.toUpperCase())
							{
								document.write("路由模式-拨号成功");
							}
							else
							{
								if( "ERROR_IDLE_DISCONNECT" == session.ConErr)
								{
									document.write("路由模式-空闲未拨号");
								}
								else if("ERROR_NONE" == session.ConErr)
								{
									document.write("路由模式-空闲未拨号");
								}
								else
								{
									document.write("路由模式-拨号失败");
								}
							}
						}
						else if( "AlwaysOn" == session.ConnectionTrigger)
						{
							if("CONNECTED" == Wan[i].status.toUpperCase())
							{
								document.write("路由模式-拨号成功");
							}
							else
							{
								if("ERROR_NONE" == session.ConErr)
								{
									document.write("路由模式-空闲未拨号");
								}
								else
								{
									document.write("路由模式-拨号失败");
								}
							}
						}
						else if( "Manual" == session.ConnectionTrigger)
						{
							if("CONNECTED" == Wan[i].status.toUpperCase())
							{
								document.write("路由模式-拨号成功");
							}
							else
							{  
								if(("0" == session.ConnectionControl) || ("ERROR_NONE" == session.ConErr))
								{
									document.write("路由模式-空闲未拨号");
								}
								else
								{
									document.write("路由模式-拨号失败");
								} 
							}
						}
					
					}
					else
					{
						document.write(("CONNECTED" == Wan[i].status.toUpperCase())? "路由模式-拨号成功" : "路由模式-拨号失败");
					}

				}
				else if( (0 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					var ipv6Wan = GetIPv6WanInfo(session.MacId);
					if("CONNECTED" == ipv6Wan.ConnectionStatus.toUpperCase())
					{
						document.write("IPv6路由模式-拨号成功");
					}
					else
					{
						if("ERROR_NONE" == session.ConErr)
						{
							document.write("IPv6路由模式-空闲未拨号");
						}
						else
						{
							document.write("IPv6路由模式-拨号失败");
						}
					}
				}
				else if( (1 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					var ipv6Wan = GetIPv6WanInfo(session.MacId);
					var v4dis = '';
					var v6dis = '';
					if("CONNECTED" == session.status.toUpperCase())
					{
						v4dis = "IPv4路由模式-拨号成功<br>";
					}
					else
					{
						if("ERROR_NONE" == session.ConErr)
						{
							v4dis = "IPv4路由模式-空闲未拨号<br>";
						}
						else
						{
							v4dis ="IPv4路由模式-拨号失败<br>";
						}
					}
					
					if("CONNECTED" == ipv6Wan.ConnectionStatus.toUpperCase())
					{
						v6dis = "IPv6路由模式-拨号成功";
					}
					else
					{
						if("ERROR_NONE" == session.ConErr)
						{
							v6dis = "IPv6路由模式-空闲未拨号";
						}
						else
						{
							v6dis ="IPv6路由模式-拨号失败";
						}
					}
					document.write(v4dis + v6dis);
				}	
				else
				{
					
				}
			}
			return;
		}
	}
	document.write("未配置");
}

function GetInternetAddress()
{
	var session;
	var IPv6Address;
	
	for(var i=0;i<Wan.length;i++)
	{
		session = Wan[i];
		
		if (session.serviceList.toUpperCase().indexOf("INTERNET") >= 0)
		{
			if (session.modeType.indexOf("Bridged") >= 0)
			{
				if( (1 == session.IPv4Enable) && (0 == session.IPv6Enable ) )
				{
					document.write("桥接模式");
				}
				if( (0 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					document.write("IPv6桥接模式");
				}
				if( (1 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					document.write("IPv4桥接模式<br>IPv6桥接模式");
				}
			}
			else 
			{
				if(1 == session.IPv6Enable )
				{
					var ipv6Wan = GetIPv6WanInfo(session.MacId);
					var IPv6AddressList = GetIPv6AddressList(session.MacId);
											
					for (var m = 0; m < IPv6AddressList.length; m++)
					{			
						if (IPv6AddressList[m].Origin.toUpperCase() != "LINKLOCAL")
						{	
							IPv6Address = IPv6AddressList[m].IPAddress;
						}
					}
				}			
				if( (1 == session.IPv4Enable) && (0 == session.IPv6Enable ) )
				{ 
					document.write(("CONNECTED" == Wan[i].status.toUpperCase())? session.ip : "未获取宽带地址");
				}
				else if( (0 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{		
					document.write(("CONNECTED" == ipv6Wan.ConnectionStatus.toUpperCase())? IPv6Address : "未获取IPv6宽带地址");
				}
				else if( (1 == session.IPv4Enable) && (1 == session.IPv6Enable ) )
				{
					v4dis = (("CONNECTED" == Wan[i].status.toUpperCase())? session.ip : "未获取宽带地址") + "<br>" ;
					v6dis = ("CONNECTED" == ipv6Wan.ConnectionStatus.toUpperCase())? IPv6Address : "未获取IPv6宽带地址" ;
					document.write(v4dis + v6dis);
				}
			}
			return;
		}
	}
	document.write("未获取宽带地址");
}
</script>
</head>
<body  class="mainbody" onLoad="LoadFrame();" text-align="left"> 
<div style="margin-top:10px;margin-left:200px;margin-right:200px">
<table class="prompt" >
<tr>
<td width="80%"></td>
<td align="right" width="20%">
<script language="javascript">
document.write('<A href="http://' + br0Ip +':'+ httpport +'/login.asp"><font style="font-size: 13px;"  color="#000000">返回登录页面</FONT></A>');
</script>
</td> 
</tr> 
</table> 

<table id="table_hardware" width="100%" border="0" cellspacing="0" cellpadding="0"> 
<tr> 
<td class="table_head" width="100%"><font id = "Title_base_lable" color=#0202EC >硬件信息</font></td> 
</tr> 
</table>
<table id="table_hardwareinfo" width="100%" border="1" cellpadding="0" cellspacing="0" class="table_bg">

<tr>
<td class="table_title" width="25%" align="left" id="Table_base1_1_table" name="Table_base1_1_table">生产厂家:&nbsp;</td>
<script>
	var tdHtml = jiuzhouFlag == "1" ? "九洲电器" : "华为";
	document.write('<td class="table_right" width="75%" id="Table_base2_2_table" name="Table_base2_2_table">' + tdHtml + '</td>');
</script>
</tr>

<tr> 
<td class="table_title" width="25%" align="left" id="Table_base2_1_table" name="Table_base2_1_table">硬件型号:&nbsp;</td> 
<td class="table_right" width="75%" id="Table_base2_2_table" name="Table_base2_2_table"> 
<script language="javascript">
if (deviceInfo != null)
{
	document.write(deviceInfo.ModelName);
}
else
{
	document.write('');
}
</script>
</td> 
</tr> 
<tr> 
<td class="table_title" width="25%" align="left" id="Table_base3_1_table" name="Table_base3_1_table">硬件版本:&nbsp;</td> 
<td class="table_right" width="75%" id="Table_base3_2_table" name="Table_base3_2_table"> <script language="javascript">
	if(deviceInfo.HardwareVersion !='')
	{
		document.write(deviceInfo.HardwareVersion);
	}
	else
	{
		document.write('');
	}
</script> </td> 
</tr> 
      
<tr> 
<td class="table_title" align="left" id="Table_base4_1_table" name="Table_base4_1_table">终端CPU:&nbsp;</td> 
<td class="table_right" id="Table_base4_2_table" name="Table_base4_2_table"><script language="javascript">
	GetCpuUsed();
</script></td> 
</tr> 
 <tr> 
    <td class="table_title" align="left" id="Table_base5_1_table" name="Table_base5_1_table">终端内存:&nbsp;</td> 
    <td class="table_right" id="Table_base5_2_table" name="Table_base5_2_table"><script language="javascript">
	GetMemUsed();
</script></td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base6_1_table" name="Table_base6_1_table">终端无线功能:&nbsp;</td> 
    <td class="table_right" id="Table_base6_2_table" name="Table_base6_2_table"> <script language="javascript">
	CheckWLANInfo();
</script> </td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base7_1_table" name="Table_base7_1_table">终端网口状态:&nbsp;</td> 
    <td class="table_right" id="Table_base7_2_table" name="Table_base7_2_table"> <script language="javascript">
	CheckLANStatusInfo();
</script> </td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base8_1_table" name="Table_base8_1_table">终端语音端口状态:&nbsp;</td> 
    <td class="table_right" id="Table_base8_2_table" name="Table_base8_2_table"> <script language="javascript">
	GetPotsStatus();
</script> </td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base9_1_table" name="Table_base9_1_table">收光状态:&nbsp;</td> 
    <td class="table_right" id="Table_base9_2_table" name="Table_base9_2_table"> <script language="javascript">
    OpticStatusInfo("receiverPower");
</script> </td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base10_1_table" name="Table_base10_1_table">发光状态:&nbsp;</td> 
    <td class="table_right" id="Table_base10_2_table" name="Table_base10_2_table"> <script language="javascript">
OpticStatusInfo("sendPower");
</script> </td> 
</tr>

 <tr> 
    <td class="table_title" align="left" id="Table_base11_1_table" name="Table_base11_1_table">光模块温度:&nbsp;</td> 
    <td class="table_right" id="Table_base11_2_table" name="Table_base11_2_table"> <script language="javascript">
	OpticStatusInfo("opticTemperature");
</script> </td> 
</tr>

 <tr id="Table_base12_1_tr"> 
    <td class="table_title" align="left" id="Table_base12_1_table" name="Table_base12_1_table">家庭网络二层丢帧率:&nbsp;</td> 
    <td class="table_right" id="Table_base12_2_table" name="Table_base12_2_table"> 
	<script language="javascript">FrameDetectLostInfo()</script> 
	</td> 
</tr>

 <tr id="Table_base13_1_tr"> 
    <td class="table_title" align="left" id="Table_base13_1_table" name="Table_base13_1_table">家庭网络二层时延:&nbsp;</td> 
    <td class="table_right" id="Table_base13_2_table" name="Table_base13_2_table"> 
	<script language="javascript">FrameDetectDelayInfo()</script> 
	</td> 
</tr>
 <tr id="Table_base14_1_tr"> 
    <td class="table_title" align="left" id="Table_base14_1_table" name="Table_base14_1_table">家庭网络二层抖动:&nbsp;</td> 
    <td class="table_right" id="Table_base14_2_table" name="Table_base14_2_table"> 
	<script language="javascript">FrameDetectJetterInfo()</script> 
	</td> 
</tr>
</table> 


<table width="100%" height="15" border="0" cellpadding="0" cellspacing="0"> 
  <tr> 
    <td></td> 
  </tr> 
</table> 

<table id="table_pontitle" width="100%" border="0" cellspacing="0" cellpadding="0"> 
<tr> 
<td class="table_head" width="100%"><font id = "Title_pon_lable" color=#0202EC >业务信息</font></td> 
</tr> 
</table>

<table id="table_poninfo" width="100%" border="1" cellpadding="0" cellspacing="0" class="table_bg">
	<tr>
		<td class="table_left"  width="25%" id="Table_pon1_1_table" name="Table_pon1_1_table">终端软件信息:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon1_2_table" name="Table_pon1_2_table">
			<script type="text/javascript" language="javascript">
				var softwareVersion = (jiuzhouFlag == '1') ? deviceInfo.SoftwareVersion.replace("HW", "JZ") : deviceInfo.SoftwareVersion;
				document.write(softwareVersion);
			</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon2_1_table" name="Table_pon2_1_table">OLT注册状态:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon2_2_table" name="Table_pon2_2_table">
		<script type="text/javascript" language="javascript">OltRegStatusInfo();</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon3_1_table" name="Table_pon3_1_table">ITMS注册状态:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon3_2_table" name="Table_pon3_2_table">
		<script type="text/javascript" language="javascript">ItmsRegStatusInfo();</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon4_1_table" name="Table_pon4_1_table">ITMS下发状态:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon4_2_table" name="Table_pon4_2_table">
		<script type="text/javascript" language="javascript">ItmsServiceStatusInfo();</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon5_1_table" name="Table_pon5_1_table">管理地址:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon5_2_table" name="Table_pon5_2_table">
		<script type="text/javascript" language="javascript">GetTr069Address();</script>
		</td>
	</tr>
	
		<tr>
		<td class="table_left"  width="25%" id="Table_pon6_1_table" name="Table_pon6_1_table">宽带拨号状态:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon6_2_table" name="Table_pon6_2_table">
		<script type="text/javascript" language="javascript">GetInternetStatus();</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon7_1_table" name="Table_pon7_1_table">宽带IP地址:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon7_2_table" name="Table_pon7_2_table">
		<script type="text/javascript" language="javascript">GetInternetAddress();</script>
		</td>
	</tr>
	
		<tr>
		<td class="table_left"  width="25%" id="Table_pon8_1_table" name="Table_pon8_1_table">语音注册状态:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon8_2_table" name="Table_pon8_2_table">
		<script type="text/javascript" language="javascript">GetVoiceUsrState();</script>
		</td>
	</tr>
	
	<tr>
		<td class="table_left"  width="25%" id="Table_pon9_1_table" name="Table_pon9_1_table">语音IP地址:&nbsp;</td>
		<td class="table_right" width="75%" id="Table_pon9_2_table" name="Table_pon9_2_table">
		<script type="text/javascript" language="javascript">GetVoiceIpAddr();</script>
		</td>
	</tr>
		
</table>
</div>
</body>
</html>
