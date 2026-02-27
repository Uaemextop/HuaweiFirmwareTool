<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>install service step1</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(voicedes.html);%>"></script>
<style>
.tabal_noborder_bg {
	padding:0px 0px 10px 0px;
	background-color: #FAFAFA;
}
</style>
<script language="JavaScript" type="text/javascript">
var VoiceDisplay = 0;
var ClassAIpSupportFlag='<%HW_WEB_GetFeatureSupport(BBSP_FT_SUPPORT_CLASS_A_IP);%>';
function stLanHostInfo(domain,enable,ipaddr,subnetmask,AddressConflictDetectionEnable)
{
	this.domain = domain;
	this.enable = enable;
	this.ipaddr = ipaddr;
	this.subnetmask = subnetmask;
	this.AddressConflictDetectionEnable = AddressConflictDetectionEnable;
}
function SlaveDhcpInfo(domain, enable)
{
	this.domain    = domain;
	this.enable    = enable;
}


function stLine(Domain, DirectoryNumber, Enable, PhyReferenceList )
{
    this.Domain = Domain;
    this.DirectoryNumber = DirectoryNumber;
    this.PhyReferenceList = PhyReferenceList;

    if (Enable.toLowerCase() == 'enabled')
    {
        this.Enable = 1;
    }
    else
    {
        this.Enable = 0;
    }     
	
    var temp = Domain.split('.');
    this.key = '.' + temp[7] + '.';
}

var AllLine = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.{i}.Line.{i},DirectoryNumber|Enable|PhyReferenceList,stLine);%>;
var CfgModeWord = '<%HW_WEB_GetCfgMode();%>';
var LanHostInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.{i},Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask|X_HW_AddressConflictDetectionEnable,stLanHostInfo);%>;
var LanHostInfo2 = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2,Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask|X_HW_AddressConflictDetectionEnable,stLanHostInfo);%>;
var PolicyRouteListAll = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterPolicyRoute, InternetGatewayDevice.Layer3Forwarding.X_HW_policy_route.{i},PolicyRouteType|VenderClassId|WanName,PolicyRouteItem);%>;  
var SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,DHCPEnable,SlaveDhcpInfo);%>;
var LanHostInfo = LanHostInfos[0];
var SlaveIpAddr = "";
if (LanHostInfos[1] != null)
{
	SlaveIpAddr = LanHostInfos[1].ipaddr;
}
else if(LanHostInfos[1] == null && LanHostInfo2[0] != null && '1' == conditionpoolfeature)
{
	SlaveIpAddr = LanHostInfo2[0].ipaddr;
}

var SelectSrvType = parent.ServiceConfigData.PurchasedSrv;
var SelectAddrType = parent.ServiceConfigData.AddrType;
var SelectVoiceLineType = parent.ServiceConfigData.VoiceServiceEnable;
function ShowByAddrType()
{
	if ('THREE' == SelectSrvType.toUpperCase())
	{
		if ('DYNAMIC' == SelectAddrType.toUpperCase())
		{
			setDisplay('MTVDynamic',1);
			setDisplay('MTVStatic',0);
		}
		else if ('STATIC' == SelectAddrType.toUpperCase())
		{
			setDisplay('MTVDynamic',0);
			setDisplay('MTVStatic',1);
		}
		else
		{
			setDisplay('MTVDynamic',0);
			setDisplay('MTVStatic',0);
			setDisplay('VoiceSpread',0);
		}
	}
	else if ('TWO' == SelectSrvType.toUpperCase())
	{
		setDisplay('MTVStatic',0);
		setDisplay('MTVDynamic',0);
		setDisplay('VoiceSpread',0);
	}
}

function ShowByVoiceLineType()
{
	if (installservice_language['bbsp_yes'].toUpperCase() == SelectVoiceLineType.toUpperCase())
	{
		setDisplay('VoiceLine',1);
		setDisplay('VoiceSpread',1);
		VoiceDisplay = 1;
	}
	else
	{
		setDisplay('VoiceLine',0);
		setDisplay('VoiceSpread',0);
		VoiceDisplay = 0;
	}
}
function SubmitReturn(val)
{
	val.id = '';
	val.NameStr = 'Service selection';
	val.name = '/html/bbsp/installservice/installservicestep1.asp';
	window.parent.OnChangeIframeShowPage(val); 
}

function Checkipmaskgateway(ipaddr,submask,gateway)
{
	if ((isValidIpAddress(ipaddr) == false || isAbcIpAddress(ipaddr) == false))
	{
		 AlertEx(Languages['IPAddressInvalid']);
		 return false;
	}
		
	if (isValidSubnetMask(submask) == false )
	{
		AlertEx(Languages['SubMaskInvalid']);
		return false;
	}
		
	if ((isValidIpAddress(gateway) == false || isAbcIpAddress(gateway) == false))
	{
		AlertEx(Languages['WanGateWayInvalid']);
		return false;
	}
		
	if('TDE2' != CfgModeWord.toUpperCase())
	{
		if (gateway == ipaddr)
		{
			AlertEx(Languages['IPAddressSameAsGateWay']);
			return false;
		}
	}
	
	if(false == isSameSubNet(ipaddr, submask, gateway, submask))
	{
		AlertEx(Languages['IPAddressNotInGateWay']);
		return false;
	}
	var addr = IpAddress2DecNum(ipaddr);
	var mask = SubnetAddress2DecNum(submask);
	var gwaddr = IpAddress2DecNum(gateway);
	if('TDE2' != CfgModeWord.toUpperCase())
	{
		if ( (addr & (~mask)) == (~mask) )
		{
			AlertEx(Languages['WANIPAddressInvalid']);
			return false;
		}
		
		if ( (addr & (~mask)) == 0 )
		{
			AlertEx(Languages['WANIPAddressInvalid']);
			return false;
		}
	
		if ( (gwaddr & (~mask)) == (~mask) )
		{
			AlertEx(Languages['WANGateWayIPAddressInvalid']);
			return false;
		}
		
		if ( (gwaddr & (~mask)) == 0 )
		{
			 AlertEx(Languages['WANGateWayIPAddressInvalid']);
			return false;
		}
	}
	
	for (var iIP=0; iIP < GetWanList().length; iIP++)
	{
		if (GetWanList()[iIP].domain != parent.ServiceConfigData.domain && GetWanList()[iIP].IPv4IPAddress == ipaddr)
		{
			AlertEx(Languages['IPAddressIsUserd']);
			return false;
		}
	} 
}

function GetPolicyRouteListLength(PolicyRouteList, Type)
{
	var Count = 0;

	if (PolicyRouteList == null)
	{
		return 0;
	}

	for (var i = 0; i < PolicyRouteList.length; i++)
	{
		if (PolicyRouteList[i] == null)
		{
			continue;
		}

		if (PolicyRouteList[i].Type == Type)
		{
			Count++;
		}
	}

	return Count;
}

function GetCurrentLoginIP()
{
	var CurUrlIp = (window.location.host).toUpperCase();
	return CurUrlIp;
}

function CheckDhcpSlave()
{
	var publicipaddr = getValue('WQipaddr');
	var lansubmask = '255.255.255.248';
	
	if ( isValidIpAddress(publicipaddr) == false ) 
	{
		AlertEx(dhcp_language['bbsp_ipaddrp'] + publicipaddr + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	if ( isValidSubnetMask(lansubmask) == false ) 
	{
		AlertEx(dhcp_language['bbsp_subnetmaskp'] + lansubmask + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
    if (ClassAIpSupportFlag != 1)
    {
        if ( isMaskOf24BitOrMore(lansubmask) == false ) 
        {
            	AlertEx(dhcp_language['bbsp_subnetmaskp'] + lansubmask + dhcp_language['bbsp_isinvalidp']);
            	return false;
        }	
    }
	if(isHostIpWithSubnetMask(publicipaddr, lansubmask) == false)
	{
		AlertEx(dhcp_language['bbsp_ipaddrp'] + publicipaddr + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	if ( isBroadcastIp(publicipaddr, lansubmask) == true ) 
	{
		AlertEx(dhcp_language['bbsp_ipaddrp'] + publicipaddr + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	
	if(SlaveDhcpInfos[0] != null && 1 == SlaveDhcpInfos[0].enable)
	{
		if (publicipaddr == LanHostInfo.ipaddr) 
		{
			AlertEx(dhcp_language['bbsp_pridhcpsecdhcp']);		  
			return false;
		}
	
		if(true==isSameSubNet(LanHostInfo.ipaddr, LanHostInfo.subnetmask,publicipaddr,lansubmask))
		{
			AlertEx(dhcp_language['bbsp_pridhcpsecdhcp']);		
			return false;
		}
	}
	var Reboot = (GetPolicyRouteListLength(PolicyRouteListAll, "SourceIP") > 0 ) ? dhcp_language['bbsp_resetont']:"";

	result = true;
	if ((publicipaddr != SlaveIpAddr) && (GetCurrentLoginIP() == SlaveIpAddr))
	{
		result = ConfirmEx(dhcp_language['bbsp_dhcpconfirmnote']+Reboot);
	}

	if ( result == true )
	{
		setDisable('ButtonApply', 1);
	}
	return result;
}

function vspaisValidCfgStr(cfgName, val, len)
{
    if (isValidAscii(val) != '')         
    {  
        AlertEx(cfgName + sipinterface['vspa_hasvalidch'] + isValidAscii(val) + sipinterface['vspa_end']);          
        return false;       
    }
    if (val.length != len)
    {
        AlertEx(cfgName + sipinterface['vspa_musthave']  + len  + sipinterface['vspa_characters']);
        return false;
    }        
}

function CheckIPAddrRange(ipaddr)
{
	if ('10' != ipaddr.split('.')[0])
	{
		AlertEx(Languages['IPAddressInvalid']);
		return false;
	}

	if(((parseInt(ipaddr.split('.')[1], 10)) < 64 )|| (parseInt(ipaddr.split('.')[1], 10) > 255))
	{
		AlertEx(Languages['IPAddressInvalid']);
		return false;
	}
}

function CheckForm()
{
	var ipaddr = '';
	var submask = '';
	var gateway = '';
	if ('THREE' == SelectSrvType.toUpperCase())
	{
		if ('DYNAMIC' == SelectAddrType.toUpperCase())
		{
			ipaddr = getValue('UCipaddr');
			if (false == CheckIPAddrRange(ipaddr))
			{
				return false; 
			}
			
			submask = getValue('submask');
			gateway = getValue('gateway');
			
			if (false == Checkipmaskgateway(ipaddr,submask,gateway))
			{
				return false; 
			}
		}
		else if ('STATIC' == SelectAddrType.toUpperCase())
		{
			ipaddr = getValue('WUipaddr');
			submask = '255.255.240.0';
			gateway = '172.26.208.1';
			if (false == Checkipmaskgateway(ipaddr,submask,gateway))
			{
				return false; 
			}
			if (false == CheckDhcpSlave())
			{
				return false; 
			}
		}

	}
			
	if (( '' != removeSpaceTrim(getValue('phonenum'))) && (1 == VoiceDisplay))
    {
        if (vspaisValidCfgStr(sipinterface['vspa_phoneregister'],getValue('phonenum'),9) == false)
        {
            return false;
        }   
    }
	
	return true;
}

function SubmitNext(val)
{
	val.id = '';
	val.NameStr = 'Service selection';
	val.name = '/CustomApp/SumaryConfig.asp';
	
	var domain = parent.ServiceConfigData.domain;
	if ('' != domain)
	{
		if (false == CheckForm())
		{
			return false;
		}

		if ('THREE' == SelectSrvType.toUpperCase())
		{
			if ('DYNAMIC' == SelectAddrType.toUpperCase())
			{
				parent.ServiceConfigData.IpAddr = getValue('UCipaddr');
				parent.ServiceConfigData.SubMask = getValue('submask');
				parent.ServiceConfigData.Gateway = getValue('gateway');				
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.NATEnabled=1");
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.ExternalIPAddress="+getValue('UCipaddr'));
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.SubnetMask="+getValue('submask'));
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.DefaultGateway="+getValue('gateway'));
			}
			else if ('STATIC' == SelectAddrType.toUpperCase())
			{
				parent.ServiceConfigData.IpAddr = getValue('WUipaddr');
				parent.ServiceConfigData.SubMask = '255.255.240.0';
				parent.ServiceConfigData.Gateway = '172.26.208.1';
				parent.ServiceConfigData.ImageIpAddr = getValue('WQipaddr');
				parent.ServiceConfigData.ImageSubMask = '255.255.255.248';
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.NATEnabled=0");
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.ExternalIPAddress="+getValue('WUipaddr'));
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.SubnetMask=255.255.240.0");
				window.parent.AddConfigParaToGlobeVar("x="+domain, "x.DefaultGateway=172.26.208.1");
				window.parent.AddConfigParaToGlobeVar("y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2", "y.IPInterfaceIPAddress="+getValue('WQipaddr'));
				window.parent.AddConfigParaToGlobeVar("y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2", "y.IPInterfaceSubnetMask=255.255.255.248");

			}
		}
		else if ('TWO' == SelectAddrType.toUpperCase())
		{
			window.parent.AddConfigParaToGlobeVar("x="+domain, "x.Enable=0");
		}
	}
	
	if (installservice_language['bbsp_yes'].toUpperCase() == SelectVoiceLineType.toUpperCase())
	{
		window.parent.AddConfigParaToGlobeVar("z=InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1", "z.DirectoryNumber="+FormatUrlEncode(getValue('phonenum')));
		parent.ServiceConfigData.VoiceLineNum = getValue('phonenum');
	}
	
	else if  (installservice_language['bbsp_no'].toUpperCase() == SelectVoiceLineType.toUpperCase())
	{
		window.parent.AddConfigParaToGlobeVar("z=InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1", "z.DirectoryNumber="+FormatUrlEncode(getValue('phonenum')));
		parent.ServiceConfigData.VoiceLineNum = getValue('phonenum');
	}
	else
	{
	}

	window.parent.OnChangeIframeShowPage(val); 
}

function setDataDisplay()
{
	var wanlist = GetWanList();
	var iptv_index = -1;
	for (var i=0; i < wanlist.length; i++)	
	{
		if (wanlist[i].domain == parent.ServiceConfigData.domain)
		{
			iptv_index = i;
			break;
		}
	}
	if (-1 != iptv_index)
	{
		setText('UCipaddr',wanlist[iptv_index].IPv4IPAddress);  
		setText('submask',wanlist[iptv_index].IPv4SubnetMask);
		setText('gateway',wanlist[iptv_index].IPv4Gateway);  
		setText('WUipaddr',wanlist[iptv_index].IPv4IPAddress); 
	}
	if (null != LanHostInfo2[0]) 
	{
		setText('WQipaddr',LanHostInfo2[0].ipaddr); 
	}
	if (null != AllLine[0]) 
	{
		setText('phonenum',AllLine[0].DirectoryNumber); 
	}
}

function GetMaskandGW()
{
	var ipaddr;
	if ('THREE' == SelectSrvType.toUpperCase())
	{
		if ('DYNAMIC' == SelectAddrType.toUpperCase())
		{
			ipaddr = getValue('UCipaddr');
			
			if ((isValidIpAddress(ipaddr) == false || isAbcIpAddress(ipaddr) == false))
			{
				 AlertEx(Languages['IPAddressInvalid']);
				 return false;
			}
			
			if ( CheckIPAddrRange(ipaddr) == false )
			{
				return false; 
			}
			
			if (64 <= parseInt(ipaddr.split('.')[1], 10) 
			    && parseInt(ipaddr.split('.')[1], 10) <= 127)
			{
				setText('submask', '255.192.0.0');
				setText('gateway', '10.64.0.1');
			}

			else if (128 <= parseInt(ipaddr.split('.')[1], 10) 
			         && parseInt(ipaddr.split('.')[1], 10) <= 255)
			{
				setText('submask', '255.128.0.0');
				setText('gateway', '10.128.0.1');
			}
		}
	}
}

function LoadFrame()
{
	ShowByAddrType();
	ShowByVoiceLineType();
	setDataDisplay();
}
</script>
</head>
<body onLoad="LoadFrame();" class="iframebody"> 

<div id="MTVDynamic" class="FuctionPageAreaCss" style="display:none;" >
<div id="MTVDynamicTitle" class="FunctionPageTitleCss">
<span id="MTVDynamicText" class="PageTitleTextCss" BindText="bbsp_MovTV_title"></span>
</div>
<form id = "MTVDynamicConfigForm">
<div style="height:30px;"></div>
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="UCipaddr"             RealType="TextBox"       DescRef="bbsp_UCipaddr"      RemarkRef="bbsp_ipaddrnote"          ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"     InitValue="Empty"  ClickFuncApp="onblur=GetMaskandGW"/>
<li   id="gateway"              RealType="TextBox"       DescRef="bbsp_gateway"       RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     InitValue="Empty"/>
<li   id="submask"              RealType="TextBox"       DescRef="bbsp_submask"       RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     InitValue="Empty"/>
</table>
<script>
var TableClass = new stTableClass("PageSumaryTitleCss tablecfg_title width_per55", "tablecfg_right width_per45", "", "Select");
var MTVDynamicConfigFormList = new Array();
MTVDynamicConfigFormList = HWGetLiIdListByForm("MTVDynamicConfigForm");
HWParsePageControlByID("MTVDynamicConfigForm", TableClass, installservice_language, null);
</script>
<div style="height:30px;"></div>
</form>
</div>

<div id="MTVStatic" class="FuctionPageAreaCss"  style="display:none;">
<div id="MTVStaticTitle" class="FunctionPageTitleCss">
<span id="MTVStaticText" class="PageTitleTextCss" BindText="bbsp_MovTV_title"></span>
</div>
<form id = "MTVStaticConfigForm">
<div style="height:30px;"></div>
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="WUipaddr"             RealType="TextBox"       DescRef="bbsp_WUipaddr"      RemarkRef="bbsp_ipaddrnote1"              ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"     InitValue="Empty"/>
<li   id="WQipaddr"             RealType="TextBox"       DescRef="bbsp_WQipaddr"      RemarkRef="bbsp_ipaddrnote"              ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"     InitValue="Empty"/>
</table>
<script>
var MTVStaticConfigFormList = new Array();
MTVStaticConfigFormList = HWGetLiIdListByForm("MTVStaticConfigForm");
HWParsePageControlByID("MTVStaticConfigForm", TableClass, installservice_language, null);
getElementById('WUipaddr').setAttribute('title', installservice_language['bbsp_WUnote']);
</script>
<div style="height:30px;"></div>
</form>
</div>

<div id="VoiceSpread" style="height:20px;display:none;"></div>
<div id="VoiceLine" class="FuctionPageAreaCss" style="display:block;">
<div id="VoiceLineTitle" class="FunctionPageTitleCss">
<span id="VoiceLineText" class="PageTitleTextCss" BindText="bbsp_voiceline_title"></span>
</div>
<form id = "VoiceLineConfigForm">
<div style="height:30px;"></div>
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="phonenum"             RealType="TextBox"       DescRef="bbsp_phonenum"      RemarkRef="Empty"              ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"     InitValue="Empty"/>
</table>
<script>
var VoiceLineConfigFormList = new Array();
VoiceLineConfigFormList = HWGetLiIdListByForm("VoiceLineConfigForm");
HWParsePageControlByID("VoiceLineConfigForm", TableClass, installservice_language, null);
</script>
<div style="height:30px;"></div>
</form>
</div>

<div style="height:30px;"></div>
<table width="100%" border="0" cellspacing="0" cellpadding="0" class=""> 
	<tr> 
	  <td class='width_per3'></td> 
	  <td class="table_submit" > 
	   <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
	   <button id="btnReturn" name="btnReturn" type="button" class="BluebuttonGreenBgcss width_120px" style="margin-left: 0px;" onClick="SubmitReturn(this);"><script>document.write(installservice_language['bbsp_return']);</script> </button> 
	   <button id="btnNext" name="btnNext" type="button" class="BluebuttonGreenBgcss width_120px" style="margin-left: 36px;" onClick="SubmitNext(this);"><script>document.write(installservice_language['bbsp_next']);</script> </button>  
	</tr> 
</table> 

<script>
	ParseBindTextByTagName(installservice_language, "span",  1);
	ParseBindTextByTagName(installservice_language, "td",    1);
	ParseBindTextByTagName(installservice_language, "input", 2);
</script>

</body>
</html>