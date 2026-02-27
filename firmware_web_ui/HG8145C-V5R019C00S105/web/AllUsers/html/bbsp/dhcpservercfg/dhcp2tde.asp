<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<title>DHCP Configure</title>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="javascript" src="../common/dhcpinfo.asp"></script>
<style>
.TextBox
{
	width:130px;  
}
.TextBox_2
{
	width:63px;  
}
.TextBoxLtr
{
	width:130px;
	direction:ltr;  
}

.Select
{
	width:135px;  
}
.Select_2
{
	width:63px;
	margin:0px 0px 0px 3px;
}
.tabal_noborder_bg {
	padding:0px 0px 10px 0px;
	background-color: #FAFAFA;
}
</style>	
<script language="JavaScript" type="text/javascript">
var PolicyRouteNum = 0;
var ClassAIpSupportFlag='<%HW_WEB_GetFeatureSupport(BBSP_FT_SUPPORT_CLASS_A_IP);%>';
function PolicyRouteItem(_Domain, _Type, _VenderClassId, _WanName)
{
    this.Domain = _Domain;
    this.Type = _Type;
    this.VenderClassId = _VenderClassId;
    this.WanName = _WanName;
}

var PolicyRouteListAll = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterPolicyRoute, InternetGatewayDevice.Layer3Forwarding.X_HW_policy_route.{i},PolicyRouteType|VenderClassId|WanName,PolicyRouteItem);%>; 
for (i = 0; i < PolicyRouteListAll.length && PolicyRouteListAll[i]; i++)
{  
	if(PolicyRouteListAll[i].Type.toUpperCase() == "SourceIP".toUpperCase())
	{
		PolicyRouteNum ++;
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

function dhcpmainst(domain,enable,startip,endip,leasetime,MainDNS,DNSServers)
{
	this.domain 	= domain;
	this.enable		= enable;
	this.startip	= startip;
	this.endip		= endip;
	this.leasetime  = leasetime;
	MainDNS = (MainDNS == "")?DNSServers:MainDNS;
	if(MainDNS == "")
	{
		this.MainPriDNS	= "";  
		this.MainSecDNS = "";
	}
	else
	{
		var MainDnss 	= MainDNS.split(',');
		this.MainPriDNS	= MainDnss[0];  
		this.MainSecDNS  = MainDnss[1];
		if (MainDnss.length <=1)
		{
			this.MainSecDNS = "";
		}
	}
}

function stipaddr(domain,enable,ipaddr,subnetmask)
{
	this.domain		= domain;
	this.enable		= enable;
	this.ipaddr		= ipaddr;
	this.subnetmask	= subnetmask;	
}

var MainDhcpRange = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaMainDhcpPool, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement,DHCPServerEnable|MinAddress|MaxAddress|DHCPLeaseTime|X_HW_DNSList|DNSServers,dhcpmainst);%>;  

var LanIpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.{i},Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask,stipaddr);%>;
if (LanIpInfos[1] == null)
{
    LanIpInfos[1] = new stipaddr("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2", "", "", ""); 
}

var dhcpmain = MainDhcpRange[0];
var curUserType='<%HW_WEB_GetUserType();%>';
var sysUserType='0';
var slv_independency='<%HW_WEB_GetFeatureSupport(FT_SLAVE_NO_ASSIGN_ADDR);%>';
var conditionpoolfeature ='<%HW_WEB_GetFeatureSupport(BBSP_FT_DHCPS_COND_POOL);%>';
var norightslavefeature ='<%HW_WEB_GetFeatureSupport(FT_NOMAL_NO_RIGHT_SLAVE_POOL);%>';
function dhcpcnst1(domain,dhcpStart,dhcpEnd,LeaseTime,Enable,option60,ntpsvr,NormalUserEnable,SlaDNS)
{
	this.domain 	= domain;
	this.dhcpStart 	= dhcpStart;
	this.dhcpEnd 	= dhcpEnd;
	this.LeaseTime 	= LeaseTime;
	this.Enable 	= Enable;  
	this.option60 	= option60;
	if(SlaDNS == "")
	{
		this.SlaPriDNS	= "";  
		this.SlaSecDNS  = "";
	}
	else
	{
		var SlaDnss 	= SlaDNS.split(',');
		this.SlaPriDNS	= SlaDnss[0];  
		this.SlaSecDNS  = SlaDnss[1];
		
		if (SlaDnss.length <=1)
		{
		    this.SlaSecDNS = "";
		}
	}
	
	this.ntpsvr  = ntpsvr; 
	this.NormalUserEnable = NormalUserEnable;
}

function dhcpcnst(domain,dhcpStart,dhcpEnd,LeaseTime,Enable,option60,ntpsvr,Option43,NormalUserEnable,SlaDNS)
{
	this.domain 	= domain;
	this.dhcpStart 	= dhcpStart;
	this.dhcpEnd 	= dhcpEnd;
	this.LeaseTime 	= LeaseTime;
	this.Enable 	= Enable;  
	this.option60 	= option60;
	if(SlaDNS == "")
	{
		this.SlaPriDNS	= "";  
		this.SlaSecDNS  = "";
	}
	else
	{
		var SlaDnss 	= SlaDNS.split(',');
		this.SlaPriDNS	= SlaDnss[0];  
		this.SlaSecDNS  = SlaDnss[1];
		
		if (SlaDnss.length <=1)
		{
		    this.SlaSecDNS = "";
		}
	}
	
	this.ntpsvr  = ntpsvr; 
	this.Option43 = Option43;
	this.NormalUserEnable = NormalUserEnable;
}
function condhcpst(domain,enable,option60,option60mode,ipstart,ipend,gateway,gatewaymask,dnss,dhcpleasetime,normaluserenable)
{
	this.Domain 	= domain;
	this.Gateway 	    = gateway;
	this.Gatewaymask    = gatewaymask;
	this.DhcpStart 	= ipstart;
	this.DhcpEnd 	= ipend;
	this.LeaseTime 	= dhcpleasetime;
	this.Enable 	= enable;  
	this.Option60 	= option60;
	this.Option60mode = option60mode;
	if(dnss == "")
	{
		this.SlaPriDNS	= "";  
		this.SlaSecDNS  = "";
	}
	else
	{
		var SlaDnss 	= dnss.split(',');
		this.SlaPriDNS	= SlaDnss[0];  
		this.SlaSecDNS  = SlaDnss[1];
		
		if (SlaDnss.length <=1)
		{
		    this.SlaSecDNS = "";
		}
	}
	
	this.NormalUserEnable = normaluserenable;
}


var SlaveDhcpInfos;

if (conditionpoolfeature == 1)
{
    SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,StartIP|EndIP|LeaseTime|DHCPEnable|Option60|NTPList|NormalUserEnable|DNSList ,dhcpcnst1);%>;  
}
else
{
    SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,StartIP|EndIP|LeaseTime|DHCPEnable|Option60|NTPList|Option43|NormalUserEnable|DNSList ,dhcpcnst);%>;  
}
var ConditionDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.{i}, Enable|VendorClassID|VendorClassIDMode|MinAddress|MaxAddress|IPRouters|SubnetMask|DNSServers|DHCPLeaseTime|X_HW_NormalUserEnable ,condhcpst);%>; 


function SetDHCPServerDisplay(value)
{
	if ( value == 1 || value == '1' )
	{
		setDisable("mainstartipaddr",0);
		setDisable("mainendipaddr",0);
		setDisable("MainLeasedTime",0);
		setDisable("maindhcpLeasedTimeFrag",0);
	}
	else
	{
		setDisable("mainstartipaddr",1);
		setDisable("mainendipaddr",1);
		setDisable("MainLeasedTime",1);
		setDisable("maindhcpLeasedTimeFrag",1);
	}
}

function SetMainDHCPServer()
{
	var enable = getSelectVal('dhcpSrvType');
	SetDHCPServerDisplay(enable);
}

function GetCurrentLoginIP()
{
	var CurUrlIp = (window.location.host).toUpperCase();
	
	return CurUrlIp;
}

function CheckParaDhcp1() 
{
	var result = false;
	var ethIpAddress = getValue('LanHostIP');
	var ethSubnetMask = getValue('LanHostMask');
	var ethstartipaddr = getValue('mainstartipaddr');
	var ethendipaddr = getValue('mainendipaddr');

	if ( isValidIpAddress(ethIpAddress) == false ) 
	{
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	if ( isValidSubnetMask(ethSubnetMask) == false ) 
	{
		AlertEx(dhcp_language['bbsp_subnetmaskmh'] + ethSubnetMask + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	  
	if(isHostIpWithSubnetMask(ethIpAddress, ethSubnetMask) == false)
	{
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	if ( isBroadcastIp(ethIpAddress, ethSubnetMask) == true ) {
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}

	if (false == isSameSubNet(ethstartipaddr, ethSubnetMask, ethIpAddress, ethSubnetMask))
	{
	     AlertEx(dhcp_language['bbsp_conditioncheck_tde']);
	     return false;
	}
	
	if (false == isSameSubNet(ethendipaddr, ethSubnetMask, ethIpAddress, ethSubnetMask))
	{
	     AlertEx(dhcp_language['bbsp_conditioncheck_tde']);
	     return false;
	}
	
	
    var Reboot = (GetPolicyRouteListLength(PolicyRouteListAll, "SourceIP") > 0 && getValue('LanHostIP') != LanIpInfos[0].ipaddr) ? dhcp_language['bbsp_resetont']:"";
	result = true;
	if ((getValue('LanHostIP') != LanIpInfos[0].ipaddr) && (GetCurrentLoginIP() == LanIpInfos[0].ipaddr))
	{
		result = ConfirmEx(dhcp_language['bbsp_dhcpconfirmnote']+Reboot);
	}
	
	return result;
}

function CheckParaDhcp2() 
{
	var IpMin;
	var IPMax;
	var ethIpAddress = getValue('LanHostIP');
	var ethSubnetMask = getValue('LanHostMask');
	var mainstartipaddr = getValue('mainstartipaddr');
	var mainendipaddr = getValue('mainendipaddr');
	var MainLeasedTime = getValue('MainLeasedTime');
	var maindhcpLeasedTimeFrag = getSelectVal('maindhcpLeasedTimeFrag');
	var SlaveDhcpEnable = '';
	if (1 == getSelectVal('dhcpSrvType'))
	{
        if (isValidIpAddress(mainstartipaddr) == false)
        {
            AlertEx(dhcp2_language['bbsp_pridhcpstipinvalid']);
            return false;
        }

        if (isBroadcastIp(mainstartipaddr, ethSubnetMask) == true)
        {
            AlertEx(dhcp2_language['bbsp_pridhcpstipinvalid']);
            return false;
        }

        if (false == isSameSubNet(mainstartipaddr,ethSubnetMask,ethIpAddress,ethSubnetMask))
        {
            AlertEx(dhcp2_language['bbsp_pridhcpstipmustsamesubhost']);
            return false;
        }

        if (isValidIpAddress(mainendipaddr) == false) 
        {
            AlertEx(dhcp2_language['bbsp_dhcpendipinvalid']);
            return false;
        }

        if(isBroadcastIp(mainendipaddr, ethSubnetMask) == true)
        {
            AlertEx(dhcp2_language['bbsp_dhcpendipinvalid']);
            return false;
        }

        if (false == isSameSubNet(mainendipaddr,ethSubnetMask,ethIpAddress,ethSubnetMask))
        {
            AlertEx(dhcp2_language['bbsp_pridhcpedipmustsamesubhost']);
            return false;
        }

        if (!(isEndGTEStart(mainendipaddr, mainstartipaddr))) 
        {
            AlertEx(dhcp2_language['bbsp_priendipgeqstartip']);
            return false;
        }
		if(PolicyRouteNum > 0)
      	{
			var IpStartNew = mainstartipaddr.split('.');
			var IpEndNew = mainendipaddr.split('.');
			var IpMinNew = parseInt(IpStartNew[3]);
			var IpMaxNew = parseInt(IpEndNew[3]);
			
			var IpStartOld = MainDhcpRange[0].startip.split('.');
			var IpEndOld = MainDhcpRange[0].endip.split('.');
			var IpMinOld = parseInt(IpStartOld[3]);
			var IpMaxOld = parseInt(IpEndOld[3]);
			if (IpMinNew > IpMinOld || IpMaxNew < IpMaxOld)
			{
				AlertEx(dhcp2_language['bbsp_ippoolpolicyrouteinvalid']);
				return false;
			}
		}

        if (false == checkLease("bbsp_pripool",MainLeasedTime,maindhcpLeasedTimeFrag,dhcp2_language))
        {
            return false;
        }
	
		if ( getValue('dnsMainPri') != '' && (isValidIpAddress(getValue('dnsMainPri')) == false || isAbcIpAddress(getValue('dnsMainPri')) == false))
		{
			AlertEx(dhcp2_language['bbsp_pripoolpridnsinvalid']);
			 return false;
		}
			
		if ( getValue('dnsMainSec') != '' && (isValidIpAddress(getValue('dnsMainSec')) == false || isAbcIpAddress(getValue('dnsMainSec')) == false))
		{
			AlertEx(dhcp2_language['bbsp_pripoolsecdndinvalid']);
			return false;
		}
	}
	
	if (!((curUserType != sysUserType) && ("1" == norightslavefeature)))
	{
		if ((conditionpoolfeature == 1) && (ConditionDhcpInfos.length > 1))
		{
			SlaveDhcpEnable = ConditionDhcpInfos[0].Enable;
		}
		else
		{
			SlaveDhcpEnable = SlaveDhcpInfos[0].Enable;
		}
		if ((1 == SlaveDhcpEnable) && ("0" == slv_independency) && (1 != getSelectVal("dhcpSrvType")))
		{
			AlertEx(dhcp2_language['bbsp_startsecdhcp']);
			return false;		
		}
	}
    setDisable('btnApply', 1);
    return true;
}

function CheckForm() 
{
	if (false == CheckParaDhcp1())
	{
		LoadFrame();
		return false;
	}
	
	if (false == CheckParaDhcp2())
	{
		LoadFrame();
		return false;
	}

    return true;
}


function ApplyConfig()
{
	 if(false == CheckForm())
	 {
		return false;
	 }
	 
    if (1 == ClassAIpSupportFlag)
    {
        for (var i = 0;i < GetWanList().length;i++)
        {
            var CurrentWan = GetWanList()[i];
            if (CurrentWan.IPv4IPAddress != '0.0.0.0' && CurrentWan.IPv4SubnetMask != '0.0.0.0'
                && CurrentWan.IPv4IPAddress != '' && CurrentWan.IPv4SubnetMask != '' )
            {
                if (getValue('LanHostIP') == CurrentWan.IPv4IPAddress)
                {
                    AlertEx(dhcp2_language['bbsp_ipdifwan']);
                    return false;
                }
            if (CurrentWan.IPv4Enable == "1")
            {
                if(true==isSameSubNet(getValue('LanHostIP'), getValue('LanHostMask'),
                                      CurrentWan.IPv4IPAddress, CurrentWan.IPv4SubnetMask))
                {
                      AlertEx(dhcp2_language['bbsp_lanwanipcheck']);		
                      return false;
                }
            }
        }
        }
    }
	var Form = new webSubmitForm();
	Form.addParameter('x.IPInterfaceIPAddress',getValue('LanHostIP'));
	Form.addParameter('x.IPInterfaceSubnetMask',getValue('LanHostMask'));		
	Form.addParameter('z.IPRouters',getValue('LanHostIP'));
	Form.addParameter('z.SubnetMask',getValue('LanHostMask'));		
	Form.addParameter('z.DHCPServerEnable',getSelectVal('dhcpSrvType'));
	var DnsMStr = getValue('dnsMainPri') + ',' + getValue('dnsMainSec');
	if ( getValue('dnsMainPri') == 0)
	{
		DnsMStr = getValue('dnsMainSec');
	}
	if ( getValue('dnsMainSec') == 0)
	{
		DnsMStr = getValue('dnsMainPri');
	} 
	Form.addParameter('z.X_HW_DNSList',DnsMStr);     
	Form.addParameter('z.MinAddress',getValue('mainstartipaddr'));
	Form.addParameter('z.MaxAddress',getValue('mainendipaddr'));
	
    var urlpara = 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1'
				  +	'&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement'
				  + '&RequestFile=html/bbsp/dhcpservercfg/dhcp2tde.asp';
	
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    var url = 'set.cgi?' + urlpara;
	
    setDisable('dhcpSrvType',1);
	Form.setAction(url);
	Form.submit();
}	


function setLease(dhcpLease, flag)
{
    var i = 0;
    var timeUnits = 604800;
    var infinite = ((dhcpLease == "-1") || (dhcpLease == "4294967295"));

    for(i = 0; i < 4; i++)
    {
        if (i == 0 )
        {
            timeUnits  = 604800;
        }
        else if (i == 1)
        {
            timeUnits  = 86400;
        }
        else if (i == 2)
        {
            timeUnits  = 3600;
        }
        else
        {
            timeUnits  = 60;                    
        }
          
        if ( true == isInteger(dhcpLease / timeUnits) )
        {
            break; 
        }          
    }

  	if ( flag == "slave" )
  	{
	    setSelect('dhcpLeasedTimeFrag', timeUnits);
	    if(infinite)
			setText('SlaveLeasedTime', dhcp2_language['bbsp_infinitetime']);
	    else
			setText('SlaveLeasedTime', dhcpLease /timeUnits);	
  	}
	else if ( flag == "main" )
	{
	    setSelect('maindhcpLeasedTimeFrag', timeUnits);
	    if(infinite)
			setText('MainLeasedTime', dhcp2_language['bbsp_infinitetime']);
	    else
			setText('MainLeasedTime', dhcpLease /timeUnits);	
	}
	else
	{
		AlertEx(dhcp2_language['bbsp_poolinvalid']);
	}

}

function setMainDhcp()
{
	setSelect('dhcpSrvType', MainDhcpRange[0].enable);
	setText('LanHostIP', LanIpInfos[0].ipaddr);
	setText('LanHostMask', LanIpInfos[0].subnetmask);
	setText('mainstartipaddr', MainDhcpRange[0].startip);
	setText('mainendipaddr', MainDhcpRange[0].endip);
	setText('dnsMainPri', MainDhcpRange[0].MainPriDNS);
	setText('dnsMainSec', MainDhcpRange[0].MainSecDNS);
	setLease(dhcpmain.leasetime, "main");
	SetDHCPServerDisplay(MainDhcpRange[0].enable);
}

function InitLeasedTime()
{
	var LeasedTimeIdArray = ["maindhcpLeasedTimeFrag", "dhcpLeasedTimeFrag"];
	for(var i = 0; i < LeasedTimeIdArray.length; i++)
	{
		var LeasedTimeId = "#" + LeasedTimeIdArray[i];
		$(LeasedTimeId).append('<option value="60">'+ dhcp2_language['bbsp_minute'] + '</option>');
		$(LeasedTimeId).append('<option value="3600">'+ dhcp2_language['bbsp_hour'] + '</option>');	
		$(LeasedTimeId).append('<option value="86400">'+ dhcp2_language['bbsp_day'] + '</option>');	
		$(LeasedTimeId).append('<option value="604800">'+ dhcp2_language['bbsp_week'] + '</option>');
	}	
}

function updateIpByMask(ipmain, mask, iprelated)
{
	var i = 0;
	var ipnew = ['0','0','0','0'];
	var maskParts = mask.split('.');
	var ipmainParts = ipmain.split('.');
	var iprelatedParts = iprelated.split('.');

	for (i = 0; i < 4; i++) 
	{
		var num = parseInt(maskParts[i]);
		var ip1 = parseInt(ipmainParts[i]) & num;
		var ip2 = parseInt(iprelatedParts[i]) & (0xff & ~num);
		ipnew[i] = parseInt(ip1 + ip2);
	}	
    return 	ipnew[0]+'.'+ipnew[1]+'.'+ipnew[2]+'.'+ipnew[3];
}

function GetIPRange()
{
	var ethIpAddress = getValue('LanHostIP');
	var ethSubnetMask = getValue('LanHostMask');

	if ( isValidIpAddress(ethIpAddress) == false ) 
	{
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	  
	if(isHostIpWithSubnetMask(ethIpAddress, ethSubnetMask) == false)
	{
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}
	if ( isBroadcastIp(ethIpAddress, ethSubnetMask) == true )
	{
		AlertEx(dhcp_language['bbsp_ipmhaddrp'] + ethIpAddress + dhcp_language['bbsp_isinvalidp']);
		return false;
	}

	var ip1 = updateIpByMask(ethIpAddress, ethSubnetMask, getValue('mainstartipaddr'));
	setText('mainstartipaddr', ip1);
	var ip2 = updateIpByMask(ethIpAddress, ethSubnetMask, getValue('mainendipaddr'));
	setText('mainendipaddr', ip2);
}

function LoadFrame() 
{
	setMainDhcp();
}

</script>
</head>
<body onLoad="LoadFrame();" class="iframebody"> 
<div style="height:20px;"></div>
<div id="FuctionPageArea" class="FuctionPageAreaCss">
<div id="FunctionPageTitle" class="FunctionPageTitleCss">
<span id="PageTitleText" class="PageTitleTextCss" BindText="bbsp_localnetwork"></span>
</div>
<div style="height:30px;"></div>
<div id="DhcpServerPanel">
<form id = "PriPoolConfigForm">
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="LanHostIP"        		RealType="TextBox"      	  DescRef="bbsp_lanhostmh1"        	   RemarkRef="Empty"     				ErrorMsgRef="Empty"    Require="TRUE"    BindField="Empty"   InitValue="Empty"      MaxLength="15" ClickFuncApp="onblur=GetIPRange"/>
<li   id="LanHostMask"        		RealType="TextBox"      	  DescRef="bbsp_maskmh1"        	   RemarkRef="Empty"     				ErrorMsgRef="Empty"    Require="TRUE"    BindField="Empty"   InitValue="Empty"      MaxLength="15"/>
<li   id="dhcpSrvType"              RealType="DropDownList"       DescRef="bbsp_enablepridhcpmh1"      RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"  Elementclass="Select"   
InitValue="[{TextRef:'bbsp_dhcpon',Value:'1'},{TextRef:'bbsp_dhcpoff',Value:'0'}]" ClickFuncApp="onchange=SetMainDHCPServer"/>
<li   id="mainstartipaddr"          RealType="TextBox"            DescRef="bbsp_startipmh1"            RemarkRef="Empty"                    ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"       InitValue="Empty"  MaxLength="15"/>
<li   id="mainendipaddr"            RealType="TextBox"            DescRef="bbsp_endipmh1"              RemarkRef="Empty"     			    ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"           InitValue="Empty"  MaxLength="15"/>
<li   id="MainLeasedTime"           RealType="TextOtherBox"       DescRef="bbsp_leasedmh"             RemarkRef="Empty"    			        ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"   Elementclass="TextBox_2"    InitValue="[{Type:'select',Item:[{AttrName:'id',AttrValue:'maindhcpLeasedTimeFrag'},{AttrName:'class',AttrValue:'Select_2'}]}]"/>
</table>
<script>
var TableClass = new stTableClass("PageSumaryTitleCss tablecfg_title width_per40", "tablecfg_right width_per60", "", "Select");
var PriPoolConfigFormList = new Array();
PriPoolConfigFormList = HWGetLiIdListByForm("PriPoolConfigForm");
HWParsePageControlByID("PriPoolConfigForm", TableClass, dhcp2_language, null);
setDisplay('MainLeasedTimeRow',0);
</script>
</form>

<form id = "PriDnsConfigForm">
<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<tr><td BindText="bbsp_dnsserver" class="PageSumaryTitleCss padleft"></td></tr></table> 

<table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
<li   id="dnsMainPri"               RealType="TextBox"            DescRef="bbsp_pridnsmh1"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
<li   id="dnsMainSec"               RealType="TextBox"            DescRef="bbsp_secdnsmh1"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
</table>
<script>
var PriDnsConfigFormList = new Array();
PriDnsConfigFormList = HWGetLiIdListByForm("PriDnsConfigForm");
HWParsePageControlByID("PriDnsConfigForm", TableClass, dhcp2_language, null);
</script>
</form>
<div style="height:30px;"></div>
</div>
</div>

<div style="height:30px;"></div>
<table width="100%" border="0" cellspacing="0" cellpadding="0" class=""> 
<tr> 
  <td class="width_per3"></td>
  <td class="table_submit" > 
   <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
  <button id="btnApply" name="btnApply" type="button" class="BluebuttonGreenBgcss width_120px" style="margin-left: 0px;" onClick="ApplyConfig();"><script>document.write(dhcp2_language['bbsp_app']);</script> </button> 
</tr> 
</table> 

<script>
	InitLeasedTime();
	ParseBindTextByTagName(dhcp2_language, "span",  1);
	ParseBindTextByTagName(dhcp2_language, "td",    1);
	ParseBindTextByTagName(dhcp2_language, "input", 2);
</script>

</body>
</html>
