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
<script language="javascript" src="../common/dhcpinfo.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="JavaScript" src="<%HW_WEB_GetReloadCus(html/bbsp/dhcpservercfg/dhcp2.cus);%>"></script>
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
</style>	
<script language="JavaScript" type="text/javascript">
var curUserType='<%HW_WEB_GetUserType();%>';
var normaluserenable;
var sysUserType='0';
var curCfgModeWord ='<%HW_WEB_GetCfgMode();%>'; 
var conditionpoolfeature ='<%HW_WEB_GetFeatureSupport(BBSP_FT_DHCPS_COND_POOL);%>';
var hiderelay125feature ='<%HW_WEB_GetFeatureSupport(FT_NOMAL_HIDE_DHCP_RELAY_125);%>';
var norightslavefeature ='<%HW_WEB_GetFeatureSupport(FT_NOMAL_NO_RIGHT_SLAVE_POOL);%>';
var slv_independency='<%HW_WEB_GetFeatureSupport(FT_SLAVE_NO_ASSIGN_ADDR);%>';
var SonetFlag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var SonetHN8055QFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_SONET_HN8055Q);%>';
var TDEMode = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_TDE);%>';
var BZTLFMode = '<%HW_WEB_GetFeatureSupport(FT_TDE_BRAZIL);%>';
var option240feature = (TDEMode == '1' || BZTLFMode == '1');
var ConditionPoolAddFlag = 0;
var ClassAIpSupportFlag='<%HW_WEB_GetFeatureSupport(BBSP_FT_SUPPORT_CLASS_A_IP);%>';
var selIndex = -1;

function IsSonetUser()
{
	if((SonetFlag == '1') 
		&& curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

function IsSonetHN8055QUser()
{
	if((SonetHN8055QFlag == '1') 
		&& curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

function IsSonetNewNormalUser()
{
	if ((('SONET' == curCfgModeWord.toUpperCase()) || ('SONET8045Q' == curCfgModeWord.toUpperCase())) && (curUserType != '0'))
	{
		return true;
	}
	else
	{
		return false;
	}
}

function IsOSKNormalUser()
{
	if ('OSK' == CfgModeWord.toUpperCase() && curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

function IsAISNormalUser()
{
	if ('AIS' == CfgModeWord.toUpperCase() && curUserType != '0')
	{
		return true;
	}
	else
	{
		return false;
	}
}

var TELMEX = false;

if (GetCfgMode().TELMEX == "1")
{
	TELMEX = true;
}
else
{
	TELMEX = false;
}

function loadlanguage()
{
	var all = document.getElementsByTagName("td");
	for (var i = 0; i <all.length ; i++) 
	{
		var b = all[i];
		if(b.getAttribute("BindText") == null)
		{
			continue;
		}
		setObjNoEncodeInnerHtmlValue(b, dhcp2_language[b.getAttribute("BindText")]);
	}
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
	this.IPRange = ipstart + ' -<br> ' + ipend;

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
	
	this.dnssDis = this.SlaPriDNS+'<br>'+this.SlaSecDNS;
	
	this.NormalUserEnable = normaluserenable;
}

function stDhcpConditionOption(domain,enable,tag,value)
{
	this.domain 	      = domain;
	this.enable           = enable;
	this.tag              = tag;
	this.value            = value;
	this.type            = "ConditionPool"
}

function dhcpmainst(domain,enable,startip,endip,leasetime,l2relayenable,HGWstartip,HGWendip,STBstartip,STBendip,Camerastartip,Cameraendip,Computerstartip,Computerendip,Phonestartip,Phoneendip,MainDNS,X_HW_Option125Enable,DNSServers,iprouters,subnetmask)
{
	this.domain 	= domain;
	this.enable		= enable;
	this.startip	= startip;
	this.endip		= endip;
	this.leasetime  = leasetime;
	this.l2relayenable = l2relayenable;
	this.HGWstartip = HGWstartip;
	this.HGWendtip = HGWendip;
	this.STBstartip = STBstartip;
	this.STBendtip = STBendip;	
	this.Camerastartip = Camerastartip;
	this.Cameraendtip = Cameraendip;
	this.Computerstartip = Computerstartip;
	this.Computerendtip = Computerendip;		
	this.Phonestartip = Phonestartip;
	this.Phoneendtip = Phoneendip;	
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
	this.X_HW_Option125Enable = X_HW_Option125Enable;
	this.iprouters = iprouters;
	this.subnetmask = subnetmask;
}

function stipaddr(domain,enable,ipaddr,subnetmask)
{
	this.domain		= domain;
	this.enable		= enable;
	this.ipaddr		= ipaddr;
	this.subnetmask	= subnetmask;	
}

function stipaddrpool(startip,endip)
{
	this.startip	= startip;
	this.endip	= endip;
}

function DhcpServerInfo()
{
	this.domain = null;
	this.MainEnable = "";
}
var PolicyRouteNum = 0;

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

var SlaveDhcpInfos;

if (conditionpoolfeature == 1)
{
    SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,StartIP|EndIP|LeaseTime|DHCPEnable|Option60|NTPList|NormalUserEnable|DNSList ,dhcpcnst1);%>;  
}
else
{
    SlaveDhcpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaSlaveDhcpPool, InternetGatewayDevice.X_HW_DHCPSLVSERVER,StartIP|EndIP|LeaseTime|DHCPEnable|Option60|NTPList|Option43|NormalUserEnable|DNSList ,dhcpcnst);%>;  
}

var MainDhcpRange = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaMainDhcpPool, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement,DHCPServerEnable|MinAddress|MaxAddress|DHCPLeaseTime|X_HW_DHCPL2RelayEnable|X_HW_HGWStart|X_HW_HGWEnd|X_HW_STBStart|X_HW_STBEnd|X_HW_CameraStart|X_HW_CameraEnd|X_HW_ComputerStart|X_HW_ComputerEnd|X_HW_PhoneStart|X_HW_PhoneEnd|X_HW_DNSList|X_HW_Option125Enable|DNSServers|IPRouters|SubnetMask,dhcpmainst);%>;  

var LanIpInfos = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_FilterSlaveLanHostIp, InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.{i},Enable|IPInterfaceIPAddress|IPInterfaceSubnetMask,stipaddr);%>;
if (LanIpInfos[1] == null)
{
    LanIpInfos[1] = new stipaddr("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2", "", "", ""); 
}

var dhcpmain = MainDhcpRange[0];

var option240 = "";
var option240instance = 0;
var ConditionDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.{i}, Enable|VendorClassID|VendorClassIDMode|MinAddress|MaxAddress|IPRouters|SubnetMask|DNSServers|DHCPLeaseTime|X_HW_NormalUserEnable ,condhcpst);%>; 

var DhcpConditionOptions = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.1.DHCPOption.{i}, Enable|Tag|Value, stDhcpConditionOption);%>;
var DhcpConditionOptionsnum = DhcpConditionOptions.length - 1;

if (option240feature == 1)
{
    for (var i = 0; i < DhcpConditionOptionsnum; i++)
    {
        if (DhcpConditionOptions[i].tag == "240")
	    {
	        option240instance = i + 1;
		    var tmp  = DhcpConditionOptions[i].value;
		    option240 = Base64Decode(tmp);
	    }
    }
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


function setAllDisable()
{
	setDisable('DHCPEnable',1);
	setDisable('SlaveEthStart',1);
	setDisable('dhcpLeasedTimeFrag',1);
	setDisable('SlaveEthEnd',1);	
	setDisable('SlaveLeasedTime',1);
	setDisable('dhcpOption60',1);
	setDisable('dnsSecPri',1);
	setDisable('dnsSecSec',1);

	
	if (conditionpoolfeature == 1)
	{       
	    setDisable('Option60Mode',1);
	}
	else
	{
		setDisable('dhcpOption43',1);
		setDisable('ntpserver',1);
	}
}

function LoadFrame() 
{
	if((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))
	{
		setDisplay( "SecondaryServerPool" , 0 );
	}
	if((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
	{
		setDisplay('dhcpL2relayRow',0);
		setDisplay( "SecondaryServerPool" , 0 );
		setDisplay("dnsSecPriRow",0);
		setDisplay("dnsSecSecRow",0);
		setDisplay('dhcpMainOption125Row', 0);
	}
	if(((hiderelay125feature == '1') && (curUserType != sysUserType))
		|| (true == IsSonetHN8055QUser()) ||(true == IsSonetNewNormalUser()))
	{
		setDisplay('dhcpL2relayRow',0);
		setDisplay('dhcpMainOption125Row',0);
	}			
	
	if ("1" == GetCfgMode().DT_HUNGARY)
    {
        setDisplay( "SecondaryServerPool" , 0 );
		setDisplay("dnsSecPriRow",0);
		setDisplay("dnsSecSecRow",0);		
    }
	
	with ( document.forms[0] ) 
	{    
		setMainDhcp();
		setDhcp(LanIpInfos[1]);		
    } 
   
    if (curUserType != sysUserType && false == IsSonetUser())
	{
		setDisable("dnsMainPri",1);
		setDisable("dnsMainSec",1);	
		setDisable("dnsSecPri",1);
		setDisable("dnsSecSec",1);
	}
	
	if ((curUserType != sysUserType)&& ((true == IsOSKNormalUser()) || (true == IsAISNormalUser())))
    {
		setDisable("dnsMainPri",0);
		setDisable("dnsMainSec",0); 
		setDisable("dnsSecPri",0);
		setDisable("dnsSecSec",0);
    }

	loadlanguage();
	
	var slavepoolenable;
	if ((conditionpoolfeature == 1) && (ConditionDhcpInfos.length > 1))
	{
		normaluserenable = ConditionDhcpInfos[0].NormalUserEnable;
		slavepoolenable = ConditionDhcpInfos[0].Enable;
		
		setDisplay('dhcpOption43Row', 0);
		setDisplay('ntpserverRow', 0);
	}
	else
	{       
		normaluserenable = SlaveDhcpInfos[0].NormalUserEnable;
		slavepoolenable = SlaveDhcpInfos[0].Enable;
		setDisplay('Option60ModeRow', 0);	
	}
	
	if ((option240feature == 1) && (conditionpoolfeature == 1))
	{
	    setDisplay('dhcpOption240Row', 1);
	}
	else
	{
	    setDisplay('dhcpOption240Row', 0);
	}
	
	if(slavepoolenable == 1)
	{
		setDisplay("dnsSecPriRow",1);
		setDisplay("dnsSecSecRow",1);
	}
	setDisplay('SecondaryServerPool', 1);

	
	if((("1" == norightslavefeature) && (curUserType != sysUserType))
		|| (true == IsSonetHN8055QUser()))
	{
		setDisplay('SecondaryServerPool', 0);
	}
	
    if((curUserType != sysUserType)&&(normaluserenable == '0'))
	{
		setAllDisable();
	}
}

function setMainDhcp()
{
	with(document.forms[0])
	{
		setCheck('dhcpSrvType', MainDhcpRange[0].enable);
		setCheck('dhcpL2relay', MainDhcpRange[0].l2relayenable);
        setCheck('dhcpMainOption125', MainDhcpRange[0].X_HW_Option125Enable);
        
		setElementInnerHtmlById("LanHostIP", MainDhcpRange[0].iprouters);
		setElementInnerHtmlById("LanHostMask", MainDhcpRange[0].subnetmask);
		setText('mainstartipaddr', MainDhcpRange[0].startip);
		setText('mainendipaddr', MainDhcpRange[0].endip);
		if(GetCfgMode().PCCWHK != "1")
		{
			setText('dnsMainPri', MainDhcpRange[0].MainPriDNS);
			setText('dnsMainSec', MainDhcpRange[0].MainSecDNS);
		}
		setLease(dhcpmain.leasetime, "main");
	
		SetDHCPServerDisplay(MainDhcpRange[0].enable);
	}
}

function setDhcp(dhcpst)
{
	with(document.forms[0])
	{
		if ((conditionpoolfeature == 1) && (ConditionDhcpInfos.length > 1))
		{		
		    setText('SlaveEthStart', ConditionDhcpInfos[0].DhcpStart);
		    setText('SlaveEthEnd', ConditionDhcpInfos[0].DhcpEnd);
			setText('SlaveIpAddr', ConditionDhcpInfos[0].Gateway);
			setText('SlaveMask', ConditionDhcpInfos[0].Gatewaymask);
			setDisable('SlaveIpAddr', 0);
			setDisable('SlaveMask', 0);
			setText('dhcpOption60', ConditionDhcpInfos[0].Option60);
		    setSelect('Option60Mode', ConditionDhcpInfos[0].Option60mode);
		    if(GetCfgMode().PCCWHK != "1")
		    {
			    setText('dnsSecPri', ConditionDhcpInfos[0].SlaPriDNS);
			    setText('dnsSecSec', ConditionDhcpInfos[0].SlaSecDNS);
		    }
		    
		    setLease(ConditionDhcpInfos[0].LeaseTime, "slave");
		    setCheck('DHCPEnable', ConditionDhcpInfos[0].Enable);
			
			if (option240feature == 1)
			{
			    setText('dhcpOption240', option240);
			}
		}
		else
		{
		    setText('SlaveEthStart', SlaveDhcpInfos[0].dhcpStart);
		    setText('SlaveEthEnd', SlaveDhcpInfos[0].dhcpEnd);
			setText('SlaveIpAddr', LanIpInfos[1].ipaddr);
			setText('SlaveMask', LanIpInfos[1].subnetmask);
			setDisable('SlaveIpAddr', 1);
			setDisable('SlaveMask', 1);
			setText('dhcpOption60', SlaveDhcpInfos[0].option60);
		    if(GetCfgMode().PCCWHK != "1")
		    {
			setText('dnsSecPri', SlaveDhcpInfos[0].SlaPriDNS);
			setText('dnsSecSec', SlaveDhcpInfos[0].SlaSecDNS);
		    }
		    setText('ntpserver', SlaveDhcpInfos[0].ntpsvr);
		    setText('dhcpOption43', SlaveDhcpInfos[0].Option43);
		    setLease(SlaveDhcpInfos[0].LeaseTime, "slave");

		    setCheck('DHCPEnable', SlaveDhcpInfos[0].Enable);
		}
	}
}

function IsDhcpOption60Valid(value)
{
    var uiDotCount = 0;
    var i;
    var chDot = '*';
    var uiLength = value.length;

    for (i = 0; i < value.length; i++)
    {
	    if(value.charAt(i)==chDot)
        {
            uiDotCount++; 
        }
    }   

    if (uiDotCount > 2)
    {
        return false;
    }

    if (0== uiDotCount)
    {
        return true;
    }

    if ((1 == uiDotCount) 
        && (value.charAt(0) != chDot) 
        && (value.charAt(uiLength-1) != chDot))
    {
        return false;
    }

    if ((2 == uiDotCount) 
        && ((value.charAt(0) != chDot) 
        || (value.charAt(uiLength-1) != chDot)))
    {
        return false
    }
    return true;
}


function  dnsipcheck(ip)
{  
     if (ip.length == 0)
	 {
	     return true;
	 }
	 if((isAbcIpAddress(ip) == false) || (isValidIpAddress(ip) == false)  )
	 {
		  return false;
	 }
	return true;
}

function ParseNtpServerResult(string)
{   
    var splitobj = ",";
    var subString = string.split(splitobj);
    var stringlength = 0;
	
    stringlength = string.length;
		
    if (subString.length > 0 )
    {
	    for ( var i = 0 ; i < subString.length ; i++ )
		{
		     if(false == dnsipcheck(subString[i]))
		    {
				AlertEx(dhcp2_language['bbsp_ntpserverinvalid']);
				return false;
		    }
		}
	}
	return true;
}
     

function ParseOption60Result(string)
{   
    var splitobj = ",";
    var subString = string.split(splitobj);
    
    if (subString.length > 0 )
    {
	    for ( var i = 0 ; i < subString.length ; i++ )
	    {
	          if (subString[i] == "")
	          {
	              return false;
	          }
	          
		  if (IsDhcpOption60Valid(subString[i]) == false)
		  {
				return false;
		  }
	   }
    }
    
    return true;
}

function ParseConditionOption60Result(string, mode)
{
    var splitobj = ",";
    var subString = string.split(splitobj);
    
    var i = 0;
    var chDot = '*';
    
    if (subString.length > 1)
    {   
        if (mode == "Exact")
        {
            if (ParseOption60Result(string) ==  false)
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    else
    {
        for (i = 0; i < string.length; i++)
        {
	    if(string.charAt(i) == chDot)
            {
                return false;
            }
        }      
    }
    
    return true;
}
        
function isHexaDigit(digit) {
   var hexVals = new Array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                           "A", "B", "C", "D", "E", "F", "a", "b", "c", "d", "e", "f");
   var len = hexVals.length;
   var i = 0;
   var ret = false;

   for ( i = 0; i < len; i++ )
      if ( digit == hexVals[i] ) break;

   if ( i < len )
      ret = true;

   return ret;
}

function IsDhcpOption43Valid(Option43)
{
    var uiDotCount = 0;
    var i;
    var uiLength = Option43.length;
	
	if (uiLength > 64)
	{
	    AlertEx(dhcp2_language['bbsp_option43leninvalid']);
	    return false;
	}
	
	if (('0' == Option43.charAt(0) && 'x' == Option43.charAt(1)) || ('0' == Option43.charAt(0) && 'X' == Option43.charAt(1)))
	{
	    if ((Option43.length)%2 == 1)
		{
		     AlertEx(dhcp2_language['bbsp_option43invalid']);
             return false;
		}
        for (i = 2; i < Option43.length; i++)
       {
	        if (isHexaDigit(Option43.charAt(i)) == false)
           {
		        AlertEx(dhcp2_language['bbsp_option43invalid']);
                return false;
           }
       }
   }	
    return true;
}
function CheckForm() 
{
   var IpMin;
   var IPMax;
   with ( document.forms[0] ) 
   {  
		if (1 == getCheckVal('dhcpSrvType'))
		{
	        if (isValidIpAddress(mainstartipaddr.value) == false)
	        {
	            AlertEx(dhcp2_language['bbsp_pridhcpstipinvalid']);
	            return false;
	        }

	        if (isBroadcastIp(mainstartipaddr.value, LanIpInfos[0].subnetmask) == true)
	        {
	            AlertEx(dhcp2_language['bbsp_pridhcpstipinvalid']);
	            return false;
	        }

	        if (false == isSameSubNet(mainstartipaddr.value,LanIpInfos[0].subnetmask,LanIpInfos[0].ipaddr,LanIpInfos[0].subnetmask))
	        {
	            AlertEx(dhcp2_language['bbsp_pridhcpstipmustsamesubhost']);
	            return false;
	        }

	        if (isValidIpAddress(mainendipaddr.value) == false) 
	        {
	            AlertEx(dhcp2_language['bbsp_dhcpendipinvalid']);
	            return false;
	        }

	        if(isBroadcastIp(mainendipaddr.value, LanIpInfos[0].subnetmask) == true)
	        {
	            AlertEx(dhcp2_language['bbsp_dhcpendipinvalid']);
	            return false;
	        }

	        if (false == isSameSubNet(mainendipaddr.value,LanIpInfos[0].subnetmask,LanIpInfos[0].ipaddr,LanIpInfos[0].subnetmask))
	        {
	            AlertEx(dhcp2_language['bbsp_pridhcpedipmustsamesubhost']);
	            return false;
	        }

	        if (!(isEndGTEStart(mainendipaddr.value, mainstartipaddr.value))) 
	        {
	            AlertEx(dhcp2_language['bbsp_priendipgeqstartip']);
	            return false;
	        }

			if(PolicyRouteNum > 0)
	      	{
				var IpStartNew = getValue('mainstartipaddr').split('.');
				var IpEndNew = getValue('mainendipaddr').split('.');
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
			
	        if (false == checkLease("bbsp_pripool",MainLeasedTime.value,maindhcpLeasedTimeFrag.value,dhcp2_language))
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

		if ((TELMEX != true)&&("1" != GetCfgMode().DT_HUNGARY)&&(!((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))) 
			&& (!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
			&& (!((curUserType != sysUserType) && ("1" == norightslavefeature))))
		{
			if (getCheckVal("DHCPEnable") == 1) 
			{
				if (("0" == slv_independency) && (1 != getCheckVal("dhcpSrvType")))
				{
					AlertEx(dhcp2_language['bbsp_startsecdhcp']);
					return false;				
				}
			}
		}
	}

    setDisable('btnApply', 1);
    setDisable('cancelValue', 1);
    return true;
    
}

function CheckFormConditionPool() 
{
   var IpMin;
   var IPMax;
   with ( document.forms[0] ) 
   {  	
	if ((TELMEX != true)&&("1" != GetCfgMode().DT_HUNGARY)&&(!((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))) 
		&& (!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
		&& (!((curUserType != sysUserType) && ("1" == norightslavefeature))))
	{
      if (getCheckVal("DHCPEnable") == 1) 
      {
		if (("0" == slv_independency) && (1 != getCheckVal("dhcpSrvType")))
		{
			AlertEx(dhcp2_language['bbsp_startsecdhcp']);
			return false;				
		}
		if (conditionpoolfeature == 1)
		{
            var conditionroute = getValue("SlaveIpAddr");
            var conditionmask = getValue("SlaveMask");

            if (isValidIpAddress(getValue("SlaveIpAddr")) == false) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipinvalid']);
    			return false;
    		}

            if (isValidSubnetMask(conditionmask) == false ) 
            {
                AlertEx(conditionmask + dhcp2_language['bbsp_aninvalidipaddr']);
                return false;
            }

			if (((LanIpInfos[0].subnetmask) != conditionmask) &&
				((LanIpInfos[1].subnetmask) != conditionmask)) 
            {
                AlertEx(conditionmask + dhcp2_language['bbsp_aninvalidipaddr']);
                return false;
            }

            if (isValidIpAddress(getValue("SlaveEthStart")) == false) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipinvalid']);
    			return false;
    		}

    		if (isBroadcastIp(getValue("SlaveEthStart"), conditionmask) == true)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipinvalid']);
    			return false;
    		}

    		if (false == isSameSubNet(getValue("SlaveEthStart"),conditionmask,conditionroute,conditionmask))
    		{
    			AlertEx(dhcp2_language['bbsp_pridhcpstipmustsamesubhost2']);
    			return false;
    		}

			if (true == isSameSubNet(LanIpInfos[0].ipaddr,LanIpInfos[0].subnetmask,conditionroute,conditionmask))
			{
				if (!((LanIpInfos[0].ipaddr == conditionroute) && (LanIpInfos[0].subnetmask == conditionmask)))
				{
					AlertEx(dhcp2_language['bbsp_pridhcpcondhcp']);
					return false;
				}
			}

    		if (isValidIpAddress(getValue("SlaveEthEnd")) == false) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipinvalid']);
    			return false;
    		}

    		if (isBroadcastIp(getValue("SlaveEthEnd"), conditionmask) == true)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipinvalid']);
    			return false;
    		}

    		if (false == isSameSubNet(getValue("SlaveEthEnd"),conditionmask,conditionroute,conditionmask))
    		{
    			AlertEx(dhcp2_language['bbsp_pridhcpedipmustsamesubhost2']);
    			return false;
    		}

    		if (!(isEndGTEStart(getValue("SlaveEthEnd"), getValue("SlaveEthStart")))) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipgeqstartip']);
    			return false;
    		}

    		if (getValue("SlaveEthStart") == conditionmask)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipdifroute']);
    			return false;
    		}

    		if (getValue("SlaveEthEnd") == conditionmask)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipdifroute']);
    			return false;
    		}
			
			if (option240feature == 1)
			{
			    var tmp = getValue('dhcpOption240');
	            var tmp1 = Base64Encode(tmp);
				
				if (isValidAscii(tmp) != '')
	            {
                    AlertEx(dhcp2_language['bbsp_option240invalid']);
                    return false;
	            }
				
				if (tmp1.length > 340)
				{
				    AlertEx(dhcp2_language['bbsp_option240leninvalid']);
                    return false;
				}
			}
		}
        else
		{
    		if (true == isSameSubNet(LanIpInfos[1].ipaddr,LanIpInfos[1].subnetmask,LanIpInfos[0].ipaddr,LanIpInfos[0].subnetmask))
    		{
    			AlertEx(dhcp2_language['bbsp_pridhcpstipmustsamesubhost2']);
    			return false;
    		}

    		if (isValidIpAddress(getValue("SlaveEthStart")) == false) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipinvalid']);
    			return false;
    		}

    		if (isBroadcastIp(getValue("SlaveEthStart"), LanIpInfos[1].subnetmask) == true)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipinvalid']);
    			return false;
    		}

    		if (false == isSameSubNet(getValue("SlaveEthStart"),LanIpInfos[1].subnetmask,LanIpInfos[1].ipaddr,LanIpInfos[1].subnetmask))
    		{
    			AlertEx(dhcp2_language['bbsp_pridhcpstipmustsamesubhost2']);
    			return false;
    		}

    		if (isValidIpAddress(getValue("SlaveEthEnd")) == false) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipinvalid']);
    			return false;
    		}

    		if (isBroadcastIp(getValue("SlaveEthEnd"), LanIpInfos[1].subnetmask) == true)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipinvalid']);
    			return false;
    		}

    		if (false == isSameSubNet(getValue("SlaveEthEnd"),LanIpInfos[1].subnetmask,LanIpInfos[1].ipaddr,LanIpInfos[1].subnetmask))
    		{
    			AlertEx(dhcp2_language['bbsp_pridhcpedipmustsamesubhost2']);
    			return false;
    		}

    		if (!(isEndGTEStart(getValue("SlaveEthEnd"), getValue("SlaveEthStart")))) 
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipgeqstartip']);
    			return false;
    		}

    		if (getValue("SlaveEthStart") == LanIpInfos[1].subnetmask)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpstartipdifroute']);
    			return false;
    		}

    		if (getValue("SlaveEthEnd") == LanIpInfos[1].subnetmask)
    		{
    			AlertEx(dhcp2_language['bbsp_secdhcpendipdifroute']);
    			return false;
    		}
      	}
		
		var timeLease = getValue('SlaveLeasedTime');
		if (false == checkLease("bbsp_secpool",timeLease,getSelectVal('dhcpLeasedTimeFrag'),dhcp2_language))
		{
				return false;
		}

		if(getValue('dhcpOption60').length == 0 )
		{
			AlertEx(dhcp2_language['bbsp_60required']);
			return false;
		}
		
		if (isValidAscii(getValue('dhcpOption60')) != '')
		{
			AlertEx(dhcp2_language['bbsp_60'] + getValue('dhcpOption60') + dhcp2_language['bbsp_60invalid']);
			return false;
		}
		 
		if(false == isSafeStringExc(getValue('dhcpOption60'),'#='))
		{
			AlertEx(dhcp2_language['bbsp_60'] + getValue('dhcpOption60') + dhcp2_language['bbsp_60invalid']);
			return false;
		}
		
		if (conditionpoolfeature == 1)
		{
		    var mode = getSelectVal('Option60Mode');
            if (ParseConditionOption60Result(getValue('dhcpOption60'), mode) == false)
            {
                AlertEx(dhcp2_language['bbsp_60'] + getValue('dhcpOption60') + dhcp2_language['bbsp_60invalid']);
				return false;
			}
		}
		else
		{
			if (ParseOption60Result(getValue('dhcpOption60')) == false)
			{
				AlertEx(dhcp2_language['bbsp_60'] + getValue('dhcpOption60') + dhcp2_language['bbsp_60invalid']);
				return false;
			}
		}
		if(GetCfgMode().PCCWHK != "1")
		{				
		     if ( getValue('dnsSecPri') != '' && (isValidIpAddress(getValue('dnsSecPri')) == false || isAbcIpAddress(getValue('dnsSecPri')) == false))
		     {
		         AlertEx(dhcp2_language['bbsp_secpoolpridnsinvalid']);
			 return false;
		     }
		
		     if ( getValue('dnsSecSec') != '' && (isValidIpAddress(getValue('dnsSecSec')) == false || isAbcIpAddress(getValue('dnsSecSec')) == false))
		     {
		        AlertEx(dhcp2_language['bbsp_secpoolsecdnsinvalid']);
		        return false;
		     }
	       } 
	       
 
	       var ntpip = getValue('ntpserver');
               var option43 = getValue('dhcpOption43');
	
               if (ntpip.length !=0)
               {
	           if (ParseNtpServerResult(ntpip) == false)
                   {
	               return false;
                   }
               }
	 
               if (option43.length != 0)
               {
	           if (isValidAscii(option43) == '')
	           {
	                if (IsDhcpOption43Valid(option43) == false)
                        {
		            return false;
                        }
	           }
	          else
	          {
	              AlertEx(dhcp2_language['bbsp_option43invalid'] );
                      return false;
	          }
              }
         }
     }
	}

    setDisable('btnApply', 1);
    setDisable('cancelValue', 1);

    return true;
}


function ApplyOption240(base64, instance, Form)
{ 
    var urlpara;
	var url = '';
	if (instance == 0)
	{
		var urlPrefix = 'Add_a' + 'a';
		Form.addParameter(urlPrefix + '.Value', base64);
		Form.addParameter(urlPrefix + '.Enable', 1);
		Form.addParameter(urlPrefix + '.Tag', 240);
		url += '&' + urlPrefix + '=' 
			+ 'InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.1.DHCPOption';		    
	}
	else
	{
		var urlPrefix = 'm' + 'a';
		Form.addParameter(urlPrefix + '.Value', base64);
		url += '&' + urlPrefix + '=' + 'InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.1.DHCPOption.1';
	}		
	return url;
}

function FillupSubmitPara(Form)
{	
	var optionurl = '';
	 with (document.forms[0])
     {
        if (conditionpoolfeature == 1)
        {   		    
			Form.addParameter('y.Enable',getCheckVal('DHCPEnable'));

    	    if(GetCfgMode().PCCWHK != "1")
    	    {
                var DnsSStr = getValue('dnsSecPri') + ',' + getValue('dnsSecSec');
                if ( getValue('dnsSecPri') == 0)
                {
                    DnsSStr = getValue('dnsSecSec');
                }
                if ( getValue('dnsSecSec') == 0)
                {
                    DnsSStr = getValue('dnsSecPri');
                } 
                Form.addParameter('y.DNSServers',DnsSStr);
    	    }

			Form.addParameter('y.IPRouters',getValue('SlaveIpAddr'));
			Form.addParameter('y.SubnetMask',getValue('SlaveMask'));
    	    Form.addParameter('y.MinAddress',getValue('SlaveEthStart'));
    	    Form.addParameter('y.MaxAddress',getValue('SlaveEthEnd'));
    	    Form.addParameter('y.DHCPLeaseTime',getValue('SlaveLeasedTime')*getValue('dhcpLeasedTimeFrag'));
    	    Form.addParameter('y.VendorClassID',getValue('dhcpOption60'));
			Form.addParameter('y.VendorClassIDMode',getSelectVal('Option60Mode'));
        }
        else
        {
		    if ((curUserType == sysUserType) || (0 != normaluserenable))
			{
				if((true != TELMEX)&&("1" != GetCfgMode().DT_HUNGARY)&&(!((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))) 
				  && (!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
				  && (!((curUserType != sysUserType) && ("1" == norightslavefeature)))
				  && (false == IsSonetHN8055QUser()))
				{
					Form.addParameter('y.DHCPEnable',getCheckVal('DHCPEnable'));
				}
				if (getCheckVal("DHCPEnable") == 1) 
				{
					if(GetCfgMode().PCCWHK != "1")
					{
						var DnsSStr = getValue('dnsSecPri') + ',' + getValue('dnsSecSec');
						if ( getValue('dnsSecPri') == 0)
						{
							DnsSStr = getValue('dnsSecSec');
						}
						if ( getValue('dnsSecSec') == 0)
						{
							DnsSStr = getValue('dnsSecPri');
						} 
						if((true != TELMEX) && (!((curUserType != sysUserType) && ("1" == norightslavefeature)))
							&& (false == IsSonetHN8055QUser()))
						{
							Form.addParameter('y.DNSList',DnsSStr);
						}
					}

					if((true != TELMEX)&&("1" != GetCfgMode().DT_HUNGARY)&&(!((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))) 
					&& (!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
					&& (!((curUserType != sysUserType) && ("1" == norightslavefeature)))
					&& (false == IsSonetHN8055QUser()))
					{
						Form.addParameter('y.StartIP',getValue('SlaveEthStart'));
						Form.addParameter('y.EndIP',getValue('SlaveEthEnd'));
						Form.addParameter('y.LeaseTime',getValue('SlaveLeasedTime')*getValue('dhcpLeasedTimeFrag'));
						Form.addParameter('y.Option60',getValue('dhcpOption60'));
						Form.addParameter('y.NTPList',getValue('ntpserver'));
						Form.addParameter('y.Option43',getValue('dhcpOption43'));
					}
				}
           }
        }     
    }	

    setDisable('DHCPEnable',1);
    setDisable('dhcpSrvType',1);
    setDisable('dhcpL2relay',1);
	setDisable('dhcpMainOption125',1);
}	

function OnAddNewSubmit()
{
	var optionurl = '';
	if(false == CheckFormConditionPool())
	{
		return false;
	}	
	var Form = new webSubmitForm();
    FillupSubmitPara(Form);
	if (option240feature == 1)
	{
	    var tmp = getValue('dhcpOption240');
        optionurl = ApplyOption240(Base64Encode(tmp), option240instance, Form);
	}
    
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction('addcfg.cgi?' +'y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool' 
				+ optionurl + '&RequestFile=html/bbsp/dhcpservercfg/dhcp2tde_xgpon.asp');
    Form.submit();
}

function OnModifySubmit()
{
	var optionurl = '';
	if(false == CheckFormConditionPool())
	{
		return false;
	}	
	var Form = new webSubmitForm();
    FillupSubmitPara(Form);
	if (option240feature == 1)
	{
	    var tmp = getValue('dhcpOption240');
        optionurl = ApplyOption240(Base64Encode(tmp), option240instance, Form);
	}
    
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction('complex.cgi?y=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPConditionalServingPool.1'
                    + optionurl + '&RequestFile=html/bbsp/dhcpservercfg/dhcp2tde_xgpon.asp');
    Form.submit();

}

function DhcpConditionInfoselectRemoveCnt(val)
{

}

function OnDeleteButtonClick(TableID)
{
    var CheckBoxList = document.getElementsByName('DhcpConditionInfo' + 'rml');
    var Count = 0;
    var i;
    for (i = 0; i < CheckBoxList.length; i++)
    {
        if (CheckBoxList[i].checked == true)
        {
            Count++;
        }
    }

    if (Count == 0)
    {
        return false;
    }

    var Form = new webSubmitForm();
    for (i = 0; i < CheckBoxList.length; i++)
    {
        if (CheckBoxList[i].checked != true)
        {
            continue;
        }

        Form.addParameter(CheckBoxList[i].value,'');
    }
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    
    Form.setAction('del.cgi?RequestFile=html/bbsp/dhcpservercfg/dhcp2tde_xgpon.asp');
    Form.submit();
	DisableRepeatSubmit();
}


function ApplyConditionpool()
{
    if (ConditionPoolAddFlag == 1)
    {
        return OnAddNewSubmit();
    }
    else
    {
        return OnModifySubmit();
    }
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
                if (getValue('SlaveIpAddr') == CurrentWan.IPv4IPAddress)
                {
                    AlertEx(dhcp2_language['bbsp_ipdifwan']);
                    return false;
                }
            if (CurrentWan.IPv4Enable == "1")
            {
                if(true==isSameSubNet(getValue('SlaveIpAddr'), getValue('SlaveMask'),
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
	 with (document.forms[0])
     {
        Form.addParameter('z.DHCPServerEnable',getCheckVal('dhcpSrvType'));
		if((!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
		  && (!((curUserType != sysUserType) && ("1" == hiderelay125feature)))
		  && (false == IsSonetHN8055QUser())&& (false == IsSonetNewNormalUser()))
		{
        	Form.addParameter('z.X_HW_DHCPL2RelayEnable',getCheckVal('dhcpL2relay'));
		}
		if ((true != TELMEX) && (!((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY")))
		 && (!((curUserType != sysUserType) && ("1" == hiderelay125feature)))
		 && (false == IsSonetHN8055QUser())
		 && (false == IsSonetNewNormalUser())
		 && ('PCCW' != CfgModeWord.toUpperCase())
		 && (GetCfgMode().PCCWHK != "1"))
		{
        	Form.addParameter('z.X_HW_Option125Enable',getCheckVal('dhcpMainOption125'));
		}

			
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
        Form.addParameter('z.DHCPLeaseTime',getValue('MainLeasedTime')*getValue('maindhcpLeasedTimeFrag'));     
    }	
	
    var RequestFile = 'html/bbsp/dhcpservercfg/dhcp2tde_xgpon.asp';
    var urlpara;
    
    if (conditionpoolfeature == 1)
    {
        urlpara = '&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement'
        			  + '&RequestFile=' + RequestFile;
    }
    else
    {	
		if (((curUserType != sysUserType) && (GetCfgMode().PCCWHK == "1"))  || (true == TELMEX) || ("1" == GetCfgMode().DT_HUNGARY)
			 || ((curUserType != sysUserType) && (curCfgModeWord.toUpperCase() == "RDSGATEWAY"))
			 || ((curUserType != sysUserType) && ("1" == norightslavefeature))
			 || (true == IsSonetHN8055QUser()))
		{
			urlpara = 'z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement'
					  + '&RequestFile=' + RequestFile;
		}
		else
		{
			urlpara = 'x=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.2'
						  + '&z=InternetGatewayDevice.LANDevice.1.LANHostConfigManagement'
						  + '&RequestFile=' + RequestFile;
		}
    }
	
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    var url = 'set.cgi?' + urlpara;
	
    setDisable('DHCPEnable',1);
    setDisable('dhcpSrvType',1);
    setDisable('dhcpL2relay',1);
	setDisable('dhcpMainOption125',1);
	
	Form.setAction(url);
	Form.submit();
}	

function SetInputRuleInfo(conPoolItem)
{
    setText('SlaveEthStart', conPoolItem.DhcpStart);
    setText('SlaveEthEnd', conPoolItem.DhcpEnd);
	setText('SlaveIpAddr', conPoolItem.Gateway);
	setText('SlaveMask', conPoolItem.Gatewaymask);
	setDisable('SlaveIpAddr', 0);
	setDisable('SlaveMask', 0);
	setText('dhcpOption60', conPoolItem.Option60);
    setSelect('Option60Mode', conPoolItem.Option60mode);

    setText('dnsSecPri', conPoolItem.SlaPriDNS);
    setText('dnsSecSec', conPoolItem.SlaSecDNS);
    
    setLease(conPoolItem.LeaseTime, "slave");
    setCheck('DHCPEnable', conPoolItem.Enable);
	
	if (option240feature == 1)
	{
	    setText('dhcpOption240', option240);
	}

}

function OnNewInstance(index)
{
   ConditionPoolAddFlag = 1;

   var conPoolItem = new condhcpst('', '', '', '', '', '', '', '', '', '43200', '');
   setDisplay('SlaveConfigForm', 1);
   setDisplay('dhcpOption43Row', 0);
   setDisplay('dhcpOption43Row', 0);
   setDisplay('ntpserverRow', 0);
   setDisplay('Option60ModeRow', 1);
   SetInputRuleInfo(conPoolItem);
}

function ModifyInstance(index)
{
    ConditionPoolAddFlag = 2;
	setDisplay('SlaveConfigForm', 1);
	setDisplay('dhcpOption43Row', 0);
	setDisplay('ntpserverRow', 0);
	setDisplay('Option60ModeRow', 1);
    SetInputRuleInfo(ConditionDhcpInfos[index]);
}

function setControl(index)
{ 
    if (-1 == index)
    {
        if (ConditionDhcpInfos.length-1 == 1)
        {
            var tableRow = getElementById("DhcpConditionInfo");
            tableRow.deleteRow(tableRow.rows.length-1);
            AlertEx(dhcp2_language['bbsp_conpoolfull']);
            return false;
        }
    }
    
    selIndex = index;
	if (index < -1)
	{
		return;
	}

    if (-1 == index)
    {        
        return OnNewInstance(index);
    }
    else
    {
        return ModifyInstance(index);
    }
}


function SetDHCPL2Relay()
{
	var enable = getCheckVal('dhcpL2relay');
}

function SetMainDHCPServer()
{
	var enable = getCheckVal('dhcpSrvType');
	SetDHCPServerDisplay(enable);
}

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

function CancelConfig()
{
    LoadFrame();
}

var TableClass = new stTableClass("table_title width_per25", "table_right width_per75", "", "Select");
		  
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

function InitOption60Mode()
{
	$("#Option60Mode").append('<option value="Exact">'+ dhcp2_language['bbsp_op60_exact'] + '</option>');
	$("#Option60Mode").append('<option value="Prefix">'+ dhcp2_language['bbsp_op60_prefix'] + '</option>');	
	$("#Option60Mode").append('<option value="Suffix">'+ dhcp2_language['bbsp_op60_suffix'] + '</option>');	
	$("#Option60Mode").append('<option value="Substring">'+ dhcp2_language['bbsp_op60_substring'] + '</option>');
}

function InitTableData()
{
	var TableDataInfo = new Array();
    var RecordCount = ConditionDhcpInfos.length- 1;
    var i = 0;
	var Listlen = 0;
	
    if (RecordCount == 0)
    {	
		TableDataInfo[Listlen] = new condhcpst('', '', '', '', '', '', '', '', '', '', '');
		TableDataInfo[Listlen].domain = '--';
		TableDataInfo[Listlen].Enable = '--';
		TableDataInfo[Listlen].Option60 = '--';
		TableDataInfo[Listlen].Gateway = '--';
		TableDataInfo[Listlen].Gatewaymask = '--';
		TableDataInfo[Listlen].DhcpStart = '--';
		TableDataInfo[Listlen].DhcpEnd = '--';
		TableDataInfo[Listlen].LeaseTime = '--';		
		TableDataInfo[Listlen].Option60mode = '--';
		TableDataInfo[Listlen].SlaPriDNS = '--';
		TableDataInfo[Listlen].SlaSecDNS = '--';
		TableDataInfo[Listlen].NormalUserEnable = '--';	
		HWShowTableListByType(1, "DhcpConditionInfo", true, 8, TableDataInfo, DhcpConditionListInfo, dhcp2_language, null);
		return;
    }

    for (i = 0; i < RecordCount; i++)
    {
		TableDataInfo[Listlen] = new condhcpst('', '', '', '', '', '', '', '', '', '', '');
		TableDataInfo[Listlen].domain = ConditionDhcpInfos[i].Domain;
		TableDataInfo[Listlen].Enable = (ConditionDhcpInfos[i].Enable == '1' ? dhcp2_language['bbsp_enable']:dhcp2_language['bbsp_disable']);
		TableDataInfo[Listlen].Option60 = (ConditionDhcpInfos[i].Option60 == '' ? '--' : ConditionDhcpInfos[i].Option60);
		TableDataInfo[Listlen].Gateway = (ConditionDhcpInfos[i].Gateway == '' ? '--' : ConditionDhcpInfos[i].Gateway);
		TableDataInfo[Listlen].Gatewaymask = (ConditionDhcpInfos[i].Gatewaymask == '' ? '--' : ConditionDhcpInfos[i].Gatewaymask);
		TableDataInfo[Listlen].IPRange = (ConditionDhcpInfos[i].IPRange == '' ? '--' : ConditionDhcpInfos[i].IPRange);
		TableDataInfo[Listlen].dnssDis = (ConditionDhcpInfos[i].dnssDis == '' ? '--' : ConditionDhcpInfos[i].dnssDis);
		TableDataInfo[Listlen].LeaseTime = (ConditionDhcpInfos[i].LeaseTime == '' ? '--' : ConditionDhcpInfos[i].LeaseTime);
		Listlen++;
    }
    TableDataInfo.push(null);
	HWShowTableListByType(1, "DhcpConditionInfo", true, 8, TableDataInfo, DhcpConditionListInfo, dhcp2_language, null);
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<div id="ConfigForm" action="../network/set.cgi"> 
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("dhcp2", GetDescFormArrayById(dhcp2_language, "bbsp_mune"), GetDescFormArrayById(dhcp2_language, "bbsp_dhcp2_title2"), false);
</script> 
<div class="title_spread"></div>
<div id="DhcpServerPanel">
<form id = "PriPoolConfigForm">
<table width="100%" border="0" cellpadding="0" cellspacing="0" class="func_title"> 
<tr><td BindText="bbsp_pripool"></td></tr></table>  

<table border="0" cellpadding="0" cellspacing="1"  width="100%">
<li   id="dhcpSrvType"        		RealType="CheckBox"      	  DescRef="bbsp_enablepridhcpmh"      RemarkRef="Empty"     			ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"  ClickFuncApp="onclick=SetMainDHCPServer"/>
<li   id="dhcpL2relay"        		RealType="CheckBox"      	  DescRef="bbsp_enablel2relaymh"      RemarkRef="Empty"     			ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"  ClickFuncApp="onclick=SetDHCPL2Relay"/>
<li   id="dhcpMainOption125"        RealType="CheckBox"      	  DescRef="bbsp_main_option125"       RemarkRef="Empty"     			ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="LanHostIP"        		RealType="HtmlText"      	  DescRef="bbsp_lanhostmh"        	 RemarkRef="Empty"     				ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="LanHostMask"        		RealType="HtmlText"      	  DescRef="bbsp_maskmh"        		 RemarkRef="Empty"     				ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="mainstartipaddr"          RealType="TextBox"            DescRef="bbsp_startipmh"            RemarkRef="bbsp_mustbesamesubnet"     ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"       InitValue="Empty"  MaxLength="15"/>
<li   id="mainendipaddr"            RealType="TextBox"            DescRef="bbsp_endipmh"              RemarkRef="Empty"     			ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"           InitValue="Empty"  MaxLength="15"/>
<li   id="MainLeasedTime"           RealType="TextOtherBox"       DescRef="bbsp_leasedmh"             RemarkRef="Empty"    			ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"   Elementclass="TextBox_2"    InitValue="[{Type:'select',Item:[{AttrName:'id',AttrValue:'maindhcpLeasedTimeFrag'},{AttrName:'class',AttrValue:'Select_2'}]}]"/>
<li   id="dnsMainPri"             RealType="TextBox"            DescRef="bbsp_pridnsmh"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
<li   id="dnsMainSec"             RealType="TextBox"            DescRef="bbsp_secdnsmh"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
</table>
<script>
PriPoolConfigFormList = HWGetLiIdListByForm("PriPoolConfigForm");
HWParsePageControlByID("PriPoolConfigForm", TableClass, dhcp2_language, null);
</script>
<table width="100%" border="0" cellspacing="0" cellpadding="0" class="table_button"> 
<tr> 
  <td class='width_per25'></td> 
  <td class="table_submit" > 
   <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
  <button id="btnApply" name="btnApply" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="ApplyConfig();"><script>document.write(dhcp2_language['bbsp_app']);</script> </button> 
	<button name="cancelValue" id="cancelValue" type="button" class="CancleButtonCss buttonwidth_100px" onClick="CancelConfig();"><script>document.write(dhcp2_language['bbsp_cancel']);</script> </button>  
</td>
</tr> 
</table>
</form>

<div id="DhcpPoolPanel" style="display:none"> 
 <div class="func_spread"></div> 
 <table width="100%" border="0" cellpadding="0" cellspacing="0" class="func_title"> 
<tr><td BindText="bbsp_pripoolsub"></td></tr></table> 

    <table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg"> 
      <tbody id='dhcpPoolInfo'> 
      <tr > 
        <td  class="table_title width_per25" BindText = 'bbsp_devtype'></td> 
        <td  class="table_right width_per15" BindText = 'bbsp_startip'></td> 
        <td  class="table_right width_per60" BindText = 'bbsp_endip'></td> 
      </tr> 
      <tr > 
        <td  class="table_title width_per25" BindText = 'bbsp_hgwmh'></td> 
		<td  class="table_right width_per15"> <div align="left"> 
			<input type='text' id='HGWEthStart' name='HGWEthStart' maxlength='15'>
		</div></td> 
        <td  class="table_right width_per60"> <input type='text' id='HGWEthEnd' name='HGWEthEnd' maxlength='15'></td> 
      </tr> 
      <tr > 
        <td  class="table_title width_per25" BindText = 'bbsp_stbmh'></td> 
        <td  class="table_right width_per15"> <input type='text' id='STBEthStart' name='STBEthStart' maxlength='15'></td> 
        <td  class="table_right width_per60"> <input type='text' id='STBEthEnd' name='STBEthEnd' maxlength='15'></td> 
      </tr> 
      <tr> 
        <td  class="table_title width_per25" BindText = 'bbsp_cameramh'></td> 
        <td  class="table_right width_per15"> <input type='text' id='CameraEthStart' name='CameraEthStart' maxlength='15'></td> 
        <td  class="table_right width_per60"> <input type='text' id='CameraEthEnd' name='CameraEthEnd' maxlength='15'></td> 
      </tr> 
      <tr> 
        <td  class="table_title width_per25" BindText = 'bbsp_computermh'></td> 
        <td  class="table_right width_per15"> <input type='text' id='ComputerEthStart' name='ComputerEthStart' maxlength='15'></td> 
        <td  class="table_right width_per60"> <input type='text' id='ComputerEthEnd' name='ComputerEthEnd' maxlength='15'></td> 
      </tr> 
      <tr > 
        <td  class="table_title width_per25" BindText = 'bbsp_phonemh'></td> 
        <td  class="table_right width_per15"> <input type='text' id='PhoneEthStart' name='PhoneEthStart' maxlength='15'></td> 
        <td  class="table_right width_per60"> <input type='text' id='PhoneEthEnd' name='PhoneEthEnd' maxlength='15'></td> 
      </tr> 
      </tbody> 
    </table> 
</div> 

<div id='SecondaryServerPool' style="display:none">
<div class="func_spread"></div>

<form id = "SecPoolConfigForm">
<table width="100%" border="0" cellpadding="0" cellspacing="0" class="func_title"> 
<tr>
<td id="SecPoolInfoBar">
<script>
if (conditionpoolfeature == '1')
{
	document.write(dhcp2_language['bbsp_conpool']);
}
else
{
	document.write(dhcp2_language['bbsp_secpool']);
}
</script>
</td>
</tr></table>  
</form>
<script language="JavaScript" type="text/javascript">
	var DhcpConditionListInfo = new Array();	
	DhcpConditionListInfo.push(new stTableTileInfo("Empty","align_center","DomainBox"));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_enablesign","align_center","Enable"));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_op60","align_center","Option60", false, 6));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_ip","align_center","Gateway"));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_mask","align_center","Gatewaymask"));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_iprange","align_center","IPRange", false,"",0));
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_dnss","align_center","dnssDis", false,"",0));	
	DhcpConditionListInfo.push(new stTableTileInfo("bbsp_leasetime","align_center","LeaseTime"));
	
	DhcpConditionListInfo.push(new stTableTileInfo(null));
	InitTableData();
</script>
<form id = "SlaveConfigForm" style="display:none">
<table border="0" cellpadding="0" cellspacing="1"  width="100%">
<li   id="DHCPEnable"        	  RealType="CheckBox"      	    DescRef="bbsp_enableconvermh"     RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="SlaveIpAddr"        	  RealType="TextBox"      	    DescRef="bbsp_ipmh"        		  RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="SlaveMask"        	  RealType="TextBox"      	    DescRef="bbsp_maskmh"        	  RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="SlaveEthStart"          RealType="TextBox"            DescRef="bbsp_startipmh"          RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"   InitValue="Empty"  MaxLength="15"/>
<li   id="SlaveEthEnd"            RealType="TextBox"            DescRef="bbsp_endipmh"            RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"   InitValue="Empty"  MaxLength="15"/>
<li   id="SlaveLeasedTime"        RealType="TextOtherBox"       DescRef="bbsp_leasedmh"           RemarkRef="Empty"    			ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   Elementclass="TextBox_2"    InitValue="[{Type:'select',Item:[{AttrName:'id',AttrValue:'dhcpLeasedTimeFrag'},{AttrName:'class',AttrValue:'Select_2'}]}]"/>
<li   id="dhcpOption60"           RealType="TextBox"            DescRef="bbsp_op60mh"             RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="TRUE"     BindField="Empty"   Elementclass="TextBoxLtr"  InitValue="Empty"  TitleRef="bbsp_60prnote"  MaxLength="256"/>
<li   id="Option60Mode"        	  RealType="DropDownList"      	DescRef="bbsp_op60_modemh"        RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"    BindField="Empty"   InitValue="Empty"/>
<li   id="dhcpOption43"           RealType="TextBox"            DescRef="bbsp_op43mh"             RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"   Elementclass="TextBoxLtr"   InitValue="Empty"  TitleRef="bbsp_option43prnote"  MaxLength="64"/>
<li   id="ntpserver"              RealType="TextBox"            DescRef="bbsp_ntpserver"          RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"   InitValue="Empty"  TitleRef="bbsp_ntpserverprnote"  MaxLength="64"/>
<li   id="dnsSecPri"             RealType="TextBox"            DescRef="bbsp_pridnsmh"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
<li   id="dnsSecSec"             RealType="TextBox"            DescRef="bbsp_secdnsmh"            RemarkRef="Empty"    ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"        InitValue="Empty"  MaxLength="15"/>
<li   id="dhcpOption240"         RealType="TextBox"            DescRef="bbsp_op240mh"             RemarkRef="Empty"     		ErrorMsgRef="Empty"    Require="FALSE"     BindField="Empty"   Elementclass="TextBoxLtr"  InitValue="Empty"  MaxLength="522"/>
</table>
<script language="JavaScript" type="text/javascript">
	var DhcpConditionFormList = new Array();
	DhcpConditionFormList = HWGetLiIdListByForm("SlaveConfigForm", null);
	HWParsePageControlByID("SlaveConfigForm", TableClass, dhcp2_language, null);
</script>

</div>

<table width="100%" border="0" cellspacing="0" cellpadding="0" class="table_button"> 
<tr> 
  <td class='width_per25'></td> 
  <td class="table_submit" > 
  <button id="btnApply" name="btnApply" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="ApplyConditionpool();"><script>document.write(dhcp2_language['bbsp_app']);</script> </button> 
	<button name="cancelValue" id="cancelValue" type="button" class="CancleButtonCss buttonwidth_100px" onClick="CancelConfig();"><script>document.write(dhcp2_language['bbsp_cancel']);</script> </button>  
</td>
</tr> 
</table> 
</form>
</div>
<br>
<br>
<script language="JavaScript" type="text/javascript">
InitLeasedTime();
InitOption60Mode();
getElById("DHCPEnableRow").title = dhcp2_language['bbsp_dhcp_enable'];
</script>  
</body>
</html>
