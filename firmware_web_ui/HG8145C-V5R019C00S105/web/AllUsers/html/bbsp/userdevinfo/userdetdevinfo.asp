<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<title>User Device detail Information</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/GetLanUserDevInfo.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<script language="JavaScript" type="text/javascript">

var num = 0;
var domianvlaue = "OldWeb";
var page = 1;
var MAX_LINE_TYPE=129;
var HW_USER_DEVICE_IP_STATIC="Static";
var FOR_NULL="--";
var hostname = "";
var deviceIP = "";
var IPType   = "";
var remainleasetime = "";
var deviceDur = "";
var unit_h = "";
var unit_m = "";
var IsPTVDFFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_PTVDF);%>';
var STBPort = '<%HW_WEB_GetSTBPort();%>';
function IsFreInSsidName()
{
	if(1 == IsPTVDFFlag)
	{
		return true;
	}
}

if(( window.location.href.indexOf("?") > 0) &&( window.location.href.split("?").length == 3))
{
    if(window.location.href.split("?")[1].indexOf("InternetGatewayDevice") >=0)
    {
        domianvlaue = window.location.href.split("?")[1] ;
        if(domianvlaue.charAt(domianvlaue.length - 1) == '.')
        {
            domianvlaue = domianvlaue.substr(0, domianvlaue.length - 1);
        }
    }
    else
    {
        num  = window.location.href.split("?")[1];
    }
    page = window.location.href.split("?")[2];  
}

function IPv6USERDevice(Domain,IpAddr,MacAddr,Port,IpType,DevType,DevStatus,PortType,Time,HostName,LeaseTimeRemaining)
{
	this.Domain 	= Domain;
	this.IpAddr	    = IpAddr;
	this.MacAddr	= MacAddr;
	if(Port=="LAN0" || Port=="SSID0")
	{
		this.Port 	= FOR_NULL;
	}
	else
	{
	   this.Port 	= Port;
	}	
	this.PortType	= PortType;
	this.DevStatus 	= DevStatus;
	this.IpType		= IpType;
	
	if(IpType==HW_USER_DEVICE_IP_STATIC)
	{
	  this.DevType = FOR_NULL;
	}
	else
	{
		if(DevType=="")
		{
			this.DevType	= FOR_NULL;	
		}
		else
		{
			this.DevType	= DevType;		
		}	
	}
		
	this.Time	    = Time;
	if(HostName=="")
	{
		this.HostName	= FOR_NULL;
	}else
	{
	   this.HostName	= HostName;
	}
	
	this.LeaseTimeRemaining = LeaseTimeRemaining ;
}
function DhcpInfo(Domain, IPAddress, MACAddress, LeaseTimeRemaining,AddressSource)
{
    this.Domain     = Domain;
    this.IPAddress  = IPAddress;
    this.MACAddress = MACAddress;
    this.LeaseTimeRemaining = LeaseTimeRemaining;
	this.AddressSource = AddressSource;
}
var DhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.Hosts.Host.{i},IPAddress|MACAddress|LeaseTimeRemaining|AddressSource, DhcpInfo);%>;
var DhcpInfosNum = DhcpInfos.length - 1;
var UserDevices = new Array();
$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : "/html/bbsp/common/GetLanUserDevInfo.asp",
		success : function(data) {
		UserDevices = eval(data);   
		}
	});

var UserDevicesnum = UserDevices.length - 1;


function GetRemainLeaseTime(ipaddr, macaddr)
{
    if(domianvlaue.indexOf(".IPv6Address") >= 0)
    {
        return  UserDevices[num] .LeaseTimeRemaining ;
    }
    for (var i = 0; i < DhcpInfosNum; i++)
    {
        if ((ipaddr == DhcpInfos[i].IPAddress) && (macaddr == DhcpInfos[i].MACAddress))
        {
            return DhcpInfos[i].LeaseTimeRemaining;
        }
    }
	
    return -1;
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
		b.innerHTML = userdevinfo_language[b.getAttribute("BindText")];
	}
}

function IsUseNewWeb()
{
    if ('OldWeb' == domianvlaue)
    {
        return false;
    }
    return true;
}

function OnBack()
{
    if (true == IsUseNewWeb())
    {
        window.location='userdevinfo1.asp?'+page;
    }
    else
    {
        window.location='userdevinfo.asp?'+page;
    }
}
function USERv6Device(domain, IPv6Addr, IPv6Scope)
{
	this.domain = domain;
	this.IPv6Addr = IPv6Addr;
	this.IPv6Scope = IPv6Scope;	
}
function LoadFrame()
{
    if ( "1" == GetCfgMode().TELMEX )
    {
        document.getElementById('ShowOnlineTimeInfo').style.display="none";
	}
	loadlanguage();
}
</script>
</head>
<body  class="mainbody" onLoad="LoadFrame();"> 
<script language="JavaScript" type="text/javascript">
if (true == IsUseNewWeb())
{
	HWCreatePageHeadInfo("userdetdevinfotitle", GetDescFormArrayById(userdevinfo_language, "bbsp_mune"), GetDescFormArrayById(userdevinfo_language, "bbsp_userdetdevinfo_title1"), false);
}
else
{
	HWCreatePageHeadInfo("userdetdevinfotitle", GetDescFormArrayById(userdevinfo_language, "bbsp_mune"), GetDescFormArrayById(userdevinfo_language, "bbsp_userdetdevinfo_title"), false);
}
</script> 
<div class="title_spread"></div>

<table width="100%" border="0" cellpadding="0" cellspacing="1" class="tabal_noborder_bg" id='devdetinfo'> 
  <tr> 
	<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
    <td class="table_title  width_per25" BindText='bbsp_hostnamemh'></td> 
    <td class="table_right width_per75"> <script language="JavaScript">
				if(IsUseNewWeb() == true)
				{ 
					var Result = null;
					var ParameterList = null ;
					var ObjPath = 'x='+domianvlaue;
					if( domianvlaue.indexOf(".IPv6Address") >= 0 )
					{
						ParameterList = 'IP&MacAddr&PortID&IpType&DevType&DevStatus&PortType&Time&HostName&LeaseTime&x.X_HW_Token='+getValue('onttoken');
				
					}
					else
					{
						ParameterList = 'IpAddr&MacAddr&PortID&IpType&DevType&DevStatus&PortType&time&HostName&x.X_HW_Token='+getValue('onttoken');
					}
				
					
					$.ajax({
						type : "POST",
						async : false,
						cache : false,
						url : '/getajax.cgi?' + ObjPath + "&RequestFile=nopage",
						data: ParameterList,
						success : function(data) {
							Result  = eval('"' + data + '"');
						}
					});
					
					var UserDevInfoTmp = $.parseJSON(Result);
					if(domianvlaue.indexOf(".IPv6Address") >= 0)
					{
						UserDevices[num] = new IPv6USERDevice(domianvlaue,UserDevInfoTmp.IP,UserDevInfoTmp.MacAddr,UserDevInfoTmp.PortID,UserDevInfoTmp.IpType,UserDevInfoTmp.DevType,UserDevInfoTmp.DevStatus,UserDevInfoTmp.PortType,UserDevInfoTmp.Time,UserDevInfoTmp.HostName,UserDevInfoTmp.LeaseTime);
					}
					else
					{
						UserDevices[num] = new USERDevice(domianvlaue,UserDevInfoTmp.IpAddr,UserDevInfoTmp.MacAddr,UserDevInfoTmp.PortID,UserDevInfoTmp.IpType,UserDevInfoTmp.DevType,UserDevInfoTmp.DevStatus,UserDevInfoTmp.PortType,UserDevInfoTmp.time,UserDevInfoTmp.HostName);
					}
					
				}
				
				if(true == IsFreInSsidName())
				{
					var SL = GetSSIDList();
					var SLFre = GetSSIDFreList();
					for(var j = 0; j < SL.length; j++)
					{
						if(SL[j].name == UserDevices[num].Port.toUpperCase())
						{
							UserDevices[num].Port = SLFre[j].name;
							break;
						}
					}
				}
				
				if(STBPort > 0)
				{
					var LanPort = "LAN" + STBPort;
					if(UserDevices[num].Port.toUpperCase() == LanPort)
					{
						UserDevices[num].Port = userdevinfo_language['bbsp_lanstb'];
					}
				}
				
	            if(('--' == UserDevices[num].HostName) && ("1" == GetCfgMode().TELMEX))
                {
                    document.write(UserDevices[num].MacAddr);
                }
                else
                {
                    document.write(htmlencode(UserDevices[num].HostName.substr(0,MAX_LINE_TYPE)));
                }			
				
				if( "X_RTK_BRIDGE" == UserDevices[num].IpType)
				{
					hostname = "--";
					deviceIP = "--";
					IPType   = "X_RTK_BRIDGE";
					remainleasetime  =  "--";
					deviceDur   =  "--";
				}
				else
				{
					hostname 		=  htmlencode(UserDevices[num].DevType.substr(0,MAX_LINE_TYPE));
					deviceIP 		=  UserDevices[num].IpAddr;
					IPType   		=  userdevinfo_language[UserDevices[num].IpType];		
					unit_h = (parseInt(UserDevices[num].Time.split(":")[0],10) > 1) ? userdevinfo_language['bbsp_hours'] : userdevinfo_language['bbsp_hour'];
				    unit_m = (parseInt(UserDevices[num].Time.split(":")[1],10) > 1) ? userdevinfo_language['bbsp_mins'] : userdevinfo_language['bbsp_min'];
					deviceDur = UserDevices[num].Time.split(":")[0] + unit_h + UserDevices[num].Time.split(":")[1] + unit_m;
					
					remainleasetime = "--";
					if ('DHCP' == UserDevices[num].IpType || 'DHCPV6'==UserDevices[num].IpType.toUpperCase())
					{	
						remainleasetime =  GetRemainLeaseTime(UserDevices[num].IpAddr, UserDevices[num].MacAddr);
						if (remainleasetime > 0)
						{
							remainleasetime = remainleasetime + userdevinfo_language["bbsp_second"];							
						}
						else
						{
						    remainleasetime = "--";
						}
					}
				}
                </script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_devtypemh'></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">
				document.write(hostname);
				</script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_ipmh'></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">               
                 document.write(deviceIP);
                </script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_macmh'></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">-
				document.write(UserDevices[num].MacAddr);
				</script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_devstatemh'></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">
				document.write(userdevinfo_language[UserDevices[num].DevStatus]);
				</script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_porttypemh'></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">
				document.write(UserDevices[num].PortType);
				</script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25">
	<script>
	if (true == IsUseNewWeb())
	{
		document.write(userdevinfo_language['bbsp_interfacemh']);
	}
	else
	{
		document.write(userdevinfo_language['bbsp_portmh']);
	}
	</script>
	</td> 
    <td  class="table_right width_per75"> <script language="JavaScript">
				document.write(UserDevices[num].Port);
				</script> </td> 
  </tr> 
  <tr id="ShowOnlineTimeInfo"> 
    <td  class="table_title width_per25"> 
	<script>
	if('ONLINE' == UserDevices[num].DevStatus.toUpperCase())
	{
		document.write(userdevinfo_language['bbsp_onlinetimemh']);
	}
	else
	{
		document.write(userdevinfo_language['bbsp_offlineiimemh']);
	}
	</script></td>
    <td  class="table_right width_per75"> <script language="JavaScript">
				document.write(deviceDur);
				</script> </td> 
  </tr> 
  <tr> 
    <td  class="table_title width_per25" BindText='bbsp_ipacmodemh' ></td> 
    <td  class="table_right width_per75"> <script language="JavaScript">
				if( domianvlaue.indexOf(".IPv6Address") >= 0 )
				{
					document.write(UserDevices[num].IpType);
				}
				else
				{
					document.write(IPType);
				}
				</script> </td> 
  </tr> 
  <tr> 
    <td class="table_title width_per25" BindText='bbsp_remainleasedtime'></td> 
    <td class="table_right width_per75"> <script language="JavaScript">
		document.write(remainleasetime );		
	</script> </td> 
  </tr> 
</table> 
<table width="100%" height="30"> 
  <tr> 
    <td class='title_bright1'> <button id="back" name="back" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="OnBack();" enable=true ><script>document.write(userdevinfo_language['bbsp_back']);</script></button> </td> 
  </tr> 
</table> 
</body>
</html>


