<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(indexclick.css);%>' type='text/css'>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(md5.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="/html/bbsp/common/wan_list_info.asp"></script>
<script language="javascript" src="/html/bbsp/common/wan_list.asp"></script>
<script language="javascript" src="/html/bbsp/common/wanipv6state.asp"></script>
<script language="javascript" src="/html/bbsp/common/wanaddressacquire.asp"></script>
<script language="JavaScript" type="text/javascript">
var WanList = GetWanList();
var curUserType = '<%HW_WEB_GetUserType();%>';
var sysUserType = '0';
var mngttype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var IsPTVDFFlag = '<%HW_WEB_GetFeatureSupport(BBSP_FT_PTVDF);%>';
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
var opticInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic.RxPower);%>';
var gponStatus = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.ONT.State);%>';
var eponStatus = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.OAM.ONT.State);%>';
var GUIDE_NULL = "--";
var smartlanfeature = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var IPProtVerMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.X_HW_IPProtocolVersion.Mode);%>';

function GetAccessMode()
{
	var accModes = new Array(["not initial", "NOT INITIAL"], ["gpon", "GPON"], ["epon", "EPON"], 
						["10g-gpon", "XG-PON"], ["Asymmetric 10g-epon", "Asymmetric 10G EPON"], 
						["Symmetric 10g-epon", "Symmetric 10G EPON"], ["ge", "GE"]);

	var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';

	var i=0;
	
	for( ; i<accModes.length; i++)
	{
		if(ontPonMode == accModes[i][0])
			return accModes[i][1];
	}
	
	return "--";
}

function GetLinkState()
{
	var State = <%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>;

	if (State == 1 || State == "1")
	{
		return  SmartOntdes["smart003"];
	}
	else
	{
		return SmartOntdes["smart004"];
	}
}

function GetLinkTime()
{
	var LinkTime = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.EPONLinkInfo.PONLinkTime);%>';
	var LinkDesc;

	LinkDesc = parseInt(LinkTime/3600) + SmartOntdes["smart006"] + parseInt((LinkTime%3600)/60) + SmartOntdes["smart007"];
	if (GetLinkState() == SmartOntdes["smart004"])
	{
		LinkDesc = GUIDE_NULL;
	}

	return LinkDesc;
}

function GetIPv6Address(wan)
{
	var AddressList = GetIPv6AddressList(wan.MacId);
	var AddressAcquire = GetIPv6AddressAcquireInfo(wan.domain);
    var PrefixList = GetIPv6PrefixList(wan.MacId);
	var Prefix = ((PrefixList!=null)?(PrefixList.length > 0?PrefixList[0].Prefix:'') :(PrefixList[0].Prefix));
	Prefix = (wan.Enable == "1") ? Prefix : "";
	var PrefixAcquire = GetIPv6PrefixAcquireInfo(wan.domain);
	PrefixAcquire = ((PrefixAcquire==null) ? '' : PrefixAcquire.Origin);
	var AddressHtml = "";
	for (var m = 0; m < AddressList.length; m++)
	{			
		if (AddressList[m].Origin.toUpperCase() != "LINKLOCAL")
		{				
			if (wan.Enable == "1")
			{
				if(AddressHtml == '')
					AddressHtml += AddressList[m].IPAddress;
				else
					AddressHtml += "<br>" + AddressList[m].IPAddress;
			}
		}
	}
		if((AddressHtml == "")&&(IsPTVDFFlag == 1))
		{
			if(AddressAcquire != null)
			{
				if((AddressAcquire.Origin == "None")&&(Prefix != ""))
				{
					var PrefixTemp = Prefix.split("::")[0];
					AddressHtml = PrefixTemp + "::1";
				}
			}
		}

	return AddressHtml;
}

function SetIPv4Addr(wan,id)
{
	if(("CONNECTED" == wan.Status.toUpperCase()) && ('' != wan.IPv4IPAddress) )
	{
		document.getElementById(id).innerHTML = htmlencode(wan.IPv4IPAddress);
	}
	else
	{
		document.getElementById(id).innerHTML = "--";
	}
}

function SetIPv6Addr(wan,id)
{
	var ipv6Wan = GetIPv6WanInfo(wan.MacId);
	var ipv6wanStatus = (ipv6Wan == undefined ? '':ipv6Wan.ConnectionStatus.toUpperCase());
	if("CONNECTED" == ipv6wanStatus)
	{
		document.getElementById(id).innerHTML = htmlencode(GetIPv6Address(wan));
	}
	else
	{
		document.getElementById(id).innerHTML = "--";
	}
}

function IsInternetWanUp(wan)
{
	if ('IPv4' == wan.ProtocolType)
	{
		return ("CONNECTED" == wan.Status.toUpperCase()) ? true : false;
	}
	else if ('IPv6' == wan.ProtocolType)
	{
		var ipv6Wan = GetIPv6WanInfo(wan.MacId);
		var ipv6wanStatus = (ipv6Wan == undefined ? '':ipv6Wan.ConnectionStatus.toUpperCase());
		return ("CONNECTED" == ipv6wanStatus) ? true : false;
	}
	else if ('IPv4/IPv6' == wan.ProtocolType)
	{
		var ipv6Wan = GetIPv6WanInfo(wan.MacId);
		var ipv6wanStatus = (ipv6Wan == undefined ? '':ipv6Wan.ConnectionStatus.toUpperCase());
		if("CONNECTED" == wan.Status.toUpperCase() || "CONNECTED" == ipv6wanStatus)
		{
			return true;
		}
		
		return false;
	}
	else
	{
		return false;
	}
}

function wandisPtvdfcurUser(Currentwan)
{
	setDisplay('iptypeinfo', 0);

	if (null == Currentwan)
    {
		document.getElementById("internetip").innerHTML = '--';
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
		return;
    }
	
	if (('IPv4' == Currentwan.ProtocolType) 
		||(('1' == IPProtVerMode) && ('IPv4/IPv6' == Currentwan.ProtocolType)))
	{
		SetIPv4Addr(Currentwan,'internetip');
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
	}
	else if (('IPv6' == Currentwan.ProtocolType) 
		||(('2' == IPProtVerMode) && ('IPv4/IPv6' == Currentwan.ProtocolType)))
	{
		SetIPv6Addr(Currentwan,'internetip');
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
	}
	else
	{
		SetIPv4Addr(Currentwan,'internetipv4');
		SetIPv6Addr(Currentwan,'internetipv6');
		setDisplay('internetipRow',0);
		setDisplay('internetipv4Row',1);
		setDisplay('internetipv6Row',1);
	}
}

function GetInternetWanstate()
{
	var Currentwan = null;	
    for (var i = 0; i < WanList.length; i++)
    {	
        if(('IP_Routed' == WanList[i].Mode) 
            && (WanList[i].ServiceList.toString().toUpperCase().indexOf("INTERNET") >= 0)
			&& ("1" == WanList[i].Enable)
			&& IsInternetWanUp(WanList[i]))
        {
            Currentwan = WanList[i];	
			break;
        }
    }

	if ((curUserType != sysUserType) && (1 == IsPTVDFFlag))
    {
		wandisPtvdfcurUser(Currentwan);
		return;		
	}    
	
	if (null == Currentwan)
    {
		document.getElementById("internettypevalue").innerHTML = '--';
		document.getElementById("internetip").innerHTML = '--';
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
		return;
    }
	
	document.getElementById("internettypevalue").innerHTML = htmlencode(Currentwan.ProtocolType);

	if ('IPv4' == Currentwan.ProtocolType)
	{
		SetIPv4Addr(Currentwan,'internetip');
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
	}
	else if ('IPv6' == Currentwan.ProtocolType)
	{
		SetIPv6Addr(Currentwan,'internetip');
		setDisplay('internetipRow',1);
		setDisplay('internetipv4Row',0);
		setDisplay('internetipv6Row',0);
	}
	else if ('IPv4/IPv6' == Currentwan.ProtocolType)
	{
		SetIPv4Addr(Currentwan,'internetipv4');
		SetIPv6Addr(Currentwan,'internetipv6');
		setDisplay('internetipRow',0);
		setDisplay('internetipv4Row',1);
		setDisplay('internetipv6Row',1);
	}
    return;
}

var InformStatus =  '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_UserInfo.X_HW_InformStatus);%>';
function SetItmsInfoStatus()
{
	if( '0' == InformStatus )
	{
		document.write(SmartOntdes["smart016"]);
	} 
	else if( '1' == InformStatus )
	{
		document.write(SmartOntdes["smart015"]);
	} 
	else if( '2' == InformStatus || '3' == InformStatus )
	{
		document.write(SmartOntdes["smart017"]);
	} 
	else
	{
		document.write(SmartOntdes["smart015"]);
	}	
}

function LoadFrame()
{
	GetInternetWanstate();
	if(smartlanfeature == 1){
		document.getElementById('PONinfo').style.display="none";
		document.getElementById('oltinfo').style.display="none";
	}
}
</script>
</head>
<body onLoad="LoadFrame();" style="background-color:#EDF1F2;">
<div id="SmartOntInfo"> 
	<div id="PONinfo" class="SmartOntModule">
		<div id="PONinfoTitle" class="TitleBorderCss"><span id="PONinfoTitleSpan" class="SmartinfoSpan" BindText="smart001"></span></div>
		<div id="AccessTypeinfo" class="TitleSpace">
			<div id="accessmodedes" class="SmartinfoLeft" BindText="smart021"></div>
			<div id="accessmodeType" class="Smartinforight"><script type="text/javascript" language="javascript">document.write(htmlencode(GetAccessMode()));</script></div>
		</div>
		<div id="accesslinkinfo" class="TitleSpace">
			<div id="accesslinkdes" class="SmartinfoLeft" BindText="smart002"></div>
			<div id="accesslinkvalue" class="Smartinforight"><script type="text/javascript" language="javascript">document.write(htmlencode(GetLinkState()));</script></div>
		</div>
		<div id="linktimeinfo" class="TitleSpace">
			<div id="linktimedes" class="SmartinfoLeft" BindText="smart005"></div>
			<div id="linktimevalue" class="Smartinforight"><script type="text/javascript" language="javascript">document.write(htmlencode(GetLinkTime()));</script></div>
		</div>
	</div>

	<div id="registerinfo" class="SmartOntModule_PonInfo">
		<div id="registerTitle" class="TitleBorderCss"><span id="registerTitleSpan" class="SmartinfoSpan" BindText="smart009"></span></div>
			<div id="oltinfo" class="TitleSpace">
				<div id="oltinfotitle" class="SmartinfoLeft" BindText="smart010"></div>
				<div id="oltinfovalue" class="Smartinforight">
				<script type="text/javascript" language="javascript">
				if(opticInfo == "--" || opticInfo == "")
				{ 
				document.write(SmartOntdes["smart029"]);
				}
				else
				{
				if (ontPonMode.toUpperCase() == 'GPON')
				{
				if (gponStatus.toUpperCase() == 'O5')
				{
				document.write(SmartOntdes["smart012"]);
				}
				else
				{
				document.write(SmartOntdes["smart013"]);
				}
				}
				else if (ontPonMode.toUpperCase() == 'EPON')
				{
				if (eponStatus.toUpperCase() =="ONLINE" )
				{
				document.write(SmartOntdes["smart012"]);
				}
				else
				{
				document.write(SmartOntdes["smart013"]);
				}
				}
				else
				{
				document.write(SmartOntdes["smart013"]);
				}
				
				}
				</script>
				</div>
			</div>
			<div id="itmsinfo" class="TitleSpace" style="display:none;">
				<div id="itmsinfotitle" class="SmartinfoLeft" BindText="smart014"></div>
				<div id="itmsinfovalue" class="Smartinforight"><script language="javascript">SetItmsInfoStatus()</script></div>
			</div>
		</div>

		<div id="internetinfo" class="SmartOntModule_InterNet">
			<div id="internetTitle" class="TitleBorderCss"><span id="internetTitleSpan" class="SmartinfoSpan" BindText="smart018"></span></div>
			<div id="iptypeinfo" class="TitleSpace">
				<div id="internettypedes" class="SmartinfoLeft" BindText="smart019"></div>
				<div id="internettypevalue" class="Smartinforight"></div>
			</div>
			<div id="internetipRow" class="TitleSpace" style="display:none;">
				<div id="internetipdes" class="SmartinfoLeft" BindText="smart020"></div>
				<div id="internetip" class="Smartinforight"></div>
			</div>
		<div id="internetipv4Row" class="TitleSpace" style="display:none;">
			<div id="internetipv4des" class="SmartinfoLeft" BindText="smart027"></div>
			<div id="internetipv4" class="Smartinforight"></div>
		</div>
		<div id="internetipv6Row" class="TitleSpace" style="display:none;">
			<div id="internetipv6des" class="SmartinfoLeft" BindText="smart028"></div>
			<div id="internetipv6" class="Smartinforight"></div>
		</div>

	</div>
</div>
<script>
ParseBindTextByTagName(SmartOntdes, "span", 1);
ParseBindTextByTagName(SmartOntdes, "td", 1);
ParseBindTextByTagName(SmartOntdes, "div", 1);
if(parseInt(mngttype, 10) == 1 && curUserType != sysUserType)
{
	$("#itmsinfo").css("display", "none");
}
else
{
	$("#itmsinfo").css("display", "block");
}
</script>
</div>
</body>
</html>
