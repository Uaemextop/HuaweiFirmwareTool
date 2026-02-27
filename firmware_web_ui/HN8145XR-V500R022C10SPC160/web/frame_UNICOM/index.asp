<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1"/>
<link href="Cuscss/<%HW_WEB_GetCusSource(index.css);%>" rel="stylesheet" type="text/css" />
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>"  media="all" rel="stylesheet"/>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="frame.asp"></script>    
<script language="JavaScript" type="text/javascript">
window.wanCacheObj = { wanListCacheObj:{}, wanIpv6StateCacheObj:{}, wanOptType: 0, curWanState: '0', wanMonitorTimer: null };
var curUserType = '<%HW_WEB_GetUserType();%>';
var devicename ='<%GetAspPoductName();%>';
document.title = devicename;

</script>
</head>
<body>
<div id="main" style ="background-image:url(/images/background.gif); width:1066px; height:600px; background-repeat: no-repeat; margin: 0px auto;">
<div style = "padding-top:66px;">
<div style = "background-image:url(/images/basemap.gif); background-repeat: no-repeat; margin: 0px auto; width:868px; height:470px;">
<div id="header">
<div id="headerContent">
<div id="headerTab">
<ul></ul>
</div>
<div id="headerLogout">
<span id="headerLogoutText"> <div style = "font-size: 15px; margin:9px 0 0 18px;">退出</div></span>
</div>
</div>
</div>
<div id="center">	
<div id="nav">
<ul></ul>
</div>
<div id="content">
<div id="topNavContent">
<div id="topNav" style="font-size: 12px;">
<ul></ul>
</div>
</div>
<div width = "100%" height="5"></div>
<div id="frameWarp">
<div id="frameWarpContent">
<iframe id="frameContent" frameborder="0" height="100%" marginheight="0" marginwidth="0" scrolling="auto" width="100%"></iframe>
</div>
</div>
</div>
</div>
<div id="producttitle" style="margin-top:27px;">
<span id="producttitleText" style="color:#b2b2b2;">
<script language="JavaScript" type="text/javascript">
var SingWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SINGLE_WLAN);%>';
var DoubleWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
function GetAccessMode()
{
    var accModes = new Array(["not initial", "NOT INITIAL"], ["gpon", "GPON"], ["epon", "EPON"],
                        ["10g-gpon", "10G GPON"], ["Symmetric 10g-gpon", "10G GPON"],["Asymmetric 10g-epon", "10G EPON"],
                        ["Symmetric 10g-epon", "10G EPON"], ["ge", "LAN"]);

    var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';

    var i=0;

    for( ; i<accModes.length; i++)
    {
        if(ontPonMode == accModes[i][0])
            return accModes[i][1];
    }

    return "--";
}
var ontPonMode = GetAccessMode();
if(ontPonMode=="LAN")
{
    TopoInfoNum=TopoInfoNumEx-1;
}

var TopoInfoNumEx = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Topo.X_HW_EthNum);%>';
var TopoInfoNum=TopoInfoNumEx;
if(ontPonMode=="LAN")
{
    TopoInfoNum=TopoInfoNumEx-1;
}
function stPhyInterface(Domain, InterfaceID )
{
    this.Domain = Domain;
}
var AllPhyInterface = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.PhyInterface.{i},InterfaceID,stPhyInterface);%>;
var VoiceNum = AllPhyInterface.length - 1;

var DeviceInfo = "中国联通FTTH终端";
if(-1 == ontPonMode.toUpperCase().indexOf("PON"))
{
	DeviceInfo = "中国联通家庭网关";
}

var WifiMode = "";
if(SingWlanFlag == "1")
{
    WifiMode = "+WiFi(2.4G)";
}else if (DoubleWlanFlag == "1")
{
    WifiMode = "+WiFi(2.4G + 5G)";
}	

if(curUserType==0)
{
    document.write(DeviceInfo+"&nbsp" + ontPonMode.toUpperCase() + "/" + TopoInfoNum + "+" + VoiceNum + WifiMode );
}

</script>
</span>
</div>
<div id="fresh">
<iframe frameborder="0" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="refresh.asp" width="100%"></iframe>
</div>
</div>
</div>
</div>
</div>
<script language="javascript" src="/html/bbsp/common/getWanDynamicData.asp"></script>
</body>
</html>