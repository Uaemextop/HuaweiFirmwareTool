<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(index_green.css);%>" rel="stylesheet" type="text/css" />
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="frame.asp"></script>    
<title></title>
<script language="JavaScript" type="text/javascript">
var curUserType = '<%HW_WEB_GetUserType();%>';
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var isZQCU = '<%HW_WEB_GetFeatureSupport(HW_FEATURE_ZQCU);%>';
if (CfgMode.toUpperCase() != 'LNCU')
{
	window.location="/index.asp";
}
else
{
	if(curUserType == 1)
	{
		window.location="/index.asp";
	}
}

var devicename ='<%GetAspPoductName();%>';
if (isZQCU == 1) {
    devicename ='<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
}
document.title = devicename;
</script>
</head>
<body>
<div id="main">
<div id="header">
<div id="headerContent">
<div id="producttitle" style="float:left;margin-top:26px;margin-left:150px; width:60px">
<span id="producttitleText" style="color:#FFFFFF;font-weight: bold;">
<script language="JavaScript" type="text/javascript">document.write(devicename);</script>
</span>
</div>
<div id="headerTab">
<ul></ul>
</div>
<div id="headerLogout">
	<span id="headerLogoutText"></span>
</div>
</div>
</div>
<div id="center">
<script type="text/javascript" language="javascript">	
document.write('<div id="nav">');
</script>
<ul></ul>
</div>
<div id="content">
<div id="topNavContent">
	<div id="topNav">
	   <ul></ul>
	</div>
	<div id="topNavLine"></div>
</div>
<div id="frameWarp">
	<div id="frameWarpContent">
		<iframe id="frameContent" frameborder="0" height="100%" marginheight="0" marginwidth="0" scrolling="auto" width="100%"></iframe>
	</div>
</div>
</div>
</div>
<div style="background-image:url(/images/cu_bg_bottom.gif);" id="footer">
<table border="0" cellpadding="0" cellspacing="0" width="100%" align="left" >
<tr>
<td style="height:10px">
<img src="../images/icon_02.gif" width="10" height="10" style="margin-left:20px"/>
<font  style="color:#FFFFFF">网上营业厅&nbsp;</font>
<a href="http://www.10010.com" target="_blank" style="text-decoration:none;color:#FFFFFF">www.10010.com</a>
<img src="../images/icon_02.gif" width="10" height="10" style="margin-left:1px"/>
<font  style="color:#FFFFFF">客服热线10010&nbsp;&nbsp;充值专线10011</font>
</td>
</tr>
</table>
</div>
<div id="fresh">
<iframe frameborder="0" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="refresh.asp" width="100%"></iframe>
</div>
</div>
</body>
</html>