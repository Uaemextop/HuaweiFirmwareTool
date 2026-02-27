<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<link type="text/css" rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(index.css);%>" />
<link rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
<script type="text/javascript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="frame.asp"></script>
<script language="JavaScript" type="text/javascript">
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
var IsCIOT = '<%HW_WEB_GetFeatureSupport(HW_OSGI_FT_CIOTMARK);%>';
var jiuzhouFlag = '<%WEB_GetJiuZhouFlag();%>';
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
function AreaRelationInfo(ChineseDes, E8CArea)
{
	this.ChineseDes = ChineseDes;
	this.E8CArea = E8CArea;
}

var AreaRelationInfos = new Array();
var userEthInfos = new Array(new AreaRelationInfo("重庆","023"),
							 new AreaRelationInfo("四川","028"),
							 new AreaRelationInfo("云南","0871"),
							 new AreaRelationInfo("贵州","0851"),			 
							 new AreaRelationInfo("北京","010"),
							 new AreaRelationInfo("上海","021"),
							 new AreaRelationInfo("天津","022"),	 
							 new AreaRelationInfo("安徽","0551"),
							 new AreaRelationInfo("福建","0591"),
							 new AreaRelationInfo("甘肃","0931"),
							 new AreaRelationInfo("广东","020"),
							 new AreaRelationInfo("广西","0771"),			 
							 new AreaRelationInfo("海南","0898"),
							 new AreaRelationInfo("河北","0311"),
							 new AreaRelationInfo("河南","0371"),
							 new AreaRelationInfo("湖北","027"),
							 new AreaRelationInfo("湖南","0731"),
							 new AreaRelationInfo("吉林","0431"),
							 new AreaRelationInfo("江苏","025"),
							 new AreaRelationInfo("江西","0791"),
							 new AreaRelationInfo("辽宁","024"),
							 new AreaRelationInfo("宁夏","0951"),
							 new AreaRelationInfo("青海","0971"),
							 new AreaRelationInfo("山东","0531"),
							 new AreaRelationInfo("山西","0351"),
							 new AreaRelationInfo("陕西","029"),	 
							 new AreaRelationInfo("西藏","0891"),
							 new AreaRelationInfo("新疆","0991"),				 
							 new AreaRelationInfo("浙江","0571"),
							 new AreaRelationInfo("黑龙江","0451"),
							 new AreaRelationInfo("内蒙古","0471"),
							 null);
							 
function GetE8CAreaByCfgFtWord(userEthInfos,name)
{
	var length = userEthInfos.length;
	for( var i = 0; i <  length - 1; i++)
	{
		if(name == userEthInfos[i].E8CArea)
		{return userEthInfos[i].ChineseDes;}
	}
	return null;
}

var CfgFtChineseArea = GetE8CAreaByCfgFtWord(userEthInfos,CfgFtWordArea);
</script>
<title></title>
</head>
<body>
<div id="container" style="position:relative;">
<div id="header">
<div id="header_logo">
<img src="../../images/cmcc_logo.png" alt=""  style="position:absolute;top:10px;left:10px;width:170px;height:59px;" />
<table width="100%" height="80px" border="0" cellspacing="0" cellpadding="0">
<tr>
<td align="right" valign="bottom">
<script language="JavaScript" type="text/javascript">
window.wanCacheObj = { wanListCacheObj:{}, wanIpv6StateCacheObj:{}, wanOptType: 0, curWanState: '0', wanMonitorTimer: null };
if(CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE' )
{
document.write('<div style="font-family: 宋体;font-size:12px;" ><span style="display: block; float: left; margin-left: 210px;font-weight: bolder;color: #ffffff;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font></span><span style="display: block;float: right;margin-right: 20px;font-weight: bolder;color: #00399E;"> 欢迎您！&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a id="buttonLogout">退出</a></span>');
}
else if( CfgFtWordArea.toUpperCase() == 'CHOOSE' && CfgMode.toUpperCase() != 'CMCC_RMSBRIDGE' )
{
document.write('<div style="font-family: 宋体;font-size:12px;"><span style="display: block; float: left; margin-left: 210px;font-weight: bolder;color: #ffffff;">您没有选择省份</span><span style="display: block;float: right;margin-right: 20px;font-weight: bolder;color: #00399E;"> 欢迎您！&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a id="buttonLogout">退出</a></span>');
}
else
{
document.write('<div style="position:relative;bottom:20px;width:950px;height:14px;font-family:宋体;font-size:12px;padding-right:20px;font-weight:bolder;color:#FFFFFF;">欢迎您！&nbsp;<a id="buttonLogout">退出</a>');
}
</script>		
</div>
</td>
</tr>
</table>
</div>
<div id="header_menu">
<div id="header_menu_state">
<table width="100%" height="120" border="0" cellspacing="0" cellpadding="0">
<tr>
<td rowspan="3" align="center" bgcolor="#fbfbfb" class="LocationDisplay" id="LocationDisplay">状态</td>
</tr>
</table>
</div>
<div id="header_menu_content">
<div id="content_info">
<table width="100%" height="30" border="0" cellspacing="0"
cellpadding="0">
<tr>
<td class="info_network_name">
</td>

<td class="info_type">型号: <span id="productTypeName" style="color:#5c5d55;"></span></td>
</tr>
</table>
</div>
<div id="content_mainitems">
<table height="43" border="0" cellspacing="0" cellpadding="0">
<tr></tr>
</table>
</div>
<div id="content_seconditems">
<table width="100%" height="30" border="0" cellspacing="0" cellpadding="0">
<tr><td></td></tr>
</table>
</div>
</div>
</div>
</div>
<div>
</div>
<div id="center">
<div id="nav"></div>
<div id="content">
<table width="100%" height="100%" border="0" cellspacing="0" cellpadding="0">
<tr>
<td height="100%" valign="top" align="left" style="background-color: #FFFFFF;">
<iframe id="frameContent" frameborder="0" marginheight="0" marginwidth="0" scrolling="no" width="100%" height="100%"></iframe>
</td>

</tr>
</table>
</div>
</div>
<div id="fresh">
<iframe src="refresh.asp" frameborder="0" marginheight="0" marginwidth="0" scrolling="no" width="100%" height="100%"></iframe>
</div>
</div>
<table width="955px" height="40px" border="0" cellspacing="0" cellpadding="0" style="margin:0 auto">
<tr>
<td style="background-color:#d1d1d1;width:25%;text-align:center;color:#5c5d55;">
<script language="JavaScript" type="text/javascript">
if (IsCIOT == '1') {
	document.write("京ICP备05002571号 © 中国移动通信版权所有");
} else if (jiuzhouFlag == "1") {
	document.write("版权所有 © 2023 深圳市九洲电器有限公司。保留一切权利。");
} else {
	document.write("版权所有 © 2023 华为技术有限公司。保留一切权利。");
}
</script>
</td>
</tr>
</table>
<script language="javascript" src="/html/bbsp/common/getWanDynamicData.asp"></script>
</body>
</html>