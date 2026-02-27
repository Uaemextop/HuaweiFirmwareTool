<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<link type="text/css" rel="stylesheet" href="../Cuscss/<%HW_WEB_CleanCache_Resource(index.css);%>" />
<link rel="stylesheet" href="../Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../frame.asp"></script>
<script language="JavaScript" type="text/javascript">
window.wanCacheObj = { wanListCacheObj:{}, wanIpv6StateCacheObj:{}, wanOptType: 0, curWanState: '0', wanMonitorTimer: null };
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
var xgPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';
var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>';
var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
var softversion = '<%HW_WEB_GetSoftVersion();%>';
var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';
var isHasClickedCheckBtn = false;
var OriUpPortMode ='<%HW_WEB_GetOriUpPortMode();%>';
var ponUpport = '<%HW_WEB_GetFeatureSupport(FT_PON_UPPORT_CONFIG);%>';
var isFttr = '<%HW_WEB_GetFeatureSupport(FT_FTTR_MAIN_ONT);%>' === '1';
var ConfigFlag = '<%HW_WEB_GetGuideFlag();%>';
var curUserType = '<%HW_WEB_GetUserType();%>';
var jiuzhouFlag = '<%WEB_GetJiuZhouFlag();%>';
var upgradeStatusobj = {upgradeStatus:0};
function AreaRelationInfo(ChineseDes, E8CArea)
{
	this.ChineseDes = ChineseDes;
	this.E8CArea = E8CArea;
}

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

function gotoGuidePage() {
	if (isFttr && (curUserType == 0) && !parseInt(ConfigFlag.split("#")[0], 10)) {
		window.location="/CustomApp/adminguideframe_fttr.asp";
	}

}
gotoGuidePage();

function IsIEBrower(num) {
    var ua = navigator.userAgent.toLowerCase();
    var isIE = ua.indexOf("msie")>-1;
    var safariVersion;
    if(isIE){
        safariVersion =  ua.match(/msie ([\d.]+)/)[1];
        var sa = parseInt(safariVersion);
        if(safariVersion <= num ){
           alert("您当前使用的IE浏览器版本过低（不支持IE6/7/8），必须升级到IE9及以上版本，以便正常访问WEB页面。");
        }
    }
}

</script>
<title>e8-c</title>
</head>
<body>
<div id="container">
<div id="header">
<div id="header_logo">
<script language="JavaScript" type="text/javascript">
if ('SHXCNCATV' == CfgMode.toUpperCase())
{
	document.write('<table width="100%" height="117" border="0" cellspacing="0" cellpadding="0" background="../../images/framelogo_shxcncatv.jpg">');
} else if (CfgMode.toUpperCase() == 'HUNCNCATV') {
	document.write('<table width="100%" height="117" border="0" cellspacing="0" cellpadding="0" background="../../images/framelogo_back.jpg">');
}
else if (CfgMode.toUpperCase() == 'SCCNCATV') {
	document.write('<table width="100%" height="117" border="0" cellspacing="0" cellpadding="0" background="../../images/framelogo_sccncatv.jpg">');
}
else if ('GZGD' == CfgMode.toUpperCase())
{
	document.write('<table width="100%" height="117" border="0" cellspacing="0" cellpadding="0" background="../../images/framelogo_gzgd.jpg">');
}
else
{
	document.write('<table width="100%" height="117" border="0" cellspacing="0" cellpadding="0" background="../../images/framelogo.jpg">');
}
</script>	
<tr>
<td align="right" valign="bottom">
<script language="JavaScript" type="text/javascript">
if(CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE' )
{
document.write('<div style="font-family: 宋体;font-size:14px;" ><span style="padding-right:620px;font-weight:bolder;color:#00399E;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font></span><span style="padding-right:20px;font-weight:bolder;color:#00399E;"> 欢迎您！&nbsp;&nbsp;<a id="buttonLogout">退出</a></span>');
}
else if( CfgFtWordArea.toUpperCase() == 'CHOOSE' )
{
document.write('<div style="font-family: 宋体;font-size:14px;"><span style="padding-right:620px;font-weight:bolder;color:#00399E;">您没有选择省份</span><span style="padding-right:20px;font-weight:bolder;color:#00399E;"> 欢迎您！&nbsp;&nbsp;<a id="buttonLogout">退出</a></span>');
}
else if(('SHXCNCATV' == CfgMode.toUpperCase()) || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV'))
{
document.write('<div style="font-family: 宋体;font-size:14px;padding-right:20px;font-weight:bolder;color:#00399E;">&nbsp;&nbsp;<a id="buttonLogout">退出</a>');
}
else
{
document.write('<div style="font-family: 宋体;font-size:14px;padding-right:20px;font-weight:bolder;color:#00399E;">欢迎您！&nbsp;&nbsp;<a id="buttonLogout">退出</a>');
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
<td rowspan="3" align="center" bgcolor="#EF8218" class="LocationDisplay" id="LocationDisplay">状态</td>
</tr>
</table>
</div>
<div id="header_menu_content">
<div id="content_info">
<table width="100%" height="30" border="0" cellspacing="0"
cellpadding="0">
<tr>
<td class="info_network_name">
<script language="JavaScript" type="text/javascript">
if ('SHXCNCATV' == CfgMode.toUpperCase()) {
	document.write('系统版本:'+ softversion);
} else if ((CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
	document.write('');
} else if (IsRhGateway == '1') {
	if (IsLAN == '1') {
		document.write('以太网上行融合智能终端');
	} else {
		if (E8CRONGHEFlag == 1) {
			if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
				document.write('GPON宽带融合终端');
			} else {
				document.write('EPON宽带融合终端'); 
			}
		} else {
			if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
				document.write('GPON上行融合智能终端');
			} else {
				document.write('EPON上行融合智能终端'); 
			} 
		}
	}
	
} else if (IsCTRG == 1) {
	if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
        if (isFttr && (xgPonMode.toUpperCase() == '10G-GPON')) {
            document.write('天翼网关-XGPON');
        } else {
            document.write('天翼网关-GPON');
        }
    } else if (isFttr && ((xgPonMode.toUpperCase() == '10G-GPON') || (ponUpport == 1 && OriUpPortMode == 5))) {
        document.write('天翼网关-XGPON');
	} else {
		document.write('天翼网关-EPON'); 
	}			        
} else {
	if (IsLAN == '1') {
		document.write('以太网上行智能终端');
	} else if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
	if (CfgMode.toUpperCase() == 'SHCTA8C' || CfgMode.toUpperCase() == 'A8C') {
		document.write('网关名称:GPON上行A8-C');
	} else {
		document.write('网关名称:GPON上行e8-C');
	}
	} else {
	if (CfgMode.toUpperCase() == 'SHCTA8C' || CfgMode.toUpperCase() == 'A8C') {
		document.write('网关名称:EPON上行A8-C');
	} else {
		document.write('网关名称:EPON上行e8-C');
	}
	}		        
}	    
	
</script>	
</td>

<td class="info_type">型号: <span id="productTypeName" style="color:#FFFFFF;"></span></td>
</tr>
</table>
</div>
<div id="content_mainitems">
<table height="60" border="0" cellspacing="0" cellpadding="0">
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
<table width="100%" height="15" border="0" cellspacing="0" cellpadding="0">
<tr>
<td align="right" style="background-color: #E3E3E3;"><img src="/images/panel1.gif" /></td>
<td width="747"><img src="/images/panel2.gif" height="15" width="747" /></td>
</tr>
</table>
</div>
<div id="center">
<div id="nav"></div>
<div class="center_h_bg"></div>
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
<div id="footer">
<table width="100%" height="30" border="0" cellspacing="0" cellpadding="0">
<tr>
<td width="208" style="background-color: #EF8218;"></td>
<td width="667" style="background-color: #427594;"></td>
<td width="80" style="background-color: #427594;"></td>				
</tr>
</table>
</div>
<div id="fresh">
<iframe src="/refresh.asp" frameborder="0" marginheight="0" marginwidth="0" scrolling="no" width="100%" height="100%"></iframe>
</div>
</div>
<table width="100%" height="20" border="0" cellspacing="0" cellpadding="0">
<tr>
	<script>
		tdHtml = jiuzhouFlag == "1" ? "深圳市九洲电器有限公司" : "华为技术有限公司";
		document.write('<td style="background-color:#d1d1d1;width:25%">版权所有 © 2023 ' + tdHtml + '。保留一切权利。</td>');
	</script>
</tr>
</table>
<script language="javascript" src="/html/bbsp/common/getWanDynamicData.asp"></script>
</body>
</html>