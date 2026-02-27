<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Expires" content="0">
<title></title>
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>"  media="all" rel="stylesheet"/>
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script type="text/javascript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>



<script language="JavaScript" type="text/javascript">
function stResultInfo(domain, Result, Status, ForceSupport,X_HW_RegisterMode)
{
	this.domain = domain;
	this.Result = Result;
	this.Status = Status;
	this.ForceSupport = ForceSupport;
	this.X_HW_RegisterMode = X_HW_RegisterMode;
}

var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|ForceSupport|X_HW_RegisterMode, stResultInfo);%>;
var Infos = stResultInfos[0];

var FailStat ='<%HW_WEB_GetLoginFailStat();%>';
var LoginTimes = '<%HW_WEB_GetLoginFailCount();%>';
var ModeCheckTimes = '<%HW_WEB_GetModPwdFailCnt();%>';
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var Var_DefaultLang = '<%HW_WEB_GetCurrentLanguage();%>';
var Language = "chinese";
document.title = ProductName;

var simcardstatus = '<%webAspGetSimRegStatus();%>';
var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var manageFlag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CWMP_JSCT);%>';
var webLoidreg = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_WEB_LOIDREG);%>';
var webRouteSet = '<%HW_WEB_GetFeatureSupport(BBSP_FT_ROUTE_BRIDGE_TRANSLATE);%>';
var RouteStatus = '<%HW_WEB_GetRouteStatus();%>';

var MngtCtrgMode = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
var MngtShctA8C = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SHCTA8C);%>';
var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
var MngtJsct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JSCT);%>';
var MngtSzct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SZCT);%>';
var MngtAhct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_AHCT);%>';
var MngtOnlineJS = '<%HW_WEB_GetFeatureSupport(HW_SSMP_PONONLINE_DISABLEREG);%>';
var SimFlag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_SIM_CARD);%>';
var PWDLogin = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_WEB_ONLY_PWD);%>';

var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
var locklefttimerhandle;

var CfgFtWordArea = '<%GetConfigAreaInfo();%>';

var var_UserName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.UserName);%>';
var APPVersion = '<%HW_WEB_GetAppVersion();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
var ModifyPasswordFlag = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1.ModifyPasswordFlag);%>';
var pwdLen = '<%HW_WEB_GetSPEC(SPEC_SSMP_CHKPWD_LENGTH.UINT32);%>';

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
		{
			return userEthInfos[i].ChineseDes;
		}
	}

	return null;
}

var CfgFtChineseArea = GetE8CAreaByCfgFtWord(userEthInfos,CfgFtWordArea);

function SubmitForm() {
	var Username = document.getElementById('user_name');
	var Password = document.getElementById('password');
	var appName = navigator.appName;
	var version = navigator.appVersion;

	if (appName == "Microsoft Internet Explorer")
	{
		var versionNumber = version.split(" ")[3];
		if (parseInt(versionNumber.split(";")[0]) < 6)
		{
			alert("不支持IE6.0以下版本。");
			return;
		}
	}

	if( 1 != PWDLogin )
	{
		if (Username.value == "")
		{
			alert("用户名不能为空。");
			Username.focus();
			return false;
		}

	}

	if (Password.value == "") 
	{
		alert("密码不能为空。");
		Password.focus();
		return false;	
	}
	
	var cookie = document.cookie;
	if ("" != cookie)
	{
		var date=new Date();
		date.setTime(date.getTime()-10000);
		var cookie22 = cookie + ";expires=" + date.toGMTString();
		document.cookie=cookie22;
	}

	var cnt;

	$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : '/asp/GetRandCount.asp',
		success : function(data) {
			cnt = data;
		}
		});

	var Form = new webSubmitForm();
	var cookie2="Cookie=body:"+ "Language:" + Language + ":SubmitType=Login" + ":" + "id=-1;path=/";
	if (SimFlag==1)
	{	
		Form.addParameter('simun', base64encode(Username.value));
		Form.addParameter('simcn', base64encode(Password.value));
		Form.addParameter('UserName', Username.value);
		Form.addParameter('PassWord', base64encode(Password.value));
		Form.addParameter('Language', Language);
		
	}
	else
	{
		Form.addParameter('UserName', Username.value);
		Form.addParameter('PassWord', base64encode(Password.value));
		Form.addParameter('Language', Language);
	}
	document.cookie = cookie2;
	Username.disabled = true;
	Password.disabled = true;

	Form.addParameter('x.X_HW_Token', cnt);
	Form.setAction('/login.cgi');
	Form.submit();
	return true;
}

function SubmitRouteSet() {

	var Username = document.getElementById('user_name');
	var Password = document.getElementById('password');
	var appName = navigator.appName;
	var version = navigator.appVersion;

	if (appName == "Microsoft Internet Explorer")
	{
		var versionNumber = version.split(" ")[3];
		if (parseInt(versionNumber.split(";")[0]) < 6)
		{
			alert("不支持IE6.0以下版本。");
			return;
		}
	}

	if( 1 != PWDLogin )
	{
		if (Username.value == "")
		{
			alert("用户名不能为空。");
			Username.focus();
			return false;
		}

	}

	if (Password.value == "") {
		alert("密码不能为空。");
		Password.focus();
		return false;
	}

	var cookie = document.cookie;
	if ("" != cookie)
	{
		var date=new Date();
		date.setTime(date.getTime()-10000);
		var cookie22 = cookie + ";expires=" + date.toGMTString();
		document.cookie=cookie22;
	}
	var cnt;

	$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : '/asp/GetRandCount.asp',
		success : function(data) {
			cnt = data;
		}
		});
	var Form = new webSubmitForm();
	var cookie2 = "Cookie=body:" + "Language:" + Language  + ":SubmitType=SetRoute"+":" +"id=-1;path=/";
	document.cookie = cookie2;
	Username.disabled = true;
	Password.disabled = true;
	Form.addParameter('UserName', Username.value);
	Form.addParameter('PassWord', base64encode(Password.value));
	Form.addParameter('x.X_HW_Token', cnt);
	Form.setAction('/login.cgi');
	Form.submit();

}

function ResultStatusSt(domain, Result, Status)
{
	this.domain = domain;
	this.Result = Result;
	this.Status  = Status;
}

var ResultStatusInfo = new Array(new ResultStatusSt("0","0","0"),null);

function requestCgi()
{
	  $.ajax({
				type : "POST",
				async : true,
				cache : false,
				url : "/asp/GetResultStatus.asp",
				success : function(data) {
					ResultStatusInfo = dealDataWithFun(data);
				}
			});

		if (((parseInt(ResultStatusInfo.Status) == 0) && (parseInt(ResultStatusInfo.Result) == 1)))
		{
			setDisable('regdevice', 1);
			clearInterval(TimerHandle);
		}
}

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

function LoadFrame() {
    
    if (('SHXCNCATV' == CfgMode.toUpperCase())&&(0 == ModifyPasswordFlag)&&(LoginTimes < errloginlockNum))
	{
		document.getElementById('wifi_set').style.display = 'block';
		document.getElementById('login_set').style.display = 'none';
		setDisable('wifi_name',1);
		document.getElementById('wifi_name2').focus();
	}
	else
	{
		document.getElementById('password').focus();
	}
	
	if (var_UserName != null)
	{
		document.getElementById('user_name').value = var_UserName;
	}
	else
	{
		document.getElementById('user_name').value = 'useradmin';
	}
	
    document.getElementById('password').focus();


    if ((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0)) {
        document.getElementById('loginfail').style.display = '';
    }
	if(( "1" == FailStat) || (ModeCheckTimes >= errloginlockNum))
	{
		document.getElementById('loginfail').style.display = '';
		if ('SHXCNCATV' == CfgMode.toUpperCase())
		{
			setDisable('btnReboot',1);
		}
		else
		{
			setDisable('cancel',1);
		}
		setDisable('save',1);
		setDisable('user_name',1);
		setDisable('password',1);
		if (webRouteSet == 1)
		{
			setDisable('routeSet',1);
		}
	}

	init();

	if (LoginTimes >= errloginlockNum)
	{
		if ('SHXCNCATV' == CfgMode.toUpperCase())
		{
			setDisable('btnReboot',1);
		}
		else
		{
			setDisable('cancel',1);
		}
		setDisable('save',1);
		setDisable('user_name',1);
		setDisable('password',1);

		if (webRouteSet == 1)
		{
			setDisable('routeSet',1);
		}
	}
}
function init() {
	if (document.addEventListener) {
		document.addEventListener("keypress", onHandleKeyDown, false);
	} else {
		document.onkeypress = onHandleKeyDown;
	}
}
function onHandleKeyDown(event) {
	var e = event || window.event;
	var code = e.charCode || e.keyCode;

	if (code == 13) {
		SubmitForm();
	}
}

function canceltext()
{
	document.getElementById('user_name').value = "";
	document.getElementById('password').value = "";
}
function IsCTRGAreaInformBind2()
{
	var x;
	var CfgKey ='<%HW_WEB_GetCfgMode();%>';
	var Customs = ["NMGCT", "SDCT"];
	var IsCtrg = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
	if (IsCtrg == '1')
	{
		for (x in Customs)
		{
			if (Customs[x] == CfgKey.toUpperCase())
			{
				return true;
			}
		}
	}
	return false;
}
function JumpToReg()
{
	if (IsCTRGAreaInformBind2())
	{
		window.location='http://' + br0Ip +':'+ httpport +'/loidreg.asp';
	}
    else if ((Infos != null) && (parseInt(Infos.Result) == 1) && ((parseInt(Infos.Status) == 0) || (1 == MngtGdct)))
	{
		if(1 == MngtCtrgMode)
		{
			window.location='http://' + br0Ip +':'+ httpport +'/loidgregsuccess.asp';
		}
		else
		{
			if ((CfgMode.toUpperCase() != 'SHXCNCATV') && (CfgMode.toUpperCase() != 'SCCNCATV') && (CfgMode.toUpperCase() != 'HUNCNCATV'))
			{
				window.location="/loidgregsuccess.asp";
			}
			else
			{
				window.location="/loidreg.asp";
			}
		}
	}
	else
	{
		if(1 == MngtCtrgMode
			&& (('E8C' == CfgMode.toUpperCase() && CfgFtWordArea.toUpperCase() == 'CHOOSE')))
		{
			window.location='http://' + br0Ip +':'+ httpport +'/loidchooseareaTy.asp';
		}
		else
		{
			if ( 'CQCT' == CfgMode.toUpperCase())
			{
				if(1 == IsLAN)
				{
					if (confirm("按要求安装顺序为：先不插入网线，输入宽带识别码（LOID）点击\"提交\"按钮后再插入网线进行注册。"))
					{
						window.location="/loidreg.asp";
					}
				}
				else 
				{
					if (confirm("按要求安装顺序为：先不插入光纤，输入宽带识别码（LOID）点击\"提交\"按钮后再插入光纤进行注册。"))
					{
						if(1 == MngtCtrgMode)
						{
							window.location='http://' + br0Ip +':'+ httpport +'/loidreg.asp';
						}
						else
						{
							window.location="/loidreg.asp";
						}
					}
				}
			}
			else
			{
				if(1 == MngtCtrgMode)
				{
					window.location='http://' + br0Ip +':'+ httpport +'/loidreg.asp';
				}
				else
				{
					window.location="/loidreg.asp";
				}
			}
		}
		
		
	}
}

function showlefttime()
{
	if(LockLeftTime <= 0)
	{
		window.location="/login.asp";
		clearInterval(locklefttimerhandle);
		return;
	}

	var html = '您登录失败的次数已超出限制，请' +  LockLeftTime + '秒后重试！';
	SetDivValue("loginfail", html);
	LockLeftTime = LockLeftTime - 1;
}

</script>
</head>
<body onload="LoadFrame();">
<script language="javascript">
if ('SHXCNCATV' == CfgMode.toUpperCase())
{
	document.write('<div class = "wraplogin_shxcncatv">');
	document.write('<div id="top_shxcncatv" style="width:100%;">');
} else if(CfgMode.toUpperCase() == 'SCCNCATV') {
	document.write('<div class = "wraplogin_shxcncatv">');
	document.write('<div id="top_sccncatv" style="width:100%;">');
}
else if('GZGD' == CfgMode.toUpperCase())
{
	document.write('<div class = "wraplogin">');
	document.write('<div id="top_gzgd" style="width:100%;">');
} else if (CfgMode.toUpperCase() == "HUNCNCATV") {
	document.write('<div class = "wraplogin">');
	document.write('<div id="top_huncncatv" style="width:100%;">');
}
else
{
	document.write('<div class = "wraplogin">');
	document.write('<div id="top" style="width:100%;">');
}
</script>
<table border="0" cellpadding="0" cellspacing="0" width="100%">
<tr>
<td>
<script language="javascript">
if(CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE' && CfgFtWordArea.toUpperCase() != '')
{
	if(1 == IsMaintWan)
	{
		document.write('<div style="margin-top:50px;margin-left:-60px"><span style="font-weight:bolder;color:#0436A5;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font>');
	}
	else
	{
		if ((Infos != null) && (parseInt(Infos.Result) == 1) && ((parseInt(Infos.Status) == 0) || (1 == MngtGdct)))
		{
			document.write('<div style="margin-top:50px;margin-left:-60px"><span style="font-weight:bolder;color:#0436A5;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font>'+
					   '&nbsp;&nbsp;&nbsp;&nbsp;更改请<a style="text-decoration:none;color:#E5E0E0">点击&gt;&gt;</a></span></div>');
		}
		else
		{
			if(1 == MngtCtrgMode)
			{
				document.write('<div style="margin-top:50px;margin-left:-60px"><span style="font-weight:bolder;color:#0436A5;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font>'+
					   '&nbsp;&nbsp;&nbsp;&nbsp;更改请<a href="http://'+ br0Ip+':'+httpport+'/loidchooseareaTyEx.asp">点击&gt;&gt;</a></span></div>');
			}
			else
			{
				document.write('<div style="margin-top:50px;margin-left:-60px"><span style="font-weight:bolder;color:#0436A5;">您的省份：<font style="color:#FF0000">'+CfgFtChineseArea+'</font>'+
					   '&nbsp;&nbsp;&nbsp;&nbsp;更改请<a href="http://'+ br0Ip+':'+httpport+'/loidchoosearea.asp">点击&gt;&gt;</a></span></div>');
			}
		}
	}
}
else if( CfgFtWordArea.toUpperCase() == 'CHOOSE' )
{
	document.write('<div style="margin-top:50px;margin-left:-80px"><span style="font-weight:bolder;color:#0436A5;">您没有选择省份</span></div>');
}

</script>
</td>
</tr>
</table>
</div>
<div class="logincenter">
<script language="javascript">
if ((CfgMode.toUpperCase() != 'SHXCNCATV') && (CfgMode.toUpperCase() != 'SCCNCATV') && (CfgMode.toUpperCase() != 'HUNCNCATV'))
{
if (MngtShctA8C == 1) {
	document.write('<li class="title_index" style="color:#FFFFFF; position:absolute; top:75px; left:20px;">欢迎使用天翼宽带政企网关</li>');
} else {
	document.write('<li class="title_index" style="color:#FFFFFF; position:absolute; top:75px; left:20px;">欢迎使用天翼宽带家庭网关</li>');
}
	document.write('<li class="content_word" style="color:#FFFFFF; position:absolute; top:100px; left:-25px;">请输入用户名、密码登录</li>');
}
</script>

</div>
<script language="javascript">
if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV'))
{
	document.write('<div class="login_word_shxcncatv" id="login_set">');
	document.write('<div class="w_text" style="color:#000000; position:absolute; top:35px; left:-80px;">');
}
else
{
	document.write('<div class="login_word" id="login_set">');
	document.write('<div class="w_text" style="color:#FFFFFF; position:absolute; top:35px; left:-80px;">');
}
</script>

<ul style="position:absolute; top:-8px; left:50px;">
<li class="left_table" ><div align="left">用户 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
<script language="javascript">
if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV'))
{
	document.write('<li class="left_table_shxcncatv" ><div align="left">密码 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>');
}
else
{
	document.write('<li class="left_table" ><div align="left">密码 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>');
}
</script>
</ul>
<ul style="color:#FFFFFF; position:absolute; top:-8px; left:-5px;">
<script language="javascript">
if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV'))
{
	document.write('<li class="right_table"><input name="user_name" id="user_name" class="board_shxcncatv_name" type="text" size="20" style="font-size: 13px;" /></li>');
	document.write('<li class="right_table"><input name="password" id="password" class="board_shxcncatv_password" type="password" autocomplete="off" size="20" style="font-size: 13px;" /></li>');
}
else
{
	document.write('<li class="right_table"><input name="user_name" id="user_name" class="board" type="text" size="20" style="font-size: 13px;" /></li>');
	document.write('<li class="right_table"><input name="password" autocomplete="off" id="password" class="board" type="password" size="20" style="font-size: 13px;" /></li>');
}

if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV'))
{
	document.write('<li class="errorinfo_shxcncatv" ><span id ="loginfail" style="display:none;">');
}
else
{
	document.write('<li class="errorinfo" ><span id ="loginfail" style="display:none;">');
}

	clearInterval(locklefttimerhandle);
	if('1' == FailStat)
	{
		SetDivValue("loginfail", "您登录失败的次数已超出限制。");
	}
	else if(((LoginTimes >= errloginlockNum) || (ModeCheckTimes >= errloginlockNum)) && parseInt(LockLeftTime) > 0)
    {
        var html = "";
        if (LoginTimes >= errloginlockNum) {
            html = '您登录失败的次数已超出限制，请' +  LockLeftTime + '秒后重试！';
        } else if (ModeCheckTimes >= errloginlockNum) {
            html = '您尝试的次数已超出限制，请' +  LockLeftTime + '秒后重试！';
        }
        SetDivValue("loginfail", html); 
        locklefttimerhandle = setInterval('showlefttime()', 1000);
    }
	else if (LoginTimes > 0 && LoginTimes < errloginlockNum)
	{
		SetDivValue("loginfail", "密码错误，请重新输入。");
	}
	else
	{
		document.getElementById('loginfail').style.display = 'none';
	}
</script>
</span></li>
</ul>
<script type="text/javascript" language="javascript">

function setText(sId, sValue)
{
    var item = getElement(sId);
    if (item == null) {
        debug(sId + " is not existed" );
        return false;
    }
    item.value = sValue;
    return true;
}
function getValue(sId)
{
    var item = getElement(sId);
    if (item == null) {
        debug(sId + " is not existed!");
        return -1;
    }
    return item.value;
}
function isValidAscii(val)
{
    for (var i = 0; i < val.length; i++) {
        var ch = val.charAt(i);
        if (ch <= ' ' || ch > '~') {
            return false;
        }
    }
    return true;
}

function isLowercaseInString(str)
{
		var lower_reg = /^.*([a-z])+.*$/;
		var MyReg = new RegExp(lower_reg);
		if ( MyReg.test(str) )
		{
			return true;
		}
		return false;
}
function isUppercaseInString(str)
{
		var upper_reg = /^.*([A-Z])+.*$/;
		var MyReg = new RegExp(upper_reg);
		if ( MyReg.test(str) )
		{
			return true;
		}
		return false;
}
function isDigitInString(str)
{
	var digit_reg = /^.*([0-9])+.*$/;
	var MyReg = new RegExp(digit_reg);
	if ( MyReg.test(str) )
	{
		return true;
	}
	return false;
}

function isSpecialCharacterNoSpace(str)
{
	var specia_Reg =/^.*[`~!@#\$%\^&\*\(\)_\+\-=\[\]\{\}\'\;\,\./:\"\?><\\\|]{1,}.*$/;
	var MyReg = new RegExp(specia_Reg);
	if ( MyReg.test(str) )
	{
		return true;
	}
	return false;
}
function CheckPwdIsComplex(str)
{
	var i = 0;
    if (str.length < pwdLen)
	{
		return false;
	}
	
	if ( isLowercaseInString(str) )
	{
		i++;
	}
	
	if ( isUppercaseInString(str) )
	{
		i++;
	}
	
	if ( isDigitInString(str) )
	{
		i++;
	}
	
	if ( isSpecialCharacterNoSpace(str) )
	{
		i++;
	}
	if ( i >= 2 )
	{
		return true;
	}
	return false;
}
function CheckParameter()
{
	var WifiName = document.getElementById('wifi_name2');
	var WifiPassword = document.getElementById('wifi_password');
	var ManagePassword = document.getElementById('manage_password');
	var CombineFlag = document.getElementById('combine_checkbox').checked;
	
	
	
	if( 1 != PWDLogin )
	{
		if (WifiName.value == "")
		{
			alert("WiFi名称不能为空。");
			WifiName.focus();
			return false;
		}
		
		if (WifiName.value.length > 22)
		{
			alert("WiFi名称不能超过32个字符（包括sxbctvnet-）。");
			WifiName.focus();
			return false;
		}
	}

	if (WifiPassword.value == "") 
	{
		alert("WiFi密码不能为空。");
		WifiPassword.focus();
		return false;
	}
	
	if (WifiPassword.value.length < 8)
	{
		alert("WiFi密码长度不能小于8位");
		WifiPassword.focus();
		return false;
	}
	
	if (WifiPassword.value.length > 63)
	{
		alert("WiFi密码长度不能大于63位");
		WifiPassword.focus();
		return false;
	}
	
	if(CombineFlag)
	{
		setText('manage_password',getValue('wifi_password'));
	}
	
	if (ManagePassword.value == "") 
	{
		if(CombineFlag)
		{
			setText('manage_password','');
		}
		else
		{
			alert("管理密码不能为空。");
			ManagePassword.focus();
		}
		return false;
	}
	
	if (ManagePassword.value.length > 127)
	{
		if(CombineFlag)
		{
			alert("管理密码长度必须在8~127个字符之间，若仍然使用WiFi密码作为路由器管理密码，请重新输入WiFi密码");
			setText('manage_password','');
			WifiPassword.focus();
		}
		else
		{
			alert("管理密码长度必须在8~127个字符之间，请重新输入");
			ManagePassword.focus();
		}
		return false;
	}
	
	if (!isValidAscii(ManagePassword.value))
	{
		if(CombineFlag)
		{
			alert("管理密码包含非法字符，若仍然使用WiFi密码作为路由器管理密码，请重新输入WiFi密码");
			setText('manage_password','');
			WifiPassword.focus();
		}
		else
		{
			alert("管理密码包含非法字符，请重新输入");
			ManagePassword.focus();
		}
		
		return false;
	}
	
	if (!CheckPwdIsComplex(ManagePassword.value))
	{
		if(CombineFlag)
		{
			alert("管理密码复杂度不符合要求，长度至少8个字符并且至少由数字、大写字母、小写字母和特殊字符中的2种组成，若仍然使用WiFi密码作为路由器管理密码，请重新输入WiFi密码并同时满足管理密码的要求");
			setText('manage_password','');
			WifiPassword.focus();
		}
		else
		{
			alert("管理密码复杂度不符合要求，长度至少8个字符并且至少由数字、大写字母、小写字母和特殊字符中的2种组成，请重新输入");
			ManagePassword.focus();
		}
		
		return false;
	}
	
	
	return true;
}
function SubmitWifi()
{
	if(!CheckParameter())
	{
		return false;
	}
	
	var Form = new webSubmitForm();
	Form.addParameter('x.SSID', 'sxbctvnet-' + getValue('wifi_name2'));
	Form.addParameter('x.BeaconType', 'WPAand11i');
	Form.addParameter('x.X_HW_WPAand11iEncryptionModes', 'TKIPandAESEncryption');
	Form.addParameter('x.X_HW_WPAand11iAuthenticationMode', 'PSKAuthentication');
	
	Form.addParameter('y.PreSharedKey', getValue('wifi_password'));
	Form.addParameter('z.Password', getValue('manage_password'));
	Form.addParameter('x.X_HW_Token', getAuthToken());
	Form.setAction('ModifyPwdNotLogIn.cgi?x=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1&y=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1&z=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1&RequestFile=login.asp');						
	Form.submit();
	
	return true;
}

function Combine_Password()
{
	var CombineFlag = document.getElementById('combine_checkbox').checked;
	if(CombineFlag)
	{
		document.getElementById('manage_password_txt').style.display = 'none';
		document.getElementById('manage_password').style.display = 'none';
		document.getElementById('confirm_bnt').style.marginTop = '-27px';
		document.getElementById('manage_password_remind').style.display = 'none';
		wifi_password.focus();
		SetDivValue("wifi_password_remind", "WiFi密码长度不能小于8位，若将WiFi密码同时设置为路由器管理密码，则WiFi密码至少由数字、大写字母、小写字母和特殊字符中的2种组成!");
	}
	else
	{
		document.getElementById('manage_password_txt').style.display = 'block';
		document.getElementById('manage_password').style.display = 'block';
		document.getElementById('confirm_bnt').style.marginTop = '0px';
		document.getElementById('manage_password_remind').style.display = 'block';
		manage_password.focus();
		SetDivValue("wifi_password_remind", "WiFi密码长度不能小于8位!");
	}
	setText('manage_password','');
		
}

function WifiPwdRmindeOn()
{
	document.getElementById('wifi_password_remind').style.display = 'block';
}

function WifiPwdRmindeOff()
{
	document.getElementById('wifi_password_remind').style.display = 'none';
}

function MangePwdRmindeOn()
{
	document.getElementById('manage_password_remind').style.display = 'block';
}

function MangePwdRmindeOff()
{
	document.getElementById('manage_password_remind').style.display = 'none';
}


function Reboot()
{
	
	if(confirm("确定要重启吗？")) 
	{
		setDisable('btnReboot',1);
		
		var Form = new webSubmitForm();
        Form.addParameter('x.X_HW_Token', getAuthToken());
		Form.setAction('http://' + br0Ip + ':' + httpport + '/'+ 'ResetWithOutLogIn.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard&RequestFile=login.asp');									
		Form.submit();
	}
}

if (webRouteSet == 1 && 1 != IsMaintWan)
{
	document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:-95px;font-size: 13px;" id="routeSet" name="routeSet" onClick="SubmitRouteSet();" value="路由设置" ></li>');
	if (1 == RouteStatus)
	{
		setDisable('routeSet',1);
	}
}

if ('SHXCNCATV' == CfgMode.toUpperCase())
{
	document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:10px;font-size: 13px;" id="save" name="save" onClick="SubmitForm();" value="登录" ></li>');
	document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:100px;font-size: 13px;" id="btnReboot" name="btnReboot" onClick="Reboot();" value="重启">');
}
else if(CfgMode.toUpperCase() == 'SCCNCATV') {
	document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:10px;font-size: 13px;" id="save" name="save" onClick="SubmitForm();" value="登录" ></li>');
	document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:100px;font-size: 13px;" id="cancel" name="cancel" onClick="canceltext();" value="取消">');
}
else
{
	document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:25px;font-size: 13px;" id="save" name="save" onClick="SubmitForm();" value="登录" ></li>');
	document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:115px;font-size: 13px;" id="cancel" name="cancel" onclick="canceltext();" value="取消">');
}

if (0 != simcardstatus)
{
	;
}
else if (('E8C' == CfgMode.toUpperCase() && CfgFtWordArea.toUpperCase() == 'NOCHOOSE'))
{
	;
}
else
{
	if ((manageFlag != 1) || (webLoidreg == 1))
	{
		if ((Infos != null) && (((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)) )
			&& ((1 == MngtJsct) || (1 == MngtSzct)))
		{
			MngtOnlineJS=0;
			if(1 !=IsMaintWan)
			{
				document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:195px;font-size: 13px;" id="regdevice" name="regdevice" disabled="disabled" onClick="JumpToReg();" value="设备注册" ></li>');
			}
			else{
				document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:195px;font-size: 13px;" id="regdevice" name="regdevice" hidden="hidden"></li>');
			}
		}
		else if ((Infos != null) && (((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)) || (parseInt(Infos.Status) == 5))
				  && (1 == MngtAhct) )
		{
			MngtOnlineJS=0;
		}
		else
		{
            if (CfgMode.toUpperCase() == 'SHXCNCATV')
			{
				if ((parseInt(Infos.Status) == 97)){
					document.getElementById('save').style.left = "50px"
					document.getElementById('btnReboot').style.left = "150px";
				}
				else{
					if(1 !=IsMaintWan){
						document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:190px;font-size: 13px;" id="regdevice" name="regdevice" onClick="JumpToReg();" value="设备注册" ></li>');
					}				
					else{
						document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:195px;font-size: 13px;" id="regdevice" name="regdevice" hidden="hidden"></li>');
					}
				}

			}
			else
			{
				if(1 !=IsMaintWan){
                    if (CfgMode.toUpperCase() == 'SCCNCATV') {
                        document.write('<li class="login_button_shxcncatv"><input type="button" style="position:absolute; width:85px; top:0px; left:190px;font-size: 13px;" id="regdevice" name="regdevice" onClick="JumpToReg();" value="设备注册" ></li>');
                    } else {
                        document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:195px;font-size: 13px;" id="regdevice" name="regdevice" onClick="JumpToReg();" value="设备注册" ></li>');
                    }
				}
				else{
					document.write('<li class="login_button"><input type="button" style="position:absolute; top:0px; left:195px;font-size: 13px;" id="regdevice" name="regdevice" hidden="hidden"></li>');
				}
			}
			if (LoginTimes >= errloginlockNum)
			{
			
				if ('SHXCNCATV' == CfgMode.toUpperCase())
				{
					if ((parseInt(Infos.Status) != 97))
					{
						setDisable('regdevice',1);
					}
				}
				else
				{
					setDisable('regdevice',1);
				}
			}
		}
	}

	if(1 == MngtOnlineJS)
	{
		var TimerHandle = setInterval("requestCgi()", 5000);
	}
}

</script>
</li>
</div>
</div>

<div class="login_word_shxcncatv" id="wifi_set" style="display: none;">
<div class="w_text" style="color:#000000; position:absolute; top:35px; left:-80px;">

<div class="reminder" style ="text-align: left; padding-left: 48px; color: #1808e6; height: 20px; line-height: 20px; ">给您的无线取个好听的名字，设置安全的密码&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div>

<div class ="listUl" style="clear:both; height: 90px;">
	<ul style="position:absolute; top:20px; left:19px; height:15px; line-height: 21px;">
		<li class="left_table" ><div align="left">WiFi名称 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
		<li style="position: relative; top: 4px;" ><div align="left">WiFi密码 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
		<li style="position: relative; top: 8px;" ><div id="manage_password_txt" align="left">管理密码 :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
	</ul>

	<ul style="color:#FFFFFF; position:absolute; top:20px; left:-15px; height:15px">
		<li class="right_table"><input name="wifi_name" id="wifi_name" class="board_shxcncatv_name" type="text" size="20" style="font-size: 13px; width: 83px; " value="sxbctvnet"  /></li>
		<li class="right_table"><input name="wifi_password" id="wifi_password" onfocus="WifiPwdRmindeOn();" onblur="WifiPwdRmindeOff();" class="board_shxcncatv_password" type="password" autocomplete="off" size="20" style="font-size: 13px; width: 170px;" /></li>
		<li style="position: relative; top: 5px;"><input name="manage_password" id="manage_password" onfocus="MangePwdRmindeOn();" onblur="MangePwdRmindeOff();" class="board_shxcncatv_password" type="password" autocomplete="off" size="20" style="font-size: 13px; width: 170px;" /></li>
	</ul>

	<ul style="position: absolute; top: 18px; left: 170px; height:15px">
		<li class="left_table" ><div align="left">-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
	</ul>

	<ul style="color:#FFFFFF; position:absolute; top:20px; left:85px; height:15px">
		<li class="right_table"><input name="wifi_name2" id="wifi_name2" class="board_shxcncatv_name" type="text" size="20" style="font-size: 13px; width: 71px;" /></li>
	</ul>
	
	<ul style="position:absolute; top:40px; left:260px; height:15px; line-height: 21px; width: 170px;">
		<li id="wifi_password_remind" style="position: absolute; top: 5px; left: 40px; width: 170px; color: #ea6514; display: none; " ><div  align="left">WiFi密码长度不能小于8位!&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</div></li>
		<li id="manage_password_remind" style="position: absolute; top: 32px; left: 40px; width: 170px; color: #ea6514; display: none; " ><div  align="left">管理密码长度至少8个字符并且至少由数字、大写字母、小写字母和特殊字符中的2种组成!</div></li>
	</ul>
	
</div>
<div class ="confirmBtn" id="confirm_bnt" style="text-align:left; margin-left:35px; ">
	<input type="checkbox" name="combine_checkbox" id="combine_checkbox" style="vertical-align: bottom;" onClick="Combine_Password();" value="ON">将WiFi密码同时设置为路由器管理密码
	<br><input type="button" style="text-align: center; margin: 10px 110px; display: block; width: 68px; height: 24px; background-color: #137af5; border: none; border-radius: 3px; color: #fff; letter-spacing: 10px; padding-left: 15px;" id="wifi_confirm" name="wifi_confirm" onClick="SubmitWifi();" value="确定" >
</div>

</div>
</div>

</div>
</body>
</html>
