<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>" language="JavaScript"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<link rel="stylesheet" href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet" href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<style type="text/css">
.table_title {
	height: 30px;
	width: 280px;
	padding-left: 20px;
	font-weight: 700;
	color: #000000;
	background-color: transparent;
}

.table_right {
	height: 30px;
	padding-left: 5px;
	font-weight: 400;
	color: #000000;
	background-color: transparent;
}

.tabal_noborder_bg {
	background-color: transparent;
	padding: 0;
	z-index: 0;
}
.TextBox {
	width: 180px;
} 
#progress {
	height: 15px;
	width: 200px;
	border: 1px solid #CCCCCC;
	background-image: url(../../../images/cus_images/strength.png);
	background-repeat: repeat-y;
	background-color: blue;
	z-index: 10;
	margin-left:30px;
}
#masker {
	float: right;
	height: 15px;
	width: 200px;
	background-color: #FAFAFA;
	z-index: 30;
}
#maskertext {
	position: absolute;
	float: left;
	display: inline-block;
	font-size: 12px;
	z-index: 40;
	background: transparent;
}
#maskertext span {
	display: inline-block;
	width: 66px;
	text-align: center;
}
#PwdStrengthContainer {
	float: left;
	width: 100%;
	height:60px;
	vertical-align:middle;
	position: relative;
	margin-top: 10px;
}
#PwdStrengthIndicator {
	height: 40px;
	width: 260px;
	text-align: center;
	font-size: 14px;
}

</style>
<script language="JavaScript" type="text/javascript">
var Ftmodifyadmin = '<%HW_WEB_GetFeatureSupport(HW_SSMP_WEB_MODIFY_AMDIN_PWD);%>';  
function SetPwdStrengthIndicator() {
	var Strength = CheckPwdStrength(getValue('newPassword'));
	
	if ("simple" == Strength)
	{
		document.getElementById("masker").style.width = "133px";
	}
	else if ("medium" == Strength)
	{
		document.getElementById("masker").style.width = "66px";
	}
	else if ("strong" == Strength)
	{
		document.getElementById("masker").style.width = "0";
	}
	else
	{
		document.getElementById("masker").style.width = "200px";
	}
}

function LoadFrame()
{
	if( ( window.location.href.indexOf("X_HW_WebUserInfo") > 0) )
	{
		if (1 == Ftmodifyadmin)
		{
			AlertEx(GetLanguageDesc("s0f0e"));
		}
		else
		{
			AlertEx(GetLanguageDesc("s0f01"));
		}
	}
}

function isValidAscii(val)
{
	for ( var i = 0 ; i < val.length ; i++ )
	{
		var ch = val.charAt(i);
		if ( ch <= ' ' || ch > '~' )
		{
			return false;
		}
	}
	return true;
}


function CheckPwdIsComplexForSpecCus(str,UserName)
{
	var i = 0;
	if ( 8 > str.length )
	{
		return false;
	}

	if (!CompareString(str,UserName) )
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

	if ( isSpecialCharacterInString(str) )
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
	var oldPassword = document.getElementById("oldPassword");
	var newPassword = document.getElementById("newPassword");
	var cfmPassword = document.getElementById("cfmPassword");

	if (oldPassword.value == "")
	{
		AlertEx(GetLanguageDesc("s0f0f"));
		return false;
	}

	if (newPassword.value == "")
	{
		AlertEx(GetLanguageDesc("s0f02"));
		return false;
	}

	if (newPassword.value.length > 64)
	{
		AlertEx(GetLanguageDesc("s1904a"));
		return false;
	}

	if (!isValidAscii(newPassword.value))
	{
		AlertEx(GetLanguageDesc("s0f04"));
		return false;
	}

	if (cfmPassword.value != newPassword.value)
	{
		AlertEx(GetLanguageDesc("s0f06"));
		return false;
	}

	var NormalPwdInfo = FormatUrlEncode(oldPassword.value);
	var CheckResult = 0;

	$.ajax({
	type : "POST",
	async : false,
	cache : false,
	url : "../common/CheckNormalPwd.asp?&1=1",
	data :'NormalPwdInfo='+NormalPwdInfo,
	success : function(data) {
		CheckResult=data;
		}
	});

	if (CheckResult != 1)
	{
		AlertEx(GetLanguageDesc("s0f11"));
		return false;
	}

	if(!CheckPwdIsComplexForSpecCus(newPassword.value))
	{
		AlertEx(GetLanguageDesc("s1902"));
		return false;
	}

	setDisable('MdyPwdApply', 1);
	setDisable('MdyPwdcancel', 1);
	return true;
}

function SubmitPwd()
{
	if (!CheckParameter())
	{
		return false;
	}

	var Form = new webSubmitForm();
	Form.addParameter('x.Password',getValue('newPassword'));
	Form.addParameter('x.OldPassword',getValue('oldPassword'));
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2'
						 + '&RequestFile=html/ssmp/accoutcfg/TdeAccountConfig.asp');
	Form.submit();
}

function GetLanguageDesc(Name)
{
	return AccountLgeDes[Name];
}

function CancelValue()
{
	setText('oldPassword','');
	setText('newPassword','');
	setText('cfmPassword','');
	
	SetPwdStrengthIndicator();
}

function CheckPwdStrength(val)
{
	var HaveDigit = 0;
	var HaveBigChar = 0;
	var HaveSmallChar = 0;
	var HaveSpecialChar = 0;

	for ( var i = 0 ; i < val.length ; i++ )
	{
		var ch = val.charAt(i);
		if ( ch <= '9' && ch >= '0' )
		{
			HaveDigit = 1;
		}
		else if(ch <= 'z' && ch >= 'a')
		{
			HaveSmallChar = 1;
		}
		else if(ch <= 'Z' && ch >= 'A')
		{
			HaveBigChar = 1;
		}
		else
		{
			HaveSpecialChar = 1;
		}
	}

	var Result = HaveDigit + HaveSmallChar + HaveBigChar + HaveSpecialChar;

	if(0 == val.length)
	{
		return "none";
	}
	if(1 == Result || val.length < 8)
	{
		return "simple";
	}
	else if( (1 == HaveDigit) && (1 == (HaveSmallChar + HaveBigChar)) && (0 == HaveSpecialChar))
	{
		return "medium";
	}
	else
	{
		return "strong";
	}
}

function title_show()
{
	$("#pwdinfoAlarm").css("display", "block");
}

function title_back()
{
	$("#pwdinfoAlarm").css("display", "none");
}

</script>
</head>
<body class="iframebody" onLoad="LoadFrame();">
<div class="title_spread"></div>

<div id="PwdChangeArea" class="FuctionPageAreaCss">

<div id="PcTitle" class="FunctionPageTitleCss">
<span id="PageTitleText" class="PageTitleTextCss" BindText="s2201"></span>
</div>

<div id="PcContent" class="FuctionPageContentCss">
<div id="PageSumaryInfo1" class="PageSumaryInfoCss" BindText="s2202"></div>
</div>

<div style="height:180px;">
<div style="float:left;width:60%;height:180px;position:relative;">
<form id="PwdChangeCfgForm"  name="PwdChangeCfgForm">
<table id="PwdChangeCfgPanel" width="100%" border="0" cellpadding="0" cellspacing="1" bordercolor="#FFFFFF">
	<li id="oldPassword" RealType="TextBox"  DescRef="s2203" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.OldPassword" InitValue="Empty"/>
	<li id="newPassword" RealType="TextBox"  DescRef="s2204" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.Password"    InitValue="Empty" ClickFuncApp="onKeyUp=SetPwdStrengthIndicator;onmouseover=title_show;onmouseout=title_back"/>
	<li id="cfmPassword" RealType="TextBox"  DescRef="s2205" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="Empty"         InitValue="Empty"/>
</table>
<script>
	var PwdChangeCfgFormList = new Array();
	PwdChangeCfgFormList = HWGetLiIdListByForm("PwdChangeCfgForm", null);
	var TableClass = new stTableClass("width_per50", "width_per50");
	HWParsePageControlByID("PwdChangeCfgForm", TableClass, AccountLgeDes, null);

	var PwdChangeArray = new Array();
	HWSetTableByLiIdList(PwdChangeCfgFormList, PwdChangeArray, null);
</script>
<div class="title_spread"></div>
<div style="float:left;height:50px;padding-left:20px">
<div style="float:left;height:50px;">
<input type="button" class="BluebuttonGreenBgcss width_120px" id="MdyPwdcancel" onClick="CancelValue();" value="" BindText="s220a"/>
</div>
<div style="float:left;width:40px;height:50px;">&nbsp</div>
<div style="float:left;height: 50px;">
<input type="button" class="BluebuttonGreenBgcss width_120px" id="MdyPwdApply" onClick="SubmitPwd();" value="" BindText="s2209"/>
</div>
<input type="hidden" id="hwonttoken" name="onttoken" value="<%HW_WEB_GetToken();%>">
</div>
</form>

<div id="pwdinfoAlarm" BindText="ss1116d"></div>

</div>
<div style="float:right;width:40%;height:60px; margin-top:-10px;">
<div id="PwdStrengthContainer">
  <div id="PwdStrengthIndicator" BindText="s2206"></div>
  <div id="progress">
    <div id="masker"></div>
  	<div id="maskertext"><span BindText="s220b"></span><span BindText="s220c"></span><span BindText="s220d"></span></div>
  </div>
</div>
</div>
</div>
</body>
<script>
ParseBindTextByTagName(AccountLgeDes, "div",  1);
ParseBindTextByTagName(AccountLgeDes, "span",  1);
ParseBindTextByTagName(AccountLgeDes, "input", 2);
</script>
</html>
