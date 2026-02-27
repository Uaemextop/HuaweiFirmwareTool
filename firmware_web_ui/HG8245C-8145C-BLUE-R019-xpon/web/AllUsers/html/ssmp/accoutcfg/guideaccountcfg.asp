<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' rel="stylesheet" type="text/css" />
<link href='../../../Cuscss/<%HW_WEB_GetCusSource(guide.css);%>' rel="stylesheet" type='text/css' />
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(md5.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" type="text/javascript">

function GetLanguageDesc(Name)
{
    return AccountLgeDes[Name];
}

function stNormalUserInfo(UserName, ModifyPasswordFlag, InstantNo)
{
    this.UserName = UserName;
    this.ModifyPasswordFlag = ModifyPasswordFlag;
    this.InstantNo = InstantNo;
}

var UserInfo = <%HW_WEB_GetNormalUserInfo(stNormalUserInfo);%>;
var logo_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var TypeWord_com = '<%HW_WEB_GetTypeWord();%>';
var sptUserName = UserInfo[0].UserName;
var sptInstantNo = UserInfo[0].InstantNo;

var PwdModifyFlag = 0;
var sysUserType = '0';
var curUserType = '<%HW_WEB_GetUserType();%>';
var curWebFrame = '<%HW_WEB_GetWEBFramePath();%>';
var curLanguage = '<%HW_WEB_GetCurrentLanguage();%>';

var IsSurportInternetCfg  = "<%HW_WEB_GetFeatureSupport(BBSP_FT_GUIDE_PPPOE_WAN_CFG);%>";
var IsSurportWlanCfg  = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_WLAN);%>';

function CheckPwdIsComplex(str)
{
	var i = 0;
	if ( 6 > str.length )
	{
		return false;
	}

	if (!CompareString(str,sptUserName) )
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

function LoadFrame()
{
	document.getElementById('txt_Username').appendChild(document.createTextNode(sptUserName));
	PwdModifyFlag = UserInfo[0].ModifyPasswordFlag;

	if((parseInt(PwdModifyFlag,10) == 0) && (curLanguage.toUpperCase() != "CHINESE"))
	{
		if (true != logo_singtel)
		{
			document.getElementById('defaultpwdnotice').innerHTML=GetLanguageDesc("s1118");
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

function CheckParameter()
{
	var oldPassword = document.getElementById("txt_oldPassword");
	var newPassword = document.getElementById("txt_newPassword");
    var cfmPassword = document.getElementById("txt_newcfmPassword");

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

	if (newPassword.value.length > 127)
	{
		AlertEx(GetLanguageDesc("s1904"));
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
		url : "/html/ssmp/common/CheckNormalPwd.asp?&1=1",
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

	if(!CheckPwdIsComplex(newPassword.value))
	{
		AlertEx(GetLanguageDesc("s1902"));
		return false;
	}

	return true;
}

function FormatUrlEncode(val)
{
	if(null != val)
	{
		var formatstr = escape(val);
		formatstr=formatstr.replace(new RegExp(/(\+)/g),"%2B");
		formatstr = formatstr.replace(new RegExp(/(\/)/g), "%2F");
		return formatstr
	}
	return null;
}

function SubmitPwd(val)
{
	if(!CheckParameter())
	{
		return false;
	}

	var newPassword = getValue('txt_newPassword');
	var OldPassword = getValue('txt_oldPassword');
	var guideConfigParaList = new Array(new stSpecParaArray("x.Password",  newPassword, 0),
                                        new stSpecParaArray("x.OldPassword", OldPassword, 0));

	var Parameter = {};
	Parameter.OldValueList = null;
	Parameter.FormLiList = null;
	Parameter.UnUseForm = true;
	Parameter.asynflag = false;
	Parameter.SpecParaPair = guideConfigParaList;
	
	

	var ConfigUrl = "setajax.cgi?x=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo."+sptInstantNo+ '&RequestFile=html/ssmp/accoutcfg/guideaccountcfg.asp';
	var tokenvalue = getValue('onttoken');
	HWSetAction("ajax", ConfigUrl, Parameter, tokenvalue);
	
	if (true == logo_singtel && TypeWord_com != "COMMON")
	{
		val.name = "/html/ssmp/cfgguide/userguidecfgdone_singtel.asp";
	}
	window.parent.onchangestep(val);
}

function onskip(val)
{
	val.id = "guidecfgdone";
	if (true == logo_singtel && TypeWord_com != "COMMON")
	{
		val.name = "/html/ssmp/cfgguide/userguidecfgdone_singtel.asp";
	}
	window.parent.onchangestep(val);
}

function onprevious(val)
{
	$.ajax({
		type : "POST",
		async : false,
		cache : false,
		url : '/smartguide.cgi?1=1&RequestFile=index.asp',
		data:'Parainfo='+'0',
		success : function(data) {
		}
		});

	if((0 == IsSurportInternetCfg) && (0 == IsSurportWlanCfg))
	{
		if (true == logo_singtel && TypeWord_com != "COMMON")
		{
			window.parent.location="../../../mainpage.asp";
		}
		else
		{
			window.parent.location="../../../index.asp";
		}
		return;
	}
	else if((1 == IsSurportInternetCfg) && (0 == IsSurportWlanCfg))
	{
		val.id = "guideinternet";
		val.name = "/html/bbsp/guideinternet/guideinternet.asp";
	}

	window.parent.onchangestep(val);
}
</script>
<style type="text/css">
.Modifyuserinfo{
	width:500px;
	float:left;
}

.nofloat{
	float:none;
}

.Pwdfloatleft{
	float:left;
}

.pwdnoticetitle{
	margin-top:16px;
}

.clearfixarea{
clear:both;
display:block;
font-size:0;
height:0;
line-height:0;
overflow:hidden;
}

/*IE7 compatible begin*/
.contentModifypwdItem{
	*text-align:left;
}

.contenModifypwdbox{
	*width:240px;
	*text-align:left;
	*padding-left:10px;
}

.txt_Username{
	*padding-left:10px;
}

.textboxbg{
	*margin:auto 0px;
}
/*IE7 compatible end*/

#guideskip{
	text-decoration:none;
	color:#666666;
	white-space:nowrap;
	*display:block;			/*IE7 compatible*/
	*margin-top:-26px;		/*IE7 compatible*/
	*margin-left:250px;		/*IE7 compatible*/
	*text-decoration:none;	/*IE7 compatible*/
}

a span{
	font-size:16px;
	margin-left:10px;
}

#defaultpwdnotice{
	color:red;
	font-size:14px;
}
table{
	border:0px;
	cellspacing:0;
	cellpadding:0;
}
.acctablehead{
	font-size:16px;
	color:#666666;
	font-weight:bold;
	text-align:center;
}
</style>
</head>
<body onLoad="LoadFrame();" style="background-color: #ffffff;">
	<div align="center">
		<table width="550px" style="margin:0 auto;">
			<tr>
				<td height="40"></td>
			</tr>
			<tr align="left">
				<td class="acctablehead" BindText="s2000"></td>
			</tr>
		</table>

		<table width="100%" height="10px">
			<tr>
				<td height="10"></td>
			</tr>
			<tr align="center">
				<td id="defaultpwdnotice"></td>
			</tr>
		</table>
		<div id="userinfo">
		<div id="Modifyuserinfo" class="Modifyuserinfo">
			<div id="username" class="contentModifypwdItem">
				<div class="ModifypwdlabelBox"><span id="useraccount" BindText="s0f08"></span></div>
				<div class="Pwdfloatleft txt_Username" id="txt_Username" name="txt_Username"></div>
			</div>

			<div id="olduserpwd" class="contentModifypwdItem">
				<div class="ModifypwdlabelBox"><span id="olduserpassword" BindText="s0f13"></span></div>
				<div class="contenModifypwdbox Pwdfloatleft"><input type="password" id="txt_oldPassword" name="txt_oldPassword" class="textModifypwdboxbg"></div>
			</div>

			<div id="newuserpwd" class="contentModifypwdItem">
				<div class="ModifypwdlabelBox"><span id="newuserpassword" BindText="s0f09"></span></div>
				<div class="contenModifypwdbox Pwdfloatleft"><input type="password" id="txt_newPassword" name="txt_newPassword" class="textModifypwdboxbg"></div>
			</div>

			<div id="newusercfmpwd" class="contentModifypwdItem">
				<div class="ModifypwdlabelBox"><span id="newusercfmpassword" BindText="s0f0b"></span></div>
				<div class="contenModifypwdbox Pwdfloatleft"><input type="password" id="txt_newcfmPassword" name="txt_newcfmPassword" class="textModifypwdboxbg"></div>
			</div>
			</div>
			
			<div class="guidepwdnoticearea Pwdfloatleft">
			<div id="pwdnoticetitle" class="pwdnoticetitle"><span id="PwdNoticeTitle" BindText="s2010"></span></div>
			<div id="pwdnoticearea">
			<ol class="outside" id="PwdNotice">
			<li><span BindText="s2011"></span></li>
			<li><span BindText="s2012"></span></li>
			<li><span BindText="s2013"></span></li>
			</ol>
			</div>
			</div>
			
		 <div id="clearfixarea" class="clearfixarea"></div>

		</div>
		
		<div id="ConfigAreaInfo">
		<div class="contentModifypwdItem nofloat">
		<div class="ModifypwdlabelBox"></div>
		<div class="contenModifySubmitbox">
		<input type="button" id="guidewificfg" name="/html/amp/wlanbasic/guidewificfg.asp" class="CancleButtonCss buttonwidth_100px" onClick="onprevious(this);">
		<script>
		if((0 == IsSurportInternetCfg) && (0 == IsSurportWlanCfg))
		{
			setText('guidewificfg', AccountLgeDes['s2004']);
		}
		else
		{
			setText('guidewificfg', AccountLgeDes['s2001']);
		}
		</script>
		<input type="button" id="guidecfgdone" name="/html/ssmp/cfgguide/userguidecfgdone.asp" class="ApplyButtoncss buttonwidth_100px"  onClick="SubmitPwd(this);" BindText="s2002">
		<a id="guideskip" name="/html/ssmp/cfgguide/userguidecfgdone.asp" href="#" onClick="onskip(this);">
		<span BindText="s2003"></span>
		</a>
		<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
		</div>
		</div>
		</div>	
	</div>

	<script>
		ParseBindTextByTagName(AccountLgeDes, "span",  1);
		ParseBindTextByTagName(AccountLgeDes, "td",    1);
		ParseBindTextByTagName(AccountLgeDes, "input", 2);
	</script>
</div>
</body>
</html>
