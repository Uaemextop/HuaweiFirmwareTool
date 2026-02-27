<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(indexclick.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
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

var UserInfo = <%HW_WEB_GetUserName(stNormalUserInfo);%>;
var sptUserName = UserInfo[0].UserName;
var sptInstantNo = UserInfo[0].InstantNo;
var PwdModifyFlag = 0;
var sysUserType = '0';
var curUserType = '<%HW_WEB_GetUserType();%>';
var curLanguage = '<%HW_WEB_GetCurrentLanguage();%>';
var mngttype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var AlarmPwdType = '<%HW_WEB_GetSPEC(SPEC_SSMP_CHKPWD_LENGTH.UINT32);%>';
var ModifyPwdType = '<%HW_WEB_GetFeatureSupport(HW_SSMP_WEB_MODIFY_AMDIN_PWD);%>';
var var_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var smartlanfeature = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var CfgMode ='<%HW_WEB_GetCfgMode();%>';

if("undefined" == AlarmPwdType || 0 == AlarmPwdType)
{
	AlarmPwdType = 6;
}

function CheckPwdIsComplex(str)
{
	var i = 0;
	if ( AlarmPwdType > str.length )
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

function LoadFrame()
{
	if(smartlanfeature == 1)
	{
		document.getElementById('PageTitle').innerHTML = GetLanguageDesc("s1119lan") 
	}
	if((1 == ModifyPwdType) && (curUserType == sysUserType) )
	{	
		sptInstantNo = 2;
		document.getElementById("username").style.display="none";
		document.getElementById("olduserpwd").style.display="block";
	}
	else
	{
		document.getElementById("username").style.display="block";
		document.getElementById('txt_Username').appendChild(document.createTextNode(sptUserName));
		document.getElementById("olduserpwd").style.display="none";
	}
	
	if((curUserType != sysUserType))
	{
		document.getElementById("olduserpwd").style.display="block";
	}

	PwdModifyFlag = UserInfo[0].ModifyPasswordFlag;

	if((parseInt(PwdModifyFlag,10) == 0) && (curLanguage.toUpperCase() != "CHINESE") && curUserType != sysUserType)
	{
		 document.getElementById('defaultpwdnotice').innerHTML='( ' + GetLanguageDesc("s1118") + ' )';
		 $('#defaultpwdnotice').css("display", "block");
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
	var oldPassword = document.getElementById("oldPassword");
	var newPassword = document.getElementById("newPassword");
	var cfmPassword = document.getElementById("cfmPassword");

	if (oldPassword.value == "" && curUserType != sysUserType)
	{
		AlertEx(GetLanguageDesc("s0f0f"));
		return false;
	}

	if (newPassword.value == "")
	{
		AlertEx(GetLanguageDesc("s0f02"));
		return false;
	}

	if (CfgMode.toUpperCase()  == 'TDE2')
	{
		if (newPassword.value.length > 64)
		{
			AlertEx(GetLanguageDesc("s1904a"));
			return false;
		}
	}
	else
	{
		if (newPassword.value.length > 127)
		{
			AlertEx(GetLanguageDesc("s1904"));
			return false;
		}
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
	
	if(curUserType != sysUserType || ((1 == ModifyPwdType) && (curUserType == sysUserType)))
	{
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
	}

	if(!CheckPwdIsComplex(newPassword.value))
	{
		AlertEx(GetLanguageDesc("s1902"));
		return false;
	}

	return true;
}

function GetLanguageDesc(Name)
{
	return AccountLgeDes[Name];
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
	
	var newPassword = getValue('newPassword');
	var guideConfigParaList = new Array(new stSpecParaArray("x.Password",newPassword, 0));

	if((curUserType != sysUserType) || ((1 == ModifyPwdType) && (curUserType == sysUserType)))
	{
		var oldPassword = getValue('oldPassword');
		var AddPara2 = new stSpecParaArray("x.OldPassword", oldPassword, 0);
		guideConfigParaList.push(AddPara2);
	}

	var Parameter = {};
	Parameter.OldValueList = null;
	Parameter.FormLiList = null;
	Parameter.UnUseForm = true;
	Parameter.asynflag = false;
	Parameter.SpecParaPair = guideConfigParaList;

	var ConfigUrl = "setajax.cgi?x=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo."+sptInstantNo+ '&RequestFile=CustomApp/mainpage.asp';
	var tokenvalue = getValue('onttoken');
	HWSetAction("ajax", ConfigUrl, Parameter, tokenvalue);
	AlertEx(GetLanguageDesc("s0f0e"));
	$('#defaultpwdnotice').css("display", "none");
	CanclePwd();
}

function CanclePwd()
{
	setText("oldPassword","");
	setText("newPassword","");
	setText("cfmPassword","");
}

function ResetONT()
{
	var Title = ResetLgeDes["s0601"];
	if(ConfirmEx(Title))
	{
		setDisable('btnReboot',1);

		var Form = new webSubmitForm();

		Form.setAction('set.cgi?x=' + 'InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard'
								+ '&RequestFile=html/ssmp/accoutcfg/ontmngt.asp');
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));
		Form.submit();
	}
}

function RestoreONT()
{
	var Title = RestoreLgeDes["s0a01"];
	if(ConfirmEx(Title))
	{
		var Form = new webSubmitForm();

		setDisable('btnRestoreDftCfg', 1);
		Form.setAction('restoredefaultcfg.cgi?' + 'RequestFile=html/ssmp/accoutcfg/ontmngt.asp');
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));
		Form.submit();
	}
}

</script>
</head>
<body onLoad="LoadFrame();" style="background-color:#EDF1F2;">
<div id="MainContent">

<div id="PageTitle" class="PageTitleCss" BindText="s1119"></div>

<div id="userinfoontmngt">
<div id="FunctionUser" class="FunctionTitle">
<div id="FunctionTitleIcon" class="FunctionTitleCss"></div>
<div id="FunctionTitleText"><span id="FunctionTitleTextSpan" class="FunctionTitleTextSpanCss" BindText="s1120"></span></div>
<div id="defaultpwdnotice"></div>
</div>

<div class="DivSpace"></div>

<div id="userconfig">
<div id="username" class="divtr" style="display:none;">
<div class="divtdlabal"><span id="useraccount" BindText="s0f08"></span></div>
<div id="txt_Username" name="txt_Username" class="divtdinput"></div>
</div>

<div id="olduserpwd" class="divtr" style="display:none;">
<div class="divtdlabal"><span id="olduserpassword" BindText="s0f13"></span></div>
<div class="divtdinput"><input type="password" id="oldPassword" name="oldPassword" class="textboxbg"></div>
</div>

<div id="newuserpwd" class="divtr">
<div class="divtdlabal"><span id="newuserpassword" BindText="s0f09"></span></div>
<div class="divtdinput"><input type="password" id="newPassword" name="newPassword" class="textboxbg"></div>
</div>

<div id="newusercfmpwd" class="divtr">
<div class="divtdlabal"><span id="newusercfmpassword"  BindText="s0f0b"></span></div>
<div class="divtdinput"><input type="password" id="cfmPassword" name="cfmPassword" class="textboxbg"></div>
</div>

<div id="submitinfo" class="divtrbutton">
<div class="divtdlabal"></div>
<div class="divtdinput">
<input type="button" id="MdyPwdApply" class="ApplyButtoncss buttonwidth_100px" onClick="SubmitPwd(this);" value="" BindText="s1121">
<input type="button" id="MdyPwdcancel" class="CancleButtonCss buttonwidth_100px" onClick="CanclePwd(this);" value="" BindText="s0f0d">
<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
</div>
</div><!-- end of submitinfo -->
</div><!-- end of userconfig -->
<div id="pwdnoticeareatitle" class="pwdnoticeareaCss"><span id="PwdNoticeTitle" class="PwdNoticeTextCss" BindText="s2010"></span></div>
<div id="pwdnoticearea" class="PwdNoticeTextCss">
<ol class="outside" id="PwdNotice"><li><span id="PwdLengthAlarm" BindText="s2011"></span></li><li><span BindText="s2012"></span></li><li><span BindText="s2013"></span></li></ol></div>
</div>
<div id="ResetRestore">
<div class="FunctionTitle">
<div id="FunctionTitleIcon" class="FunctionTitleCss"></div>
<div id="FunctionTitleText"><span id="FunctionTitleTextSpan" class="FunctionTitleTextSpanCss" BindText="s1122"></span></div>
</div>
<div id="OntReset">
<div id="ResetIcon" class="OntResetIcon"></div>
<div id="ResetButton" class="FloatLeftCss">
<input type="button"  class="bluebuttoncss buttonwidth_120px_140px" id="btnReboot" onClick="ResetONT(this);" value="" BindText="s1123"/>
</div>
<div id="ResetDes">
<table height="40px;"><tr><td class="ResetRestoreSpan" BindText="s1125"></td></tr></table>
</div>
</div>
<div id="OntRestore">
<div id="RestoreIcon" class="OntRestoreIcon"></div>
<div id="RestoreButton" class="FloatLeftCss">
<input type="button"  class="bluebuttoncss buttonwidth_140px_300px" id="btnRestoreDftCfg" onClick="RestoreONT(this);" value="" BindText="s1127"/>
</div>
<div id="RestoreDes">
<table height="40px;"><tr><td class="ResetRestoreSpan" BindText="s1126"></td></tr></table></div>
</div>
<div class="DivSpace"></div>
</div>

</div>
<script>
ParseBindTextByTagName(AccountLgeDes, "span",  1);
ParseBindTextByTagName(AccountLgeDes, "div",   1, mngttype, var_singtel);
ParseBindTextByTagName(AccountLgeDes, "td",    1);
ParseBindTextByTagName(AccountLgeDes, "input", 2);
if(8 == AlarmPwdType)
{
	SetDivValue("PwdLengthAlarm", AccountLgeDes["ss2011a"]);
}
</script>
</div>
</body>
</html>
