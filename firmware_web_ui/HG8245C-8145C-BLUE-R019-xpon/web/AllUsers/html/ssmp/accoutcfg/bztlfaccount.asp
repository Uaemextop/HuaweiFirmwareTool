<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(md5.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
</head>
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

var sptUserName = UserInfo[0].UserName;
var sptInstantNo = UserInfo[0].InstantNo;
var AlarmPwdType = '<%HW_WEB_GetSPEC(SPEC_SSMP_CHKPWD_LENGTH.UINT32);%>';
if("undefined" == AlarmPwdType || 0 == AlarmPwdType)
{
	AlarmPwdType = 6;
}

function setAllDisable()
{
	setDisable('newUsername',1);
	setDisable('oldPassword',1);
	setDisable('newPassword',1);
	setDisable('cfmPassword',1);
	setDisable('MdyPwdApply',1);
	setDisable('MdyPwdcancel',1);
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
	if( ( window.location.href.indexOf("set.cgi?") > 0) )
	{
		AlertEx(GetLanguageDesc("s0f0e"));
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

	if(!CheckPwdIsComplex(newPassword.value))
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
	if(!CheckParameter())
	{
		return false;
	}

	var Form = new webSubmitForm();
	Form.addParameter('x.Password',getValue('newPassword'));
	Form.addParameter('x.OldPassword',getValue('oldPassword'));
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.' + sptInstantNo
						 + '&RequestFile=html/ssmp/accoutcfg/bztlfaccount.asp');
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
}
</script>
<body  class="mainbody" onLoad="LoadFrame();">
<table class="setupWifiTable" cellspacing="0" cellpadding="0">
<thead>
	<tr>
		<th colspan="2" BindText="s2300"></th>
	</tr>
</thead>
<tbody>
<tr class="header">
	<td colspan="2" BindText="s2301"> 
	</td>
</tr>
<tr>		
  <td class="firstChild width_per60">
  <table width="100%" border="0" cellpadding="0" cellspacing="0" bordercolor="#FFFFFF" class="tabal_bg">
  <tr> 
  <td class="firstChild width_per60" BindText="s2302"></td>
  <td><input name='oldPassword' type="password" id="oldPassword" size="15"></td>
  </tr>
  <tr> 
  <td class="firstChild width_per60" BindText="s2303"></td>
  <td><input name='newPassword' type="password" id="newPassword" size="15"></td> 
  </tr>
  <tr> 
  <td class="firstChild width_per60"><i style="font-style:normal;" BindText="s2303"></i><br><span class="description" BindText="s2304"></span></td>
  <td><input name='cfmPassword' type='password' id="cfmPassword" size="15"></td> 
  </tr>
  </table>  
  </td>
  <td class="tabal_pwd_notice width_per40" id="PwdNotice" BindText="ss1116d" ></td>
</tr>
</tbody>
		<tfoot>
			<tr>
				<td colspan="2">
						<a  class="btn-default-orange-small right" onClick="CancelValue();" BindText="s2306"></a>
						<a  class="btn-default-orange-small right" onClick="SubmitPwd();" BindText="s2305"></a>
						<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">	  
				</td>
			</tr>
		</tfoot>
	</table>
</body>
<script>
var all = document.getElementsByTagName("td");
for (var i = 0; i < all.length; i++)
{
    var b = all[i];
	var c = b.getAttribute("BindText");
	if(c == null)
	{
		continue;
	}
    b.innerHTML = AccountLgeDes[c];
}

var all = document.getElementsByTagName("input");
for (var i = 0; i < all.length; i++)
{
    var b = all[i];
	var c = b.getAttribute("BindText");
	if(c == null)
	{
		continue;
	}
    b.value = AccountLgeDes[c];
}
</script>
<script>
	ParseBindTextByTagName(AccountLgeDes, "th",   1);
	ParseBindTextByTagName(AccountLgeDes, "td",   1);
	ParseBindTextByTagName(AccountLgeDes, "i",   1);	
	ParseBindTextByTagName(AccountLgeDes, "span", 1);
	ParseBindTextByTagName(AccountLgeDes, "a", 1);
</script>
</html>
