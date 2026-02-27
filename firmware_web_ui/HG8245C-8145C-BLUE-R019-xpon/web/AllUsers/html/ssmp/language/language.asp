<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache">
<title>Language</title>
</head>
<script language="JavaScript"type="text/javascript">
var Var_LastLoginLang = '<%HW_WEB_GetLoginRequestLangue();%>';
var indexflag = "/index.asp";
if(parent.window.location.href.indexOf("indexconfig.asp") > 0)
{
	indexflag = "/indexconfig.asp";
}
function SubmitRadio() 
{	
  	var Form = new webSubmitForm();
	Form.addParameter('language', getRadioVal('language'));
	Form.setAction('setlanguage.cgi?'+'&RequestFile=' + indexflag);   
    Form.submit(); 
}
function CancelSubmitRadio() 
{	
	LoadFrame();
}
function LoadFrame()
{
	setRadio('language', Var_LastLoginLang);
}
</script>
<body class="mainbody" onLoad="LoadFrame();">
	<table class="setupWifiTable">
		<thead>
			<tr>
				<th BindText="s001"></th>
		    </tr>
		</thead>
	<tbody>
		<tr class="header">
			<td BindText="s002"></td>
		</tr>
		<tr>
		    <td class="cinza">
				<span style="display: inline-table;" BindText="s003"></span><input type="radio" name="language" id="radiopu" value="brasil" style="vertical-align: sub;"> &nbsp; 
				<span style="display: inline-table;" BindText="s004"></span><input type="radio" name="language" id="radioen" value="english" style="vertical-align: sub;">
			</td>
		</tr>
	</tbody>
	<tfoot>
		<tr>
			<td>
				<a class="btn-default-orange-small right" onClick="CancelSubmitRadio();" BindText="s005"></a>
				<a class="btn-default-orange-small right" onClick="SubmitRadio();" BindText="s006"></a>
			</td>
		</tr>
	</tfoot>
</table>
</body>
<script>
	ParseBindTextByTagName(LanguageLgedes, "th",   1);
	ParseBindTextByTagName(LanguageLgedes, "td",   1);
	ParseBindTextByTagName(LanguageLgedes, "input", 2);
	ParseBindTextByTagName(LanguageLgedes, "span", 1);
	ParseBindTextByTagName(LanguageLgedes, "a", 1);
</script>
</html>
