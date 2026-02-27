<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
<script>
function GetLanguageDesc(Name)
{
    return ResetLgeDes[Name];
}
function Reboot()
{
	if(ConfirmEx(GetLanguageDesc("s0604"))) 
	{
		setDisable('btnReboot',1);
		
		var Form = new webSubmitForm();
				
		Form.setAction('set.cgi?x=' + 'InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard'
								+ '&RequestFile=html/ssmp/reset/reset.asp');
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));						
		Form.submit();
	}
}
function RestoreDefaultCfg()
{
	if(ConfirmEx(GetLanguageDesc("s0707"))) 
	{
		var Form = new webSubmitForm();
		
		setDisable('btnRestoreDftCfg', 1);
		Form.setAction('restoredefaultcfg.cgi?' + 'RequestFile=html/ssmp/reset/reset.asp');
		Form.addParameter('x.X_HW_Token', getValue('onttoken'));
		Form.submit();
	}
}
</script>	
</head>
<body  class="mainbody"> 
	<table class="setupWifiTable">
		<thead>
			<tr>
				<th colspan="2" BindText="s0701"></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<div class="clear"></div>
					<a id="btnReboot" class="btn-default-orange-small left" onClick="Reboot();" BindText="s0702"></a>
				</td>
				<td id="td_description" BindText="s0703"></td>
			</tr>
			<tr>
				<td>
					<div class="clear"></div>
					<a id="btnRestoreDftCfg" class="btn-default-orange-small left" onClick="RestoreDefaultCfg();" BindText="s0704"></a>
					<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
				</td>
				<td id="td_description" BindText="s0705"></td>
			</tr>
		</tbody>
	</table>
<script>
	ParseBindTextByTagName(ResetLgeDes, "th",   1);
	ParseBindTextByTagName(ResetLgeDes, "td",   1);
	ParseBindTextByTagName(ResetLgeDes, "a", 1);
</script>
</body>
</html>
