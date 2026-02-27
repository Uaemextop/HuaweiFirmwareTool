<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link type='text/css' rel="stylesheet" href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>'>
<link type='text/css' rel="stylesheet" href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
</head>
<script language="JavaScript"type="text/javascript">
var SMBEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.StorageService.1.NetworkServer.SMBEnable);%>';
function SubmitRadio() 
{	
	var Form = new webSubmitForm();
	Form.addParameter('x.SMBEnable',getRadioVal('samba'));
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.Services.StorageService.1.NetworkServer&RequestFile=html/ssmp/usbdevices/fileshare.asp');
	setDisable('btnSmbApply', 1);
	setDisable('cancelValue', 1);
	Form.submit();  
}
function CancelSubmitRadio() 
{	
	setRadio('samba',SMBEnable);
}
function LoadFrame()
{
	setRadio('samba',SMBEnable);
}
</script>
<body class="mainbody" onLoad="LoadFrame();">
	<div id="tab-01">
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
					 <span BindText="s003"></span><input name="samba" id="sambaenable" type="radio" value="1"/>&nbsp;
					 <span BindText="s004"></span><input name="samba" id="sambadisabled" type="radio" value="0"/>
					</td>
				</tr>
			</tbody>
			<tfoot>
				<tr>
				    <td>
						<a class="btn-default-orange-small right" id="cancelValue" onClick="CancelSubmitRadio();" BindText="s009"></a>
						<a class="btn-default-orange-small right" id="btnSmbApply" onClick="SubmitRadio();" BindText="s010"></a>
						<input type="hidden" name="onttoken" id="onttoken" value="<%HW_WEB_GetToken();%>">
					</td>
				</tr>
			</tfoot>
		</table>	
	</div>
</body>
<script>
	ParseBindTextByTagName(UsbdevicesLgeDes, "th",   1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "td",   1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "input", 2);
	ParseBindTextByTagName(UsbdevicesLgeDes, "span", 1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "a", 1);
</script>
</html>
