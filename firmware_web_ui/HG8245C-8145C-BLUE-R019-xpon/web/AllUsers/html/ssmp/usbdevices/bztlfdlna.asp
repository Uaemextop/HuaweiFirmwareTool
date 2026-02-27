<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
</head>
<script language="JavaScript"type="text/javascript">
function stDlnaService(domain,Enable,ShareAllPath)
{
	this.domain 	= domain;
	this.Enable = Enable;
	this.ShareAllPath = ShareAllPath;
}
var dlnaServices = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.X_HW_DmsService,Enable|ShareAllPath,stDlnaService);%>;
var dlnaService = dlnaServices[0];

function SubmitRadio() 
{	
	var Form = new webSubmitForm();
	Form.addParameter('x.Enable',getRadioVal('dlna'));
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.Services.X_HW_DmsService&RequestFile=html/ssmp/usbdevices/bztlfdlna.asp');
	setDisable('btnSmbApply', 1);
	setDisable('cancelValue', 1);
	Form.submit();    
}
function CancelSubmitRadio() 
{	
	setRadio('dlna', dlnaService.Enable);
}
function LoadFrame()
{
	setRadio('dlna', dlnaService.Enable);
}
</script>
<body class="mainbody" onLoad="LoadFrame();">
	<div id="tab-03">
		<table class="setupWifiTable">
			<thead>
				<th BindText="s007"></th>
			</thead>
			<tbody>
				<tr class="header">
					<td BindText="s008">
				</tr>
				<tr>
					<td class="cinza">
						<span BindText="s003"></span><input type="radio" name="dlna" id="dlnaenable" value="1"/>&nbsp; 
						<span BindText="s004"></span><input type="radio" name="dlna" id="dlnadisable" value="0"/>
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
<script>
	ParseBindTextByTagName(UsbdevicesLgeDes, "th",   1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "td",   1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "input", 2);
	ParseBindTextByTagName(UsbdevicesLgeDes, "span", 1);
	ParseBindTextByTagName(UsbdevicesLgeDes, "a", 1);
</script>
</body>
</html>
