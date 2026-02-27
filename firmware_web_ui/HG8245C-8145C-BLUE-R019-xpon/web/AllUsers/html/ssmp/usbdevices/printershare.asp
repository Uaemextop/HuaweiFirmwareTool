<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_CleanCache_Resource(gateway.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
</head>
<script language="JavaScript"type="text/javascript">

function stDftPrinter(domain,PrinterEnable,PrinterName)
{
	this.domain 	= domain;
	this.PrinterEnable = PrinterEnable;
	this.PrinterName = PrinterName;
}
var dftPrinters = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.X_HW_Printer,Enable|Name,stDftPrinter);%>;
var dftPrinter = dftPrinters[0];

var NetworkProtocolAuthReq  = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.StorageService.1.NetworkServer.NetworkProtocolAuthReq);%>';

function SubmitRadio() 
{	
	var Form = new webSubmitForm();
	Form.addParameter('x.NetworkProtocolAuthReq',getRadioVal('printers'));
	Form.addParameter('x.X_HW_Token', getValue('onttoken'));
	Form.setAction('set.cgi?x=InternetGatewayDevice.Services.StorageService.1.NetworkServer&RequestFile=html/ssmp/usbdevices/printershare.asp');
	setDisable('btnSmbApply', 1);
	setDisable('cancelValue', 1);
	Form.submit();    
}
function CancelSubmitRadio() 
{	
	setRadio('printers', NetworkProtocolAuthReq);
}
function LoadFrame()
{
	setRadio('printers', NetworkProtocolAuthReq);
}
</script>
<body class="mainbody" onLoad="LoadFrame();">
	<div id="tab-02">
		<table class="setupWifiTable">
			<thead>
				<th BindText="s005"></th>
			</thead>
			<tbody>
				<tr class="header">
					<td BindText="s006"></td>
				</tr>
				<tr>
					<td class="cinza">
						<span BindText="s003"></span><input type="radio" name="printers" id="printersenable" value="1"/>&nbsp; 
						<span BindText="s004"></span><input type="radio" name="printers" id="printersdisable" value="0"/>
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
</body>
</html>
