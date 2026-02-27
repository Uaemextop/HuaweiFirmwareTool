<html>
<head>
<META http-equiv=Content-Type content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<title>中国电信—我的E家</title>
</head>
<style>
.input_time {border:0px; }
</style>
<script language="javascript">
var CurrentBin = '<%HW_WEB_GetBinMode();%>';
var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
function LoadFrame()
{ 
}

function JumpTo()
{
	window.location="/loidreg.asp";
}

</script>
<body onload="LoadFrame();"> 
<form> 
<div align="center"> 
<TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0"> 
<TBODY> 
<TR> 
<TD ><IMG height="137" src="/images/register_banner.gif" width="808"></TD> 
</TR> 
<TR> 
<TD> 
<TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0"> 
<TBODY> 
<TR> 
<TD width="77" background="/images/bg.gif" rowSpan="3"></TD> 

<TD align="center" width="653" height="323" background="/images/register_gdinfo.gif"> <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0"> 
<TR> 
								<TD align="right">
								<script language="javascript">
								document.write('<A href="http://' + br0Ip +':'+ httpport +'/login.asp"><font style="font-size: 14px;" color="#000000">返回登录页面</FONT></A>');
								</script>
								</TD>
</TR> 
</TABLE> 
<TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">  
<TD colSpan="2" height="32"></TD> 
<TR height="8"> 
<TD colspan="2"></TD> 
</TR> 
<TR> 
<script language="javascript">
if (CurrentBin.toUpperCase() == "A8C") {
    document.write('<TD align="middle" colSpan="2" height="25">ONU SN (A8-C LOID)注册超时！请检查线路后重试！</TD> ');
} else {
    document.write('<TD align="middle" colSpan="2" height="25">ONU SN (E8-C LOID)注册超时！请检查线路后重试！</TD> ');
}
</script>
</TR> 
<TR> 
<TD align="center" colSpan="2" width="100%" height="30"></TD> 
</TR> 
<TR> 
<TD valign="bottom" align="right" width="130" height="22"></TD> 
<TD valign="bottom" align="left" width="130"></TD> 
</TR> 
<TR> 
<TD valign="top" align="right" width="130" height="22"></TD> 
<TD valign="top" align="left" width="130"></TD> 
</TR> 
<TR> 
<TD colspan="2" align="center"><input type="button" class="submit" style="font-size: 16px;" value="返 回" onclick="JumpTo();"/></TD> 
</TR> 
<TR> 
<TD align="middle" colSpan="2" height="5"></TD> 
</TR> 
<TR> 
<TD align="center" colSpan="2" width="100%" height="20"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD> 
</TR> 
<TR> 
<TD align="left" colSpan="2" height="60"></TD> 
</TR> 
</TABLE> 
<TD width="78" background="/images/bg.gif" rowSpan="3"></TD> 
</TR> 
</TBODY> 
</TABLE></TD> 
</TR> 
</TBODY> 
</TABLE> 
</div> 
</form> 
</body>
</html>
