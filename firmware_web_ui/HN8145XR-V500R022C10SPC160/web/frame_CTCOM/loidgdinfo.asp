<html>
<head>
<META http-equiv=Content-Type content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<script language="JavaScript" type="text/javascript">
	var BinWord ='<%HW_WEB_GetBinMode();%>';
	if(BinWord.toUpperCase() == 'A8C') {
		document.write('<title>中国电信-政企网关</title>');
	} else {
		document.write('<title>中国电信—我的E家</title>');
	}
</script>
</head>
<style>
.input_time {border:0px; }
</style>
<script language="javascript">
var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
function LoadFrame()
{ 
}

</script>

<body onload="LoadFrame();">
<form>
<div align="center">
<TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0">
<TBODY>
	<TR>
        <script language="javascript">
            if (BinWord.toUpperCase() == 'A8C') {
                document.write('<TD height="137" style="background-color:#FDE5CD" width="808"></TD>');
            } else {
                document.write('<TD ><IMG height="137" src="/images/register_banner.gif" width="808"></TD>');
            }
        </script>
	</TR>
	<TR>
		<TD>
			<TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0">
			<TBODY>
				<TR>
                    <script language="javascript">
                        if (BinWord.toUpperCase() == 'A8C') {
                            document.write('<TD width="77" style="background-color:#FDE5CD" rowSpan="3"></TD>');
                            document.write('<TD align="center" width="653" height="323" style="background-color:#FDE5CD">');
                        } else {
                            document.write('<TD width="77" background="/images/bg.gif" rowSpan="3"></TD>');
                            document.write('<TD align="center" width="653" height="323" background="/images/register_gdinfo.gif">');
                        }
                    </script>
						<TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
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
                                                        <TR height="8"><TD colspan="2"></TD></TR>
							<TR><TD align="middle" colSpan="2" height="25">业务下发失败，请检查vlan46网络管理通道！</TD></TR>
							<TR>
								<TD valign="bottom" align="right" width="130" height="25"></TD>
								<TD valign="bottom" align="left" width="130"></TD>
							</TR>
							<TR>
								<TD valign="top" align="right" width="130" height="25"></TD>
								<TD valign="top" align="left" width="130"></TD>
							</TR>
							<TR>
								<TD align="middle" colSpan="2" height="35"></TD>
							</TR>
							<TR>
								<TD align="center" colSpan="2" width="100%" height="20"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD>
							</TR>
							<TR>
								<TD align="left" colSpan="2" height="60"></TD>
							</TR>
						</TABLE>  
                    <script language="javascript">
                        if (BinWord.toUpperCase() == 'A8C') {
                            document.write('<TD width="78" style="background-color:#FDE5CD" rowSpan="3"></TD>');
                        } else {
                            document.write('<TD width="78" background="/images/bg.gif" rowSpan="3"></TD>');
                        }
                    </script>
				</TR>
			</TBODY>
			</TABLE>
		</TD>
	</TR>
</TBODY>
</TABLE>
</div>
</form>
</body>
</html>
