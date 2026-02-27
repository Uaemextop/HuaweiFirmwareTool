<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">

<link rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
<title>LOID</title>
<script language="JavaScript" type="text/javascript">
var JSLoid ='<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_UserInfo.JSCT_UserName);%>';
var recordLoid = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.X_HW_Loid);%>';

function LoadFrame()
{ 
}

</script>
</head>

<body  class="mainbody" onLoad="LoadFrame();">
<table width="100%" height="10%" border="0" cellspacing="0" cellpadding="0">
    <tr>
        <td class="prompt">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                    <td width="100%" align="center">
			<script language="JavaScript" type="text/javascript">
			if (JSLoid == recordLoid )
			{
			    document.write("烧制终端序列号成功。");
		        }
			else
			{
			    document.write("烧制终端序列号失败。");
			}
			</script>		
		    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>
</body>
</html>





