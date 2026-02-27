<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
<title>LOID</title>
<script language="JavaScript" type="text/javascript">

var RegStatus = "<%webQueryInternetStatus();%>";

function analysisResult(RegStatus)
{	
    if (RegStatus == "Connected")
	{	
		document.getElementById("ftitle").innerHTML = "已拨号上网";
	}
	else if (RegStatus == "Connecting")
	{
		document.getElementById("ftitle").innerHTML = "正在拨号中";
	}
	else if (RegStatus == "None")
	{
		document.getElementById("ftitle").innerHTML = "未开通上网业务";
	}
	else
	{
		document.getElementById("ftitle").innerHTML = "未开通上网业务";
	}
	
	return;
}


function LoadFrame()
{ 
	analysisResult(RegStatus);
}

</script>
</head>

<body  class="mainbody" onLoad="LoadFrame();">
<table width="100%" height="10%" border="0" cellspacing="0" cellpadding="0">
    <tr>
        <td class="prompt">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                   <td width="100%" align="center" id="ftitle">	
				</td>
                </tr>
            </table>
        </td>
    </tr>
</table>
</body>
</html>





