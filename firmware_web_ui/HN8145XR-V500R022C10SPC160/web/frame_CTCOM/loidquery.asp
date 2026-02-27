<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<title>LOID</title>
<script language="JavaScript" type="text/javascript">


function analysisResult(ResResult)
{
	var RegPercent = ResResult.split(";")[0];
	var RegStatusStr = ResResult.split(";")[1];
	var RegStatus = RegStatusStr.split(",")[1];
	
    if (RegStatus == "REGISTER_OK")
	{	
		document.getElementById("ftitle").innerHTML = "注册成功";
	}
	else if (RegStatus == "REGISTER_OLT")
	{
		document.getElementById("ftitle").innerHTML = "注册中";
	}
	else if (RegStatus == "REGISTER_OK_DOWN_BUSINESS")
	{
		document.getElementById("ftitle").innerHTML = "注册中";
	}
	else if (RegStatus == "REGISTER_DEFAULT")
	{
		document.getElementById("ftitle").innerHTML = "未注册";
	}
	else if (RegStatus == "REGISTER_REGISTED")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	else if (RegStatus == "REGISTER_TIMEOUT")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	else if (RegStatus == "REGISTER_NOMATCH_NOLIMITED" || RegStatus == "REGISTER_NOACCOUNT_NOLIMITED" || RegStatus == "REGISTER_NOUSER_NOLIMITED")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	else if (RegStatus == "REGISTER_NOMATCH_LIMITED" || RegStatus == "REGISTER_NOACCOUNT_LIMITED" || RegStatus == "REGISTER_NOUSER_LIMITED")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	else if (RegStatus == "REGISTER_OLT_FAIL")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	else if (RegStatus == "REGISTER_POK")
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}	
	else
	{
		document.getElementById("ftitle").innerHTML = "注册失败";
	}
	
	return;
}

function getResult()   
{
    var RegResult;
	$.ajax({
		type : "POST",
		async : false,
		cache : false,
		timeout : 4000,
		url : "asp/getregret.asp",
		success : function(data) {
				RegResult=data;
		}
	});
	
	analysisResult(RegResult);
}  


function LoadFrame()
{ 
	getResult();
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





