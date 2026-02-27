<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<title>亲！智能网关有新版本</title>
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>"  media="all" rel="stylesheet" />
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css' rel="stylesheet">
<script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
<script language="JavaScript" type="text/javascript">

function LoadFrame() 
{

}

function UpgradeSubmit(upgradetype, submitUrl)
{
	setdisableall();
	$.ajax({
			type : "POST",
			async : false,
			cache : false,
			url :  upgradetype + "?&RequestFile=" + submitUrl,
            data: getDataWithToken(),
			success : function(data) { 
			}
		});	

    window.location = "/" + submitUrl;
}
function setdisableall()
{	
	document.getElementById('btnApply1').disabled = true;
	document.getElementById('btnApply2').disabled = true;
	document.getElementById('btnApply3').disabled = true;
}

function submitbtn1()
{	
    UpgradeSubmit("agreePopUpgrade.cgi", "updateNote.asp");	
}

function submitbtn2()
{
	UpgradeSubmit("refusePopUpgrade.cgi", "updateNote.asp");	
}
function submitbtn3()
{
	UpgradeSubmit("remindPopUpgrade.cgi", "updateNote.asp");
}

</script>
</head>
<body onLoad="LoadFrame();">
	
	<div >
	<input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
	<button id="btnApply1" name="btnApply1" type="button" class="submit" onClick="submitbtn1();">升级</script></button> 
	<button name="btnApply2" id="btnApply2" class="submit" type="button" onClick="submitbtn2();">不升级</button> 
	<button name="btnApply3" id="btnApply3" class="submit" type="button" onClick="submitbtn3();">暂不升级</button> 
	</div>
		


</body>
</html>
