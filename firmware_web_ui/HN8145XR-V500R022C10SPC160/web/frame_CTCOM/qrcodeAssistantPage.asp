<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<meta http-equiv=Content-Type content="text/html; charset=UTF-8">
<style>
	#tophead {
		position: absolute;
		top: 56px;
		left: 750px;
	}

	#ahcodeId {
		margin-top: 50px;
		margin-left: 10px;
	}

	#bottomTitleId {
		position: relative;
		margin-top: -128px;
		margin-left: 233px;
		width: 500px;
	}

</style>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(ahcode.js);%>"></script>
<script>
var serverURL = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Ewcode.ServerURL);%>';
var encryptionAccount = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Ewcode.Encryption);%>';
var completeURL = serverURL + encryptionAccount;
function ewcodeUrl() {
	window.location.href = completeURL;
}

function initAhcode() {
	var options = {
		text: "",
		width: 150,
		height: 150,
		id: "ahcodeId",
		className: "ahcode",
		colorDark : "#000000",
		colorLight : "#ffffff",
		correctLevel : wabQR.CorrectLevel.Q,
        logoSrc: '',
		logoRate: 0.3
	}

	options.text = completeURL;
	var obj = document.getElementById("ahcodeImage");
	new wabQR(obj, options);

	if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
		proportion = window.innerWidth / 440;
		document.getElementById("ahcodeTable").style = "width: 100%;background-color: #2b8fd2;height: 100%";
		document.getElementById("logImage").style = "width: 20%;margin: 2% 0 0 2%";
		document.getElementById("tophead").style = "left: 25%;margin-top: 2%;font-size: " + 16 * proportion + "px;color: #f9fcfd;";
		document.getElementById("note").style = "font-size: " + 17 * proportion + "px;margin: 5% 0 0 2%;color: #ffff00;"
		document.getElementById("ahcodeId").style = "width: 35%;margin: 15% 32% 0;";
		document.getElementById("bottomTitleId").style = "font-size: " + 16 * proportion + "px; color: rgb(249, 252, 253); width: 96%; margin: 15% 2% 0;padding-bottom: 5%;";
	}
}
</script>
</head>
<body onload="initAhcode();">
	<div id="ahcodeTable"  style="margin-left: 505px;width: 808px;background-color: #2b8fd2;height: 500px;" >
		<div>
			<img id="logImage" src="/images/ctlogo.jpg" alt="" style="width: 140px;margin-top: 10px;margin-left: 10px;">
			<div id="tophead" class="topTitle" style="font-size: 22px;color: #f9fcfd;">山东电信宽带二维码自助排障助手</div>
		</div>

		<div id="note" style="font-size: 22px;margin-top: 20px;color: #ffff00;margin-left: 10px;">很抱歉，检测到您的家庭网络出现连接问题，请按照下面的方法步骤操作，我们将及时为您修复。</div>
		<div id="ahcodeImage" onclick="ewcodeUrl()"></div>
		<div id="bottomTitleId" class="bottomTitle" style="font-size: 22px;color: #f9fcfd;">请先关闭手机WIFI，再通过手机扫描二维码或点击二维码进行诊断报障。<br/>如无法扫描二维码，请拨打10000报障，感谢您的配合。</div>
	</div>
</body>
</html>
