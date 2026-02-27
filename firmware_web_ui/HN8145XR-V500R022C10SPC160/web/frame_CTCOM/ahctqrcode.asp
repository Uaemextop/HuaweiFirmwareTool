<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>QRcode</title>
<script type="text/javascript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(md5.js);%>"></script>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(ahcode.js);%>"></script>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(crypto-js.js);%>"></script>
<style type="text/css">
	body{
		background-color: #009797;
		width: 70%;
		margin: 0 auto;
	}
	#ct-logo{
		width: 62px;
		display: inline-block;
		vertical-align: middle;
	}
	.qrcode-head-wrapper .ct-title{
		display: inline-block;
		vertical-align: middle;
		font-size: 50px;
		font-weight: bolder;
		color: white;
	}
	
	.qrcode-center-wrapper{
		text-align: center;
	}
	.quick-repair-text1{
		font-size: x-large;
		color: white;
		opacity: .7;
		text-align: left;
	}
	.quick-repair-text2{
		font-size: 48px;
		color: white;
		text-align: left;
	}
	.text2-span{
		color: yellow;
	}
	
	.qucikdiv{
		text-align: center;
	}
	#quickRepairBtn{
		font-size: 48px;
		font-weight: bolder;
		color: white;
		border: 0px;
		background-color: #00B14F;
		padding: 0px 35px 10px 35px;
	}
	
	#qrcode{
		position:absolute;
		left:45%
	}
	.logoimg{

		z-index: 3;
		left: 50%;
		top: 334%;	  
	}
</style>
</head>
<body>
	<div class="qrcode-head-wrapper" >
		<img id="ct-logo" src="/images/ctlogo.jpg"></img>
		<h3 class="ct-title" >中国电信</h3>
	</div>
	<div class="qrcode-center-wrapper">
		<p class="quick-repair-text1" >尊敬的电信用户，系统检测到您的宽带网络中断，请按以下提示快速排障。</p>
		<p class="quick-repair-text2" >1、如果您现在看的是手机屏幕，请<span class="text2-span">断开WIFI连接</span>，使用移动数据上网，点击下方按钮</p>
		<div class="qucikdiv" >
			<input id="quickRepairBtn" type="button" value="快速报障" >
		</div>
		<p class="quick-repair-text2" >2、如果您现在看的是电脑屏幕，请拿出您的手机，<span class="text2-span">断开WIFI连接</span>，使用移动数据上网，扫描下方二维码</p>
		<div id="qrcode" style="margin-bottom:3em"></div>
	</div>
</body>
<script>
function getNowFormatDate() {
	var date = new Date();
	var year = date.getFullYear();
	var month = date.getMonth() + 1;
	var strDate = date.getDate();
	var hours = date.getHours();
	if (month >= 1 && month <= 9) {
		month = "0" + month;
	}
	if (strDate >= 0 && strDate <= 9) {
		strDate = "0" + strDate;
	}
	if (hours >= 0 && hours <= 9) {
		hours = "0" + hours;
	}	
	var currentdate = year + month + strDate + hours;
	
	return currentdate;
}
function stAuthGetLoidPwd(domain,UserName)
{
    this.domain   = domain;
    this.UserName     = UserName;
}

var AuthInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, UserName, stAuthGetLoidPwd);%>;

var PPPWanList = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaArrayPPPWAN, InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i},Username,stAuthGetLoidPwd);%>; 
var account = "";
for (var i = 0;i<PPPWanList.length-1;i++)
{
	if (PPPWanList[i].UserName != "")
	{
		account = PPPWanList[i].UserName;
		break;
	}

	
}
var qrCodeUrl = '<%HW_WEB_GetSPEC(SPEC_AHCT_QRCODE_URL.STRING);%>';
var options = {
  text: qrCodeUrl,
  width: 150,
  height: 150,
  colorDark : "#000000",
  colorLight : "#ffffff",
  correctLevel : wabQR.CorrectLevel.Q,
  logoSrc: '/images/ctlogo.jpg',
  logoRate: 0.3
}
var keyHex = CryptoJS.enc.Utf8.parse('zhoujielun@lx100$#1365#$'); 
var enAccount=CryptoJS.TripleDES.encrypt(account, keyHex, { iv:CryptoJS.enc.Utf8.parse('01234567'), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}); 
var enLoid=CryptoJS.TripleDES.encrypt(AuthInfo[0].UserName, keyHex, { iv:CryptoJS.enc.Utf8.parse('01234567'), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7}); 
options.text += enAccount + "&loid=" + enLoid +"&appId=998&token=" + hex_md5(account+"FTTH"+ getNowFormatDate());

new wabQR(document.getElementById("qrcode"), options);




$(".qucikdiv").click(function(){
window.location.href=options.text;
});
</script>
</html>