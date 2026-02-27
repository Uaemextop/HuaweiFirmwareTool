<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<meta http-equiv=Content-Type content="text/html; charset=UTF-8">
<style>
    #tophead {
        position: absolute;
        top: 56px;
        left: 705px;
    }

    #note {
        margin-top: 50px;
        margin-left: 50px;
        width: 387px;
        text-indent: 40px;
    }

    #qrcodeId {
        position: relative;
        margin-top: -218px;
        margin-left: 490px;
    }
</style>
    <script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(ahcode.js);%>"></script>
<script>
function GetTimeStamp()
{
    var currentDate = new Date();
    var timestamp = "timestamp=" + currentDate.getFullYear().toString();
    var month = (currentDate.getMonth() + 1).toString();
    var date = currentDate.getDate().toString();
    var hours = currentDate.getHours().toString();
    var minutes = currentDate.getMinutes().toString();
    var seconds = currentDate.getSeconds().toString();
    var timeArray = [month, date, hours, minutes, seconds];

    for (var i = 0; i < timeArray.length; i++) {
        if (timeArray[i].length < 2) {
            timestamp += '0';
        }
        timestamp += timeArray[i];
    }

    return timestamp;
}

var timestamp = GetTimeStamp();
var serverURL = '<%HW_WEB_GetSPEC(SSMP_SPEC_QRCODE_URL.STRING);%>';
var content = '<%WEB_GetQRCode();%>';
var completeURL = "";
if ((serverURL != "") && (content != "")) {
    completeURL = serverURL + timestamp + '&' + content;
}

function ewcodeUrl() {
    window.location.href = completeURL;
}

function initqrcode() {
    var options = {
        text: "",
        width: 230,
        height: 230,
        id: "qrcodeId",
        className: "qrcodeclass",
        colorDark : "#000000",
        colorLight : "#ffffff",
        correctLevel : wabQR.CorrectLevel.Q,
        logoSrc: '/images/tjcu_mini.jpg',
        logoRate: 0.33
    }

    options.text = completeURL;
    var obj = document.getElementById("qrcodeImage");
    new wabQR(obj, options);

    if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
        var proportion = window.innerWidth / 440;

        document.getElementById("qrcodeTable").style = "background-color: #C6D9F1;width: 100%;height: 100%;";
        document.getElementById("tophead").style = "left: 11%;top: 2.8%;margin-top: 2%;font-size: " + 19 * proportion + "px;";
        document.getElementById("logImage").style = "width: 25%;margin: 2% 0 0 73%;";
        document.getElementById("note").style = "color: #c00000;width: 90%;font-size: " + 19 * proportion + "px;margin: 8% 0 0 5%;text-indent:12%;"
        document.getElementById("bottomTitle").style = "font-size: " + 16 * proportion + "px; margin: 61% 2% 0 0;padding-bottom: 5%;text-align: center;";
        document.getElementById("qrcodeId").style = "width: 50%;margin: -65% 25% 0;";
        document.getElementById("foot").style = "font-size: " + 16 * proportion + "px; margin: 51% 2% 0;padding-bottom: 5%;";
    }
}
</script>
</head>
<body onload="initqrcode();">
    <div id="qrcodeTable"  style="margin-left: 453px;width: 748px;height: 400px;background-color: #C6D9F1;" >
        <div>
            <div id="tophead" class="topTitle" style="font-size: 24px;">天津联通智能排障二维码</div>
            <img id="logImage" src="/images/tjculogo.gif" alt="" style="width: 17%;margin-top: 10px;margin-left: 580px;">
        </div>
        <div id="note" style="font-size: 24px;color: #c00000;">尊敬的用户，很抱歉，天津联通检测到您的宽带可能发生了故障，请您关闭手机WIFI，扫描以下二维码进行报修故障。</div>
        <div id="bottomTitle" class="" style="font-size: 20px;margin-left: 50px;margin-top: 66px">注：如果无法扫描二维码，请拨打10010。</div>
        <div id="qrcodeImage" onclick="ewcodeUrl()"></div>
        <div id="foot" class="" style="font-size: 20px;margin-left: 50px;margin-top: 108px"></div>
    </div>
</body>
</html>
