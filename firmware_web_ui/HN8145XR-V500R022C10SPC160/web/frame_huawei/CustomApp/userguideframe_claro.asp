<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<meta http-equiv="Pragma" content="no-cache" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(frame.css);%>" media="all" rel="stylesheet" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(guide.css);%>" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script type="text/javascript" src="/resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script type="text/javascript" src="/resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src='../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<title></title>
</head>
<script>
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var ProductType = '<%HW_WEB_GetProductType();%>';
var UpgradeFlag = 0;
var selectrepwlan = "";
var wifiForm = null;
var mngttype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var logo_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var TypeWord_com = '<%HW_WEB_GetTypeWord();%>';
document.title = ProductName;
var smartlanfeature = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var DirectGuideFlag = '<%HW_WEB_GetFeatureSupport(FT_CHANGE_GUIDE_LEVEL);%>';
var notSupportPON = '<%HW_WEB_GetFeatureSupport(FT_WEB_DELETE_PON);%>';

var bsdPolicy='<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WiFi.X_HW_GlobalConfig.BandSteeringPolicy);%>';
var timer = [];
var UserName = '<%HW_WEB_GetCurUserName();%>';
var ssid1Name = "";
var ssid5Name = "";
var ssid1Code = "";
var ssid5Code = "";

function loadframe()
{
    $("#guideframebody").css("background-color", "rgb(218,41,28)");
    $("#guideframebody").css("background-image", "url()");

    timer.push(setInterval("adjustParentHeight();", 200));
    wifiForm = new webSubmitForm();
    document.getElementById("frameContent").src = "/html/ssmp/accoutcfg/guideaccountcfg_claro.asp";
    return;
}

function onchangestep(val)
{
    var id = val.id;

    if (id == "guidewifiunique") {
        bsdPolicy = 1;
    } else if (id == "guidewifiboth") {
        bsdPolicy = 0;
    } else if (id == "guideconfirmcfg") {
        window.location = "/CustomApp/guideconfirm.asp";
    }

    document.getElementById("frameContent").src = val.name;
    timer.push(setInterval("adjustParentHeight();", 200));
}

function adjustParentHeight()
{
    adjustFrameHeight("framepageContent", "frameContent", 90);
}
</script>
<body onload="loadframe();">
    <div id="guideframebody">
        <div id="guidejump" class="guide" onclick="gotoIndex()">
            <script>document.write(CfgguideLgeDes["s4011"])</script>
        </div>
        <div id="guideframebg" style="height: 300px;">
            <div id="brandlog_claro"></div>
            <script>
                document.write('<div id="ProductName">' + ProductName + '</div>');
                document.write('<div id="guideframehead"><span BindText="s2012_claro"></span></div>');
            </script>
        </div>
    </div>
    <div id="greenline"></div>
    <div id="framepageContent">
        <iframe id="frameContent" width="100%" frameborder="0" height="100%" marginheight="0" marginwidth="0"
            src=""></iframe>
    </div>
    <div style="display:none;">
        <iframe frameborder="0" width="100%" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="/refresh.asp"></iframe>
    </div>
    <script>
        ParseBindTextByTagName(CfgguideLgeDes, "span", 1);
    </script>
</body>

</html>
