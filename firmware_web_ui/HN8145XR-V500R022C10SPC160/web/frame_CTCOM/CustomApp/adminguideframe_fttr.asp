<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<meta http-equiv="Pragma" content="no-cache" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(frame.css);%>"  media="all" rel="stylesheet" />
<link href="/Cuscss/<%HW_WEB_GetCusSource(guide_fttr.css);%>" rel="stylesheet" type="text/css" />
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>" type="text/javascript" ></script>
<script language="JavaScript" src="/resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script src="/resource/<%HW_WEB_Resource(ssmpdes.js);%>" language="JavaScript"></script>
<title></title>
</head>
<script>
var wifiPara = new Object();
var curLanguage = '<%HW_WEB_GetCurrentLanguage();%>';
var ontAuthPage = '';
var wlanConfigPage = '';
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
var ProductType = '<%HW_WEB_GetProductType();%>';
var mngttype = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var logo_singtel = '<%HW_WEB_GetFeatureSupport(FT_FEATURE_SINGTEL);%>';
var smartlanfeature = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
var IsSupportpon2lan = '<%HW_WEB_GetFeatureSupport(FT_PON_UPPORT_CONFIG);%>'; 
var CurrentUpMode = '<%HW_WEB_GetUpMode();%>';
var IsSmartDev = "<%HW_WEB_GetFeatureSupport(HW_OSGI_FT_BUNDLEINFOWEB);%>";
var curChangeMode = '<%HW_WEB_GetAPChangeModeValue();%>'; 
var GhnDevFlag = '<%HW_WEB_GetFeatureSupport(FT_SSMP_GHNAP_MNGT);%>';
var DAUMLOGO = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.UserInterface.X_Web.X_WebLogo);%>';
var DAUMFEATURE = "<%HW_WEB_GetFeatureSupport(FT_PRODUCT_DAUM);%>";
var TypeWord_com = '<%HW_WEB_GetTypeWord();%>';
var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var curUserType = '<%HW_WEB_GetUserType();%>';
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';
var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>';
var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
var OriUpPortMode ='<%HW_WEB_GetOriUpPortMode();%>';
var ponUpport = '<%HW_WEB_GetFeatureSupport(FT_PON_UPPORT_CONFIG);%>';

var timer = [];
wifiPara.wifiFlag = 0;
document.title = ProductName;
var enableIotSsid = 0;
var showIotSsidFlag = 0;
var showNfcFlag = 0;

if (DAUMFEATURE == 1) {
    document.write('<link rel="shortcut icon" href="/images/hwlogo.ico" />');
    document.write('<link rel="Bookmark" href="/images/hwlogo.ico" />');
}


function setOntAuthPage()
{
    ontAuthPage = '../../html/amp/ontauth/passwordcommon.asp';
    
    if(curLanguage == "chinese") {
        ontAuthPage = '../../html/amp/ontauth/password.asp';
    }
    getElById('spanguide').innerHTML = CfgguideLgeDes['s2013'];
    getElById('frameContent').src = ontAuthPage;
}

function setWlanConfigPage()
{
    wlanConfigPage = '/html/amp/wlanbasic/guidewificfg.asp';
    getElById('spanguide').innerHTML = CfgguideLgeDes['s2017'];
    getElById('frameContent').src = wlanConfigPage;
}

var wifiForm = null;
function loadframe()
{
    if (curUserType == '0') {
        wifiPara.id = "guidewancfg";
        wifiPara.name = "/html/bbsp/wan/wan.asp?cfgguide=1";
        setWlanConfigPage();
        wifiForm = new webSubmitForm();
    }
    adjustParentHeight();
}


function onchangestep(val)
{
    var id = val.id;
    $("#framepageContent").css("height", "300px");
    if(('1' == smartlanfeature || (3 == CurrentUpMode && 1 == IsSupportpon2lan))&& val.name.indexOf("guidebssinfo.asp") != -1){
        val.name = "/html/ssmp/cfgguide/userguidecfgdone.asp";
    }

    switch (id) {
        case "guidewificfg":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2017'];
            break;
        case "guidewancfg":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2014'];
            break;
        case "guideontauth":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2013'];
            break;
        case "guidelanconfig":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2048'];
            break;
        case "guidesyscfg":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2018'];
            break;
        case "bbsp_skip":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2015'];
            break;
        case "guidecfgdone":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2015'];
            break;
        case "accountguideskip":
            getElById('spanguide').innerHTML = CfgguideLgeDes['s2048'];
            break;
        default:
            break;
    }
    setDisplay("framepageContent", 0);
    document.getElementById("frameContent").src = val.name;
    adjustParentHeight();
}

function adjustParentHeight()
{
    adjustFrameHeight("framepageContent", "frameContent", 600);
    adjustFrameHeight("framepage", "frameContent", 500);
}
</script>
<body onload="loadframe();">
    <div id="guideframebody">

        
        <div id="guideinternettop" class="guideinternettopstyle" align="center">
			<div id="internet_title">
                <p id="internet_title_text" class="internet_title_text" bindText="s2045"></p>
			</div>
			<div class="guide_internet_outer" align="center"><div class="guide_internet"></div></div>
        </div>
        <div id="content_info">
            <table width="100%" height="30" border="0" cellspacing="0"
            cellpadding="0">
            <tr>
            <td class="info_network_name">
            <script language="JavaScript" type="text/javascript">
            if ('SHXCNCATV' == CfgMode.toUpperCase()) {
                document.write('系统版本:'+ softversion);
            } else if (IsRhGateway == '1') {
                if (IsLAN == '1') {
                    document.write('以太网上行融合智能终端');
                } else {
                    if (E8CRONGHEFlag == 1) {
                        if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
                            document.write('GPON宽带融合终端');
                        } else if (ontPonMode.toUpperCase() == '10G-GPON') {
                            document.write('XGPON宽带融合终端');
                        } else {
                            document.write('EPON宽带融合终端'); 
                        }
                    } else {
                        if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
                            document.write('GPON上行融合智能终端');
                        } else if (ontPonMode.toUpperCase() == '10G-GPON') {
                            document.write('XGPON上行融合智能终端');
                        } else {
                            document.write('EPON上行融合智能终端'); 
                        } 
                    }
                }
                
            } else if (IsCTRG == 1) {
                if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
                    document.write('天翼网关-GPON');
                } else if (ontPonMode.toUpperCase() == '10G-GPON') {
                    document.write('天翼网关-XGPON');
                } else {
                    document.write('天翼网关-EPON'); 
                }			        
            } else {
                if (IsLAN == '1') {
                    document.write('以太网上行智能终端');
                } else if ((ontPonMode.toUpperCase() == 'GPON') || (ponUpport == 1 && OriUpPortMode == 1)) {
                    if (CfgMode.toUpperCase() == 'SHCTA8C' || CfgMode.toUpperCase() == 'A8C') {
                        document.write('网关名称:GPON上行A8-C');
                    } else {
                        document.write('网关名称:GPON上行e8-C');
                    }
                } else if (ontPonMode.toUpperCase() == '10G-GPON') {
                    if (CfgMode.toUpperCase() == 'SHCTA8C' || CfgMode.toUpperCase() == 'A8C') {
                        document.write('网关名称:XGPON上行A8-C');
                    } else {
                        document.write('网关名称:XGPON上行e8-C');
                    }
                } else {
                if (CfgMode.toUpperCase() == 'SHCTA8C' || CfgMode.toUpperCase() == 'A8C') {
                    document.write('网关名称:EPON上行A8-C');
                } else {
                    document.write('网关名称:EPON上行e8-C');
                }
                }
            }
            </script>
            </td>
            <td class="info_type">型号: <span id="productTypeName" style="color:#FFFFFF;"></span></td>
            <script>
                $("#productTypeName").text(ProductName);;
            </script>
            </tr>
            </table>
            </div>
    </div>

    <div id="framepageContent">
        <div><span id="spanguide" class="" BindText="s2013"></span></div>
        <div id="framepage">
            <iframe id="frameContent" frameborder="0" width="100%" height="100%" marginheight="0" marginwidth="0" src=""></iframe>
        </div>
    </div>
    <div style="display:none;">
        <iframe frameborder="0" width="100%" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="/refresh.asp"></iframe>
    </div>
    <script>
        if (parseInt(mngttype, 10) != 1)
        {						
            if(parseInt(logo_singtel, 10) == 1)
            {
                if(TypeWord_com == "COMMON")
                {
                    $("#brandlog_singtel").css("background-image", "url()");
                }
                $("#brandlog_singtel").css("display", "block");
            } else
            {
                if ((DAUMFEATURE == 1) && (DAUMLOGO == 1))
                {
                    $("#brandlog_daum_iprimus").css("display", "block");
                }
                else if ((DAUMFEATURE == 1) && (DAUMLOGO == 2))
                {
                    $("#brandlog_daum_dodo").css("display", "block");
                }
                else if ((DAUMFEATURE == 1) && (DAUMLOGO == 3))
                {
                    $("#brandlog_daum_commander").css("display", "block");
                } else {
                    $("#brandlog").css("display", "block");
                }
            }
        }
        ParseBindTextByTagName(CfgguideLgeDes, "p", 1);
        ParseBindTextByTagName(CfgguideLgeDes, "span", 1);
    </script>
</body>
</html>
