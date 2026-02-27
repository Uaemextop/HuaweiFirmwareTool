<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
<style type='text/css'>

</style>
</head>
<script>

function getWifiBackupInfo(domain, Enable, Ssid2gInst, Ssid5gInst)
{
    this.domain = domain;
    this.backupenable = Enable;
    this.ssid_index_2g = Ssid2gInst;
    this.ssid_index_5g = Ssid5gInst;
}
var wifiBackupInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_WiFiBackup,Enable|Ssid2gInst|Ssid5gInst,getWifiBackupInfo);%>; 

var frame = '<%HW_WEB_GetSPEC(SSMP_SPEC_WEB_FRAME.STRING);%>';

var ssidname_2G = "";
var ssidname_5G = "";
function stWlan(domain, Name, SSID)
{
    this.domain = domain;
    this.Name = Name;
    this.SSID = SSID;
}

var WlanList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}, Name|SSID, stWlan);%>;
var WlanListNum = WlanList.length -1;
var domain_2g ="InternetGatewayDevice.LANDevice.1.WLANConfiguration." + wifiBackupInfo[0].ssid_index_2g;
var domain_5g ="InternetGatewayDevice.LANDevice.1.WLANConfiguration." + wifiBackupInfo[0].ssid_index_5g;
for (var i = 0; i < WlanListNum; i++) {
    if (WlanList[i].domain == domain_2g) {
        ssidname_2G = WlanList[i].SSID;
    } 
    if (WlanList[i].domain == domain_5g) {
        ssidname_5G = WlanList[i].SSID;
    }
}

function LoadFrame(){
    $("#backupwifi_2G").attr("disabled", true);
    $("#backupwifi_5G").attr("disabled", true);
    setDisplay('backupwifi_2GRow', 0);
    setDisplay('backupwifi_5GRow', 0);
    document.getElementsByClassName("divsummaryicon")[0].style.display = "none";
    document.getElementById('WiFi5setting_content').style.paddingLeft = "10px";
    if (frame == "frame_CMCC" || frame == "frame_CTCOM") {
        setDisplay('head_title', 1);
    }
    changeButton();
}
function changeButton(){
    if (wifiBackupInfo[0].backupenable == 1) {
        $("#enableBackup").attr("checked", true);
            setDisplay('backupwifi_2GRow', 1);
            setDisplay('backupwifi_5GRow', 1);
            setText('backupwifi_2G', ssidname_2G);
            setText('backupwifi_5G', ssidname_5G);
    } else {
        $("#enableBackup").attr("checked", false);
    }
}

function enableClickWiFi5() {
    var enableWIFI = getCheckVal('enableBackup');
    if(enableWIFI != 1) {
        setDisplay('backupwifi_2GRow', 0);
        setDisplay('backupwifi_5GRow', 0);
        wifiBackupInfo[0].backupenable = 0;
    } else {
        setDisplay('backupwifi_2GRow', 1);
        setDisplay('backupwifi_5GRow', 1);
        setText('backupwifi_2G', ssidname_2G);
        setText('backupwifi_5G', ssidname_5G);
        wifiBackupInfo[0].backupenable = 1;
    }

    paraSubmit(wifiBackupInfo[0].backupenable);
}

function paraSubmit(backupenable) {
    var url = 'set.cgi?x=InternetGatewayDevice.X_HW_WiFiBackup';
    var Form = new webSubmitForm();
    var RequestFile = 'html/amp/wlanbasic/backupWiFi5NetworkSetting.asp';
    url = url + '&RequestFile=' + RequestFile;
    Form.addParameter('x.Enable', backupenable);
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction(url);
    Form.submit();
}

</script>

<body onLoad="LoadFrame();" class="mainbody">
    <table width="100%" border="0" cellspacing="0" cellpadding="0" id="head_title" style="display: none;">
        <tr>
            <td class="table_head" width="100%">备份WiFi5网络设置</td> 
        </tr>
    </table>
    <script>
        var backupwifi_header = cfg_backupwifi_language['backupwifi_header'];
        var backupWifiSummaryArray = new Array(new stSummaryInfo("img","", ""),
                                               new stSummaryInfo("text", GetDescFormArrayById(cfg_backupwifi_language, "backupwifi_title") + GetDescFormArrayById(cfg_backupwifi_language, "backupwifi_title_description") + "<br>"),
                                               null);
    
        HWCreatePageHeadInfo("WiFi5setting", backupwifi_header, backupWifiSummaryArray, true);
    </script>
    <div class="title_spread"></div>
    <form id="backupWIFI" name="FreeArpForm" style="display:block;">
        <table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
            <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
            <li id="enableBackup" RealType="CheckBox" DescRef="backupwifi_enable" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.enable" InitValue="Empty" InitValue="0"   ClickFuncApp="onclick=enableClickWiFi5"/>
            <li id="backupwifi_2G" RealType="TextBox" DescRef="backupwifi_2G" RemarkRef="backupwifi_password" ErrorMsgRef="Empty" Require="TRUE" BindField="x.backupwifi_2G"  MaxLength="15" InitValue="Empty"  />
            <li id="backupwifi_5G" RealType="TextBox" DescRef="backupwifi_5G" RemarkRef="backupwifi_password" ErrorMsgRef="222" Require="TRUE" BindField="x.backupwifi_5G"  MaxLength="15"  InitValue="Empty"  />
        </table>
        <script>
            var TableClass = new stTableClass("width_per30", "width_per70", "ltr");
            var FreeArpConfigFormList = new Array();
            FreeArpConfigFormList = HWGetLiIdListByForm("FreeArpForm", null);
            HWParsePageControlByID("FreeArpForm", TableClass, cfg_backupwifi_language, null);
        </script>
        <div class="func_spread"></div>
    </form>
</body>
</html>
