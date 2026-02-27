<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html, cfg_wlan_Nfc, cfg_wlancfgother_language);%>"></script>
<title>NFC</title>
<script language="JavaScript" type="text/javascript">
var nfcStats = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WiFi.X_HW_NFC, Enable|Duration|DurationTime, NfcStatsGet);%>;
var systemdsttime = '<%HW_WEB_GetSystemTime();%>';
var showTime;
var durationTime = nfcStats[0].Duration * 60 - nfcStats[0].DurationTime;

function stWlan(domain,name,Enable,BeaconType,WPAAuthenticationMode,IEEE11iAuthenticationMode,X_HW_WPAand11iAuthenticationMode,WMMEnable)
{
    this.domain = domain;
    this.name = name;
    this.Enable = Enable;
    this.BeaconType = BeaconType;
    this.WPAAuthenticationMode = WPAAuthenticationMode;
    this.IEEE11iAuthenticationMode = IEEE11iAuthenticationMode;
    this.X_HW_WPAand11iAuthenticationMode = X_HW_WPAand11iAuthenticationMode;

}

var allWlanInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|Enable|BeaconType|WPAAuthenticationMode|IEEE11iAuthenticationMode|X_HW_WPAand11iAuthenticationMode,stWlan);%>;
var isEnterprise = 0;
if ((allWlanInfo[0].BeaconType == 'WPA') && (allWlanInfo[0].WPAAuthenticationMode == 'EAPAuthentication')) {
    isEnterprise = 1;
} else if (((allWlanInfo[0].BeaconType == 'WPA2') || (allWlanInfo[0].BeaconType == '11i')) && (allWlanInfo[0].IEEE11iAuthenticationMode == 'EAPAuthentication')) {
    isEnterprise = 1;
} else if (((allWlanInfo[0].BeaconType == 'WPA/WPA2') || (allWlanInfo[0].BeaconType == 'WPAand11i')) && (allWlanInfo[0].X_HW_WPAand11iAuthenticationMode == 'EAPAuthentication')) {
    isEnterprise = 1;
}

function NfcStatsGet(domain, Enable, Duration, DurationTime) {
    this.domain = domain;
    this.Enable = Enable;
    this.Duration = Duration;
    this.DurationTime = DurationTime;
}

function ChangeNum(num) {
    if (num < 10) {
        return '0' + num;
    }
    return num;
}

function ChangeShowTime() {
    if ((durationTime == 0) || (nfcStats[0].Enable == 0)) {
        clearInterval(showTime);
        document.getElementById("nfcLastTime").innerHTML = "00:00:00";
        return;
    }

    var hour = parseInt(durationTime / 3600);
    var min = parseInt((durationTime%3600) / 60);
    var sec = parseInt((durationTime%3600)%60);

    document.getElementById("nfcLastTime").innerHTML = ChangeNum(hour) + ":" + ChangeNum(min) + ":" + ChangeNum(sec);
    durationTime = durationTime - 1;
}

function LoadFrame() {
    setCheck('nfcEnable', nfcStats[0].Enable);
    setText('nfcTime', nfcStats[0].Duration / 60);
    setDisable("nfcTime", 1 - nfcStats[0].Enable);
    if ((nfcStats[0].Enable == 1) && (nfcStats[0].Duration == 0)) {
        setDisplay("nfcLastRow", 0);
        return;
    }
    ChangeShowTime();
    showTime = setInterval('ChangeShowTime()', 1000);
}

function CancelConfig() {
    location.reload();
}

function CheckParaInfo() {
    var time = getValue('nfcTime');
    if ((time < 0) || (time > 24)) {
        return false;
    }
    return true;
}

function EnableChange() {
    setDisable('nfcTime', 1 - getCheckVal("nfcEnable"));
}

function NfcSubmit() {
    if (isEnterprise == 1) {
        alert(cfg_wlan_Nfc['amp_wlan_nfcalertEnt']);
        return;
    }
    var Form = new webSubmitForm();
    var url = "set.cgi?";
    var enable = getCheckVal('nfcEnable');
    var time = getValue('nfcTime');
    
    if (CheckParaInfo() == false) {
        alert(cfg_wlan_Nfc['amp_wlan_nfcalert']);
        return;
    }

    Form.addParameter('y.Enable', enable);
    Form.addParameter('y.Duration', time * 60);
    url += 'y=InternetGatewayDevice.LANDevice.1.WiFi.X_HW_NFC' + '&';

    url += 'RequestFile=html/amp/wlaninfo/nfcSetting.asp';
    Form.setAction(url);
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}
</script>
</head>

<body class="mainbody" onLoad="LoadFrame();">
<script language="JavaScript" type="text/javascript">
HWCreatePageHeadInfo("NFC", cfg_wlan_Nfc['amp_wlan_nfctitle'], cfg_wlan_Nfc['amp_wlan_nfcnotes'], false);
</script>

<div class="title_spread"></div>

<div class="func_title">
    <script>document.write(cfg_wlan_Nfc['amp_wlan_nfcheadtitle']);</script>
</div>

<table id="TableNfcForm" width="100%" cellpadding="1" cellspacing="1" class="tabal_noborder_bg" style="">
    <tbody>
        <tr border="1" id="nfcRow" style="">
            <td class="table_title width_per20" id="nfcColleft">
                <script>document.write(cfg_wlan_Nfc['amp_wlan_nfcbutton']);</script>
            </td>
            <td id="nfcCol" class="table_right width_per30">
                <input id="nfcEnable" type="checkbox" class="CheckBox" title="" onclick="EnableChange();">
                <font color="red" id="nfc"></font>
            </td>
            <td class="width_per50">
                <span class="gray" id="nfcspan">
                    <script>document.write(cfg_wlan_Nfc['amp_wlan_nfcnotes1']);</script>
                </span>
            </td>
        </tr>
        <tr border="1" id="nfcTimeRow">
            <td class="table_title width_per20" id="nfcTimeColleft">
                <script>document.write(cfg_wlan_Nfc['amp_wlan_nfctime']);</script>
            </td>
            <td id="nfcTimeCol" class="table_right width_per30">
                <input id="nfcTime" type="text" class="TextBox" maxLength="2">
                <font color="red" id="nfcTimeRequire"></font>
            </td>
            <td class="width_per50">
                <span class="gray" id="nfcTimespan">
                    <script>document.write(cfg_wlan_Nfc['amp_wlan_nfctimedefault']);</script>
                </span>
            </td>
        </tr>
        <tr border="1" id="nfcLastRow">
            <td class="table_title width_per20" id="nfcLastTimeColleft">
                <script>document.write(cfg_wlan_Nfc['amp_wlan_nfclasttime']);</script>
            </td>
            <td id="nfcLastTimeCol" class="table_right width_per30">
                <span id="nfcLastTime"></span>
            </td>
            <td class="width_per50">
                <span class="gray" id="nfcLastTimespan"></span>
            </td>
        </tr>
    </tbody>
</table>

<table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
    <tbody>
        <tr>
            <td class="table_submit width_per25"></td>
            <td class="table_submit"> 
                <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                <button id="applyButton" name="applyButton" type="button" class="ApplyButtoncss buttonwidth_100px" onclick="NfcSubmit();"><script>document.write(cfg_wlancfgother_language['amp_wlancfg_apply']);</script></button>
                <button id="cancelButton" name="cancelButton" type="button" class="CancleButtonCss buttonwidth_100px" onclick="CancelConfig();"><script>document.write(cfg_wlancfgother_language['amp_wlancfg_cancel']);</script></button>
            </td>
        </tr>
    </tbody>
</table>
</body>
</html>

