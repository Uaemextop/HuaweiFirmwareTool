<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/wlan_list.asp"></script>
<title>WiFi AP Turn</title>
<script language="JavaScript" type="text/javascript">
var percent = 0;
var curWebFrame='<%HW_WEB_GetWEBFramePath();%>';
var wlanArr = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|Enable|SSID|SSIDAdvertisementEnabled|X_HW_Standard|Channel|TransmitPower|RegulatoryDomain|AutoChannelEnable|X_HW_HT20|WMMEnable|X_HW_WorkMode|X_IEEE80211wEnabled|X_TxBFEnabled|X_OCCACEnables|X_HW_MCS|X_HW_RSSIThreshold|X_HW_RSSIThresholdEnable|ChannelPlus|X_SCSEnables|X_HW_AutoChannelPeriodically|X_HW_AutoChannelScope|X_HW_WifiWorkingMode|X_QHOPEnables|BeaconType|BasicEncryptionModes|WPAEncryptionModes|IEEE11iEncryptionModes|X_HW_WPAand11iEncryptionModes|X_HW_ServiceEnable, stWlanWifi);%>;
var wlanArrLen = wlanArr.length - 1;
var wlan11acFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_11AC);%>';
var barLength = (curWebFrame == 'frame_UNICOM') ? 400 : 600;
var WifiScenario = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.X_HW_WifiScenario.ScenarioType);%>';
var dacEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WiFi.FttrDcaConfig.dacEnable);%>';
var isBpon = '<%HW_WEB_GetFeatureSupport(HW_FEATURE_ZQ);%>';
var scnVar = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.X_HW_SCN.Enable);%>' === '1';

function USERDeviceInfo(Domain,MACAddress,Name) {
    this.Domain = Domain;
    this.MACAddress = MACAddress;
    this.Name = Name;
}
var g_AllUserDevinfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_HOMENET_NAME.hosts.{i},MACAddress|Name ,USERDeviceInfo);%>;

function stWlanWifi(domain, Name, Enable, SSID, wlHide, X_HW_Standard, Channel, TransmitPower, RegulatoryDomain, AutoChannelEnable, X_HW_HT20, wmmEnable, X_HW_WorkMode, 
                    X_IEEE80211wEnabled, X_TxBFEnabled, X_OCCACEnables, X_HW_MCS, X_HW_RSSIThreshold, X_HW_RSSIThresholdEnable, ChannelPlus, X_SCSEnables, 
                    X_HW_AutoChannelPeriodically, X_HW_AutoChannelScope, X_HW_WifiWorkingMode, X_QHOPEnables, BeaconType, BasicEncryptionModes, WPAEncryptionModes, 
                    IEEE11iEncryptionModes, X_HW_WPAand11iEncryptionModes, X_HW_ServiceEnable) {
    this.domain = domain;
    this.Name = Name;
    this.Enable = Enable;
    this.SSID = SSID;
    this.wlHide = wlHide;
    this.X_HW_Standard = X_HW_Standard;
    this.Channel = Channel;
    this.TransmitPower = TransmitPower;
    this.RegulatoryDomain = RegulatoryDomain;
    this.AutoChannelEnable = AutoChannelEnable;
    this.X_HW_HT20 = X_HW_HT20;
    this.wmmEnable = wmmEnable;
    this.X_HW_WorkMode = X_HW_WorkMode;
    this.X_IEEE80211wEnabled = X_IEEE80211wEnabled;
    this.X_TxBFEnabled = X_TxBFEnabled;
    this.X_OCCACEnables = X_OCCACEnables;
    this.X_HW_MCS = X_HW_MCS;
    this.X_HW_RSSIThreshold = X_HW_RSSIThreshold;
    this.X_HW_RSSIThresholdEnable = X_HW_RSSIThresholdEnable;
    this.ChannelPlus = ChannelPlus;
    this.X_SCSEnables = X_SCSEnables;
    this.X_HW_AutoChannelPeriodically = X_HW_AutoChannelPeriodically;
    this.X_HW_AutoChannelScope = X_HW_AutoChannelScope;
    this.X_HW_WifiWorkingMode = X_HW_WifiWorkingMode;
    this.X_QHOPEnables = X_QHOPEnables;
    this.BeaconType = BeaconType;
    this.BasicEncryptionModes = BasicEncryptionModes;
    this.WPAEncryptionModes = WPAEncryptionModes;
    this.IEEE11iEncryptionModes = IEEE11iEncryptionModes;
    this.X_HW_WPAand11iEncryptionModes = X_HW_WPAand11iEncryptionModes;
    this.X_HW_ServiceEnable = X_HW_ServiceEnable;
}

function stApDevice(domain, type, sn, hwversion, swversion,uptime, ApOnlineFlag, SupportedRFBand, UplinkType, APMacAddr)
{
    this.domain = domain;
    this.type = type;
    this.sn = sn;
    this.hwversion = hwversion;
    this.swversion = swversion;
    this.uptime = uptime;
    this.ApOnlineFlag = ApOnlineFlag;
    this.SupportedRFBand = SupportedRFBand;
    this.UplinkType = UplinkType;
    this.APMacAddr = APMacAddr.toUpperCase();
}

var apDeviceList = new Array();
apDeviceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}, DeviceType|SerialNumber|HardwareVersion|SoftwareVersion|UpTime|ApOnlineFlag|SupportedRFBand|UplinkType|APMacAddr, stApDevice);%>;

function stApManagement(domain, ApInst, Ieee802Standard2G, RadioEnable2G, TxPower2G,Channel2G, RfBandWidth2G, Ieee802Standard5G, RadioEnable5G, TxPower5G, Channel5G, RfBandWidth5G, APMacAddr, AutoChannel2G, AutoChannel5G, WifiAbility2G, WifiAbility5G) {
    this.domain = domain;
    this.ApInst = ApInst;
    this.Ieee802Standard2G = Ieee802Standard2G;
    this.RadioEnable2G = RadioEnable2G;
    this.TxPower2G = TxPower2G;
    this.Channel2G = Channel2G;
    this.RfBandWidth2G = RfBandWidth2G;
    this.Ieee802Standard5G = Ieee802Standard5G;
    this.RadioEnable5G = RadioEnable5G;
    this.TxPower5G = TxPower5G;
    this.Channel5G = Channel5G;
    this.RfBandWidth5G = RfBandWidth5G;
    this.APMacAddr = APMacAddr;
    this.AutoChannel2G = AutoChannel2G;
    this.AutoChannel5G = AutoChannel5G;
    this.WifiAbility2G = WifiAbility2G;
    this.WifiAbility5G = WifiAbility5G;
}

var apManagementList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_APDevice.{i}.RadioResourceManagement, ApInst|Ieee802Standard2G|RadioEnable2G|TxPower2G|Channel2G|RfBandWidth2G|Ieee802Standard5G|RadioEnable5G|TxPower5G|Channel5G|RfBandWidth5G|APMacAddr|AutoChannel2G|AutoChannel5G|WifiAbility2G|WifiAbility5G, stApManagement);%>;

function GetNameByMac(mac) {
    for (var index = 0; index < g_AllUserDevinfo.length - 1; index++) {
        if (g_AllUserDevinfo[index].MACAddress.toUpperCase() == mac.toUpperCase()) {
            if (g_AllUserDevinfo[index].Name != "") {
                return g_AllUserDevinfo[index].Name;
            }
        }
    }
    return mac;
}

function ModifyBandEnable(id) {
    var html = '<td><select id ="Enable_' + id + '"><option value="1">开</option><option value="0">关</option></select></td>';
    return html;
}

function ModifyTransmitPower(id) {
    var html = '<td><select id ="TransmitPower_' + id + '">' + 
               '<option value="100">100%</option>' + 
               '<option value="80">80%</option>' + 
               '<option value="60">60%</option>' + 
               '<option value="40">40%</option>' + 
               '<option value="20">20%</option></select></td>';

    return html;
}

function ModifyChannel(id) {
    var html = '<td><select id ="Channel_' + id + '">';
    html += '<option value="0">Auto</option>';
    if (id.split("_")[1] == "2G") {
        for (var i = 1; i < 14; i++) {
            html += '<option value="' + i + '">' + i + '</option>';
        }
    } else {
        html += '<option value="' + 36 + '">36</option>';
        html += '<option value="' + 40 + '">40</option>';
        html += '<option value="' + 44 + '">44</option>';
        html += '<option value="' + 48 + '">48</option>';
        html += '<option value="' + 52 + '">52</option>';
        html += '<option value="' + 56 + '">56</option>';
        html += '<option value="' + 60 + '">60</option>';
        html += '<option value="' + 64 + '">64</option>';
        html += '<option value="' + 100 + '">100</option>';
        html += '<option value="' + 104 + '">104</option>';
        html += '<option value="' + 108 + '">108</option>';
        html += '<option value="' + 112 + '">112</option>';
        html += '<option value="' + 116 + '">116</option>';
        html += '<option value="' + 120 + '">120</option>';
        html += '<option value="' + 124 + '">124</option>';
        html += '<option value="' + 128 + '">128</option>';
        html += '<option value="' + 132 + '">132</option>';
        html += '<option value="' + 136 + '">136</option>';
        html += '<option value="' + 140 + '">140</option>';
        html += '<option value="' + 144 + '">144</option>';
        html += '<option value="' + 149 + '">149</option>';
        html += '<option value="' + 153 + '">153</option>';
        html += '<option value="' + 157 + '">157</option>';
        html += '<option value="' + 161 + '">161</option>';
        html += '<option value="' + 165 + '">165</option>';
    }

    html += '</select></td>';

    return html;
}

function ModifyBandWidth(id) {
    var html = '<td><select id ="BandWidth_' + id + '" onChange="X_HW_HT20Change(\'' + id + '\');">';
    html += '<option value="0">' + cfg_wlancfgadvance_language['amp_chlwidth_auto2040'] + '</option>';
    html += '<option value="1">' + cfg_wlancfgadvance_language['amp_chlwidth_20'] + '</option>';
    html += '<option value="2">' + cfg_wlancfgadvance_language['amp_chlwidth_40'] + '</option>';
    html += '<option value="3">' + cfg_wlancfgadvance_language['amp_chlwidth_auto204080'] + '</option>';
    html += '<option value="4">' + cfg_wlancfgadvance_language['amp_chlwidth_auto204080160'] + '</option>';
    html += '<option value="5">' + cfg_wlancfgadvance_language['amp_chlwidth_80and80'] + '</option>';
    html += '<option value="6">' + cfg_wlancfgadvance_language['amp_chlwidth_80'] + '</option>';

    html += '</select></td>';

    return html;
}

function ModifyMode(id) {
    var html = '<td><select id ="Standard_' + id + '" onChange="X_HW_StandardChange(\'' + id + '\');">';
    html += '<option value="11a">802.11a</option>';
    html += '<option value="11na">802.11a/n</option>';
    html += '<option value="11ac">802.11a/n/ac</option>';
    html += '<option value="11nac">802.11n/ac</option>';
    html += '<option value="11aconly">802.11ac</option>';
    html += '<option value="11b">802.11b</option>';
    html += '<option value="11g">802.11g</option>';
    html += '<option value="11n">802.11n</option>';
    html += '<option value="11bg">802.11b/g</option>';
    html += '<option value="11gn">802.11g/n</option>';
    html += '<option value="11bgn">802.11b/g/n</option>';
    html += '<option value="11ax2g">802.11b/g/n/ax</option>';
    html += '<option value="11ax5g">802.11a/n/ac/ax</option>';

    html += '</select></td>';

    return html;
}

function CancelData(id) {
    var trId = id.split("_");
    var html = InitApInstList(trId[1], trId[2]);
    $("#tr_AP_" + trId[1] + "_" + trId[2]).html(html);
}

function SubmitData(id) {
    var trId = id.split("_");
    var enable = getSelectVal("Enable_"+ trId[1] + "_" + trId[2]);
    var transmit = getSelectVal("TransmitPower_"+ trId[1] + "_" + trId[2]);
    var curChannel = getSelectVal("Channel_"+ trId[1] + "_" + trId[2]);
    var bandWidth = getSelectVal("BandWidth_"+ trId[1] + "_" + trId[2]);
    var standard = getSelectVal("Standard_"+ trId[1] + "_" + trId[2]);
    var radioType = (trId[2] == "2G") ? 1 : 2;
    var index = trId[1];
    
    var Form = new webSubmitForm();

    Form.addParameter('x.SetRadioType', radioType);
    Form.addParameter('x.RadioEnable' + trId[2], enable);
    Form.addParameter('x.TxPower' + trId[2], transmit);
    Form.addParameter('x.Channel' + trId[2], curChannel);
    Form.addParameter('x.RfBandWidth' + trId[2], bandWidth);
    Form.addParameter('x.Ieee802Standard' + trId[2], standard);
    Form.setAction('set.cgi?x=' + apManagementList[index].domain
                    + '&RequestFile=html/amp/wlaninfo/wifiApTurn.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

function ModifyForAp(obj) {
    var objArr = obj.id.split("_");
    var id = objArr[1] + "_" + objArr[2];
    var apInst = objArr[1];
    var band = objArr[2];
    var trId = "tr_AP_" + id;
    var inst = (band == "2G") ? 1 : 2;
    $("#" + trId).html("");
    var trHtml = '';     
        trHtml += '<td class="align_center"><input type="checkbox" id="apListId_' + id + '" name="apListId_' + id + '" value="ON"></td>';
        trHtml += '<td class="align_center">' + apManagementList[apInst].ApInst + '</td>';
        trHtml += '<td class="align_center" style="word-wrap:break-word;">'
            + htmlencode(GetNameByMac(apManagementList[apInst].APMacAddr)) + '</td>'; 
        trHtml += '<td class="align_center">' + ShowBand(band) +'</td>';
        trHtml += ModifyBandEnable(id); 
        trHtml += ModifyTransmitPower(id);
        trHtml += ModifyChannel(id);
        trHtml += ModifyBandWidth(id);
        trHtml += ModifyMode(id);
        trHtml += '<td class="align_center">' + '<div><button id="Save_' + id + '" style="width:80px;" onClick="SubmitData(this.id)">保存</button></div><div>' 
                  + '<button id="modify_' + id + '" onClick="CancelData(this.id)" style="width:80px;">取消</button></div>' + '</td>';
    $("#" + trId).html(trHtml);
    InitSelectValue(id);
    rebuildWlanBasicDropDownList(id);
}

function InitSelectValue(id) {
    var objArr = id.split("_");
    var index = objArr[0];
    var enable = (objArr[1] == "2G") ? apManagementList[index].RadioEnable2G : apManagementList[index].RadioEnable5G;
    var transmit = (objArr[1] == "2G") ? apManagementList[index].TxPower2G : apManagementList[index].TxPower5G;
    var curChannel = (objArr[1] == "2G") ? apManagementList[index].Channel2G : apManagementList[index].Channel5G;
    var autoChannelEnable = (objArr[1] == "2G") ? apManagementList[index].AutoChannel2G : apManagementList[index].AutoChannel5G;
    var bandWidth = (objArr[1] == "2G") ? apManagementList[index].RfBandWidth2G : apManagementList[index].RfBandWidth5G;
    var standard = (objArr[1] == "2G") ? apManagementList[index].Ieee802Standard2G : apManagementList[index].Ieee802Standard5G;
    if (standard == "11ax") {
        standard = (objArr[1] == "2G") ? "11ax2g" : "11ax5g";
    }
    setSelect("Enable_" + id, enable);
    setSelect("TransmitPower_" + id, transmit);
    if (autoChannelEnable == 1) {
        setSelect("Channel_" + id, 0);
    } else {
        setSelect("Channel_" + id, curChannel);
    }
    setSelect("BandWidth_" + id, bandWidth);
    setSelect("Standard_" + id, standard);
}

function InitX_HW_Standard(id) {
    var isshow11n = 0;
    var isshow11aconly = 0;
    var isshow11ac = 0;
    var isshow11a = 0;
    var objArr = id.split("_");
    var index = objArr[0];
    var is11AXForFreq = (objArr[1] == "2G") ? "802.11b/g/n/ax" : "802.11a/n/ac/ax";
    var wlgmode = getSelectVal("Standard_" + id);

    var capInfo = (objArr[1] == "2G") ? apManagementList[index].WifiAbility2G : apManagementList[index].WifiAbility5G;
    var cap11ax = parseInt(capInfo.charAt(34));
    var cap11n = parseInt(capInfo.charAt(5));
    var cap11a = 1;
    var isshow11ax = cap11ax;

    for (i = 0; i < wlanArrLen; i++) {
        var name = wlanArr[i].Name;
        var portIndex = parseInt(name.charAt(length-1));
        if (objArr[1] == "5G") {
            if ((portIndex < ssidStart5G) || (portIndex > ssidEnd5G)) {
                continue;
            }
        } else {
             if (portIndex > ssidEnd2G) {
                continue;
            }
        }

        var BeaconType = wlanArr[i].BeaconType;
        var BasicEncryptionModes =  wlanArr[i].BasicEncryptionModes;
        var WPAEncryptionModes  = wlanArr[i].WPAEncryptionModes;
        var IEEE11iEncryptionModes = wlanArr[i].IEEE11iEncryptionModes;
        var X_HW_WPAand11iEncryptionModes = wlanArr[i].X_HW_WPAand11iEncryptionModes;

        if ((BeaconType == "Basic") && (BasicEncryptionModes == "WEPEncryption")) {
           isshow11n += 1;
           isshow11ac +=1;
           isshow11aconly +=1;
        } else if ((BeaconType == "WPA") && 
                   ((WPAEncryptionModes == "TKIPEncryption")||(WPAEncryptionModes == "TKIPandAESEncryption"))) {
           isshow11n += 1;
           isshow11aconly +=1;
        } else if (((BeaconType == "11i") || (BeaconType == "WPA2")) && 
                    ((IEEE11iEncryptionModes == "TKIPEncryption")||(IEEE11iEncryptionModes == "TKIPandAESEncryption"))) {
           isshow11n += 1;
           isshow11aconly +=1;
        } else if (((BeaconType == "WPAand11i") || (BeaconType == "WPA/WPA2")) && 
                   ((X_HW_WPAand11iEncryptionModes == "TKIPEncryption") || (X_HW_WPAand11iEncryptionModes == "TKIPandAESEncryption"))) {
           isshow11n += 1;
           isshow11aconly +=1;
        } else if (((BeaconType == "WPA3") || (BeaconType == "WPA2/WPA3")) && 
                   ((X_HW_WPAand11iEncryptionModes == "TKIPEncryption") || (X_HW_WPAand11iEncryptionModes == "TKIPandAESEncryption"))) {
           isshow11n += 1;
           isshow11aconly +=1;
        }

        if (wlanArr[i].wmmEnable == 0) {
            isshow11n += 1;
        }
    }

    isshow11n += 1 - cap11n;
    isshow11a += 1 - cap11a;

    $("#Standard_" + id).empty();
    
    var standardArr = { '11a' : ["802.11a", 0], 
                      '11b' : ["802.11b", 0], 
                      '11g' : ["802.11g", 0], 
                      '11n' : ["802.11n", 0], 
                      '11bg' : ["802.11b/g", 0], 
                      '11bgn' : ["802.11b/g/n", 0], 
                      '11na' : ["802.11a/n", 0], 
                      '11ac' : ["802.11a/n/ac", 0],
                      '11ax' : [is11AXForFreq, 0],
                      '11nac' : ["802.11n/ac", 0]
                   };

    standardArr['11n'][1] = (isshow11n == 0);
    standardArr['11ax'][1] = (isshow11ax);
    
    if (objArr[1] == "5G") {
        standardArr['11a'][1] = (isshow11a == 0);
        standardArr['11na'][1] = 1;
        standardArr['11ac'][1] = (isshow11ac == 0);
    } else {
        standardArr['11b'][1] = 1;
        standardArr['11g'][1] = 1;
        standardArr['11bg'][1] = 1;
        standardArr['11bgn'][1] = 1;

        if (wlgmode == "11n" && (standardArr['11n'][1] == 0)) {
            wlgmode = "11bgn";
        }
    }

    if ((wlgmode == "11ax2g") || wlgmode == "11ax5g") {
        wlgmode = "11ax";
    }

    InitDropDownListWithSelected("Standard_" + id, standardArr, wlgmode);

    if (getSelectVal("Standard_" + id) != wlgmode) {
        setSelect("Standard_" + id, "11bgn");
    }
}

function X_HW_StandardChange(id) {
    var mode = getSelectVal('Standard_' + id);
    var channelWidthRestore = getSelectVal('BandWidth_' + id);
    var channel = getSelectVal('Channel_' + id);
    var country = wlanArr[0].RegulatoryDomain;
    var objArr = id.split("_");
    var index = objArr[0];
    var capInfo = (objArr[1] == "2G") ? apManagementList[index].WifiAbility2G : apManagementList[index].WifiAbility5G;
    var cap11ax = parseInt(capInfo.charAt(34));
    var capHT160 = parseInt(capInfo.charAt(13));

    if ((channel == 14) && (mode != "11b")) {
        setSelect('Channel_' + id, 0);
    }
    
    if (mode == "11ax2g" || mode == "11ax5g") {
        mode = "11ax";
    }

    $('#BandWidth_' + id).empty();
    
    var bandWidthArr = { '0' : [cfg_wlancfgadvance_language['amp_chlwidth_auto2040'], 0], 
                      '1' : [cfg_wlancfgadvance_language['amp_chlwidth_20'], 0], 
                      '2' : [cfg_wlancfgadvance_language['amp_chlwidth_40'], 0], 
                      '3' : [cfg_wlancfgadvance_language['amp_chlwidth_auto204080'], 0], 
                      '4' : [cfg_wlancfgadvance_language['amp_chlwidth_auto204080160'], 0], 
                      '5' : [cfg_wlancfgadvance_language['amp_chlwidth_80and80'], 0], 
                      '6' : [cfg_wlancfgadvance_language['amp_chlwidth_80'], 0]
                   };

    if ((mode == "11b") || (mode == "11g") || (mode == "11bg") || (mode == "11a")) {
        bandWidthArr["1"][1] = 1;
    } else {
        bandWidthArr["0"][1] = 1;
        bandWidthArr["1"][1] = 1;
        bandWidthArr["2"][1] = 1;
    }

    if ((objArr[1] == "5G") && (((mode == "11ac") || (mode == "11nac") || (mode == "11aconly")) || ((cap11ax == 1) && (mode == "11ax")))) {
        bandWidthArr["3"][1] = 1;
        if (((cap11ax == 1) && (mode == "11ax")) || (capHT160 == 1)) {
            bandWidthArr["4"][1] = 1;
        }
    }

    if ((channelWidthRestore != 3) || (mode == "11ac") || (mode == "11aconly") || (mode == "11nac") || (mode == "11ax")) {
        InitDropDownListWithSelected("BandWidth_" + id, bandWidthArr, channelWidthRestore);
    } else {
        InitDropDownListWithSelected("BandWidth_" + id, bandWidthArr, 0);
    }

    var width = getValue('BandWidth_' + id);
    loadChannelList(id, mode, width);
}

function X_HW_HT20Change(id) {
    var width = getValue('BandWidth_' + id);
    var mode = getSelectVal('Standard_' + id);
    loadChannelList(id, mode, width);
}

var possibleChannels = "";
function getPossibleChannels(id, mode, width) {
    var freq = id.split("_")[1];
    var country = wlanArr[0].RegulatoryDomain;
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        url : "../common/WlanChannel.asp?&1=1",
        data :"freq=" + freq + "&country=" + country + "&standard=" + mode + "&width=" + width,
        success : function(data) {
            possibleChannels = data;
            var lastIndex = possibleChannels.lastIndexOf(',');
            var index = possibleChannels.length;
            for (var i = lastIndex + 1; i < possibleChannels.length; i++) {
                if ((possibleChannels.charCodeAt(i) < 0x30) || (possibleChannels.charCodeAt(i) > 0x39)) {
                    index = i;
                    break;
                }
            }

            possibleChannels = possibleChannels.substring(0, index);
        }
    });
}

function loadChannelListByFreq(id, width) {
    var ShowChannels = possibleChannels.split(',');
    var WebChannel = getSelectVal('Channel_' + id);
    var WebChannelValid = 0;

    $("#Channel_" + id).empty();
    
    var html = '<option value="0">Auto</option>';

    for (var j = 1; j <= ShowChannels.length; j++) {
        if (WebChannel == ShowChannels[j-1]) {
            WebChannelValid = 1;
        }

        if (ShowChannels[j-1] != "") {
            html += '<option value="' + ShowChannels[j-1] + '">'+ ShowChannels[j-1] + '</option>';
        }
    }

    $("#Channel_" + id).html(html);
    if (WebChannelValid == 1) {
        setSelect('Channel_' + id, WebChannel);
    } else {
        setSelect('Channel_' + id, 0);
    }
}

function loadChannelList(id, mode, width) {
    getPossibleChannels(id, mode, width);
    loadChannelListByFreq(id, width);
}

function rebuildWlanBasicDropDownList(id) {
    InitX_HW_Standard(id);
    X_HW_StandardChange(id);
}

function GetInstByDomain(domain) {
    return domain.split(".")[2];
}

function ShowBand(band) {
    if (band == "2G") {
        return "2.4G";
    }
    return band;
}

function ShowEnable(enable) {
    return (enable == 1) ? "开" : "关";
}

var modeList = {  '0' : cfg_wlancfgadvance_language['amp_chlwidth_auto2040'], 
                    '1' : cfg_wlancfgadvance_language['amp_chlwidth_20'], 
                    '2' : cfg_wlancfgadvance_language['amp_chlwidth_40'], 
                    '3' : cfg_wlancfgadvance_language['amp_chlwidth_auto204080'], 
                    '4' : cfg_wlancfgadvance_language['amp_chlwidth_auto204080160'], 
                    '5' : cfg_wlancfgadvance_language['amp_chlwidth_80and80'], 
                    '6' : cfg_wlancfgadvance_language['amp_chlwidth_80']
                  };

function ShowBandWidth(bandWidth) {
    return modeList[bandWidth];
}

var standardList = { '11a' : "802.11a", 
                    '11b' : "802.11b", 
                    '11g' : "802.11g", 
                    '11n' : "802.11n", 
                    '11bg' : "802.11b/g", 
                    '11bgn' : "802.11b/g/n", 
                    '11na' : "802.11a/n",
                    '11ac' : "802.11a/n/ac",
                    '11ax2g' : "802.11b/g/n/ax",
                    '11ax5g' : "802.11a/n/ac/ax"
                  };

function ShowStandard(standard, band) {
    if (standard == "11ax") {
        standard = (band == "2G") ? "11ax2g" : "11ax5g";
    }
    return standardList[standard];
}
                  
function InitApInstList(i, band) {
    var clickButton = (apDeviceList[i].UplinkType == "Wireless" || scnVar) ? "disabled" : "";
    var enable = (band == "2G") ? apManagementList[i].RadioEnable2G : apManagementList[i].RadioEnable5G;
    var transmit = (band == "2G") ? apManagementList[i].TxPower2G : apManagementList[i].TxPower5G;
    var curChannel = (band == "2G") ? apManagementList[i].Channel2G : apManagementList[i].Channel5G;
    var autoChannelEnable = (band == "2G") ? apManagementList[i].AutoChannel2G : apManagementList[i].AutoChannel5G;
    var bandWidth = (band == "2G") ? apManagementList[i].RfBandWidth2G : apManagementList[i].RfBandWidth5G;
    var standard = (band == "2G") ? apManagementList[i].Ieee802Standard2G : apManagementList[i].Ieee802Standard5G;
    var html = "";
    html += '<td class="align_center"><input type="checkbox" id="apListId_' + i +  '_' + band + '" name="apListId_' + i +  '_' + band + '" value="ON"' + clickButton + '></td>';
    html += '<td class="align_center">' + apManagementList[i].ApInst + '</td>';
    html += '<td class="align_center" style="word-wrap:break-word;">'
        + htmlencode(GetNameByMac(apManagementList[i].APMacAddr)) + '</td>'; 
    html += '<td class="align_center">' + ShowBand(band) +'</td>';
    html += '<td class="align_center">' + ShowEnable(enable) +'</td>';
    html += '<td class="align_center">' + transmit +'%</td>';
    if (autoChannelEnable == 1) {
        html += '<td class="align_center">' + 'Auto';
        if (isBpon == 1) {
            html += '(' + curChannel + ')';
        }
        html += '</td>';
    } else {
        html += '<td class="align_center">' + curChannel +'</td>';
    }
    html += '<td class="align_center">' + ShowBandWidth(bandWidth) +'</td>';
    html += '<td class="align_center">' + ShowStandard(standard, band) +'</td>';
    html += '<td class="align_center">' + '<div>' 
              + '<button style="width:80px;" id="modify_' + i +  '_' + band + '" onClick="ModifyForAp(this)" ' + clickButton + '>修改</button></div>' + '</td>';
    return html;
}

function InitApInst()
{
    for (var i = 0;i < apDeviceList.length - 1; i++) {
        if (apDeviceList[i].ApOnlineFlag == 0) {
            continue;
        }
        apOnlineNums++;
        var trHtml = '';
        trHtml += '<tr class="tabal_01 align_center ssid_detail2G" id="tr_AP_' + i + '_2G">'; 
        trHtml += InitApInstList(i,"2G");
        trHtml += '</tr>';
        trHtml += '<tr class="tabal_02 align_center ssid_detail2G" id="tr_AP_' + i + '_5G">'; 
        trHtml += InitApInstList(i,"5G");
        trHtml += '</tr>';
        $("#apInstInfo").append(trHtml);
    }
}

function Hideprocess() {
    setDisplay("wifiAlertContent", 0);
    setDisplay("wifiBackground", 0);
}

function setPrograss() {
    var sencondBar = (curWebFrame == 'frame_UNICOM') ? 20 : 30;
    percent++;
    var progvalue = percent*(sencondBar);

    $(".upgline").css("width", progvalue + "px");
    $(".upgline_back").css('width',barLength - progvalue + "px");

    var lastPercent = barLength - sencondBar*2;

    if (progvalue == lastPercent) {
        clearInterval(times);
        getResultTime = setInterval("AjaxGetData()", 2000);
        return;
    }
}

function JudgeHideprocess() {
    getAllTimes += 2;
    if (turnResult == '') {
        return;
    }
    turnResult = turnResult.split(";");
    turnResult[0] = turnResult[0].split(",");
    turnResult[1] = turnResult[1].split(",");
    fail2gList = turnResult[0][3].split(":");
    fail5gList = turnResult[1][3].split(":");
    if (((turnResult[0][1] == 0) && (turnResult[1][1] == 0)) || (getAllTimes == 20)) {
        clearInterval(getResultTime);
        $(".upgline").css("width", barLength + "px");
        $(".upgline_back").css('width', '0px');
        setTimeout("Hideprocess()",1000);
        setDisplay("TurnResult", 1);
        getElementById("num2gTotal").innerHTML = turnResult[0][0];
        getElementById("num2gSuccess").innerHTML = turnResult[0][2];
        getElementById("num2gFail").innerHTML = turnResult[0][0] - turnResult[0][2];
        getElementById("num5gTotal").innerHTML = turnResult[1][0];
        getElementById("num5gSuccess").innerHTML = turnResult[1][2];
        getElementById("num5gFail").innerHTML = turnResult[1][0] - turnResult[1][2];
        if (fail2gList[0] != 0) {
            var html2gFail;
            html2gFail = fail2gList[1];
            for (var i = 2; i < fail2gList.length; i++) {
                html2gFail += "," + fail2gList[i];
            }

            getElementById("failList2g").innerHTML = "失败的AP ID:" + html2gFail;
            setDisplay("failList2g", 1);
        }

        if (fail5gList[0] != 0) {
            var html5gFail;
            html5gFail = fail5gList[1];
            for (var i = 2; i < fail5gList.length; i++) {
                html5gFail += "," + fail5gList[i];
            }

            getElementById("failList5g").innerHTML = "失败的AP ID:" + html5gFail;
            setDisplay("failList5g", 1);
        }
    }
}

var turnResult;
function AjaxGetData() {
    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "./getWifiTurnResult.asp?&1=1",
            success : function(data) {
                turnResult = data;
                JudgeHideprocess();
            }
        });
}

function AjaxData() {
    $.ajax({
            type : "POST",
            async : true,
            cache : false,
            url : "setRadioOptimize.cgi?RequestFile=html/amp/wlaninfo/wifiApTurn.asp",
            data :"wlaninst="+wlaninst + '&x.X_HW_Token=' + getValue('onttoken'),
            success : function(data) {
            }
        });
}

var ApTurnMode = "";
function CheckTurnBandMode(index, band) {
    var mode = (band == "2G") ? apManagementList[index].Ieee802Standard2G : apManagementList[index].Ieee802Standard5G;
    var capInfo = (band == "2G") ? apManagementList[index].WifiAbility2G : apManagementList[index].WifiAbility5G;
    var cap11ax = parseInt(capInfo.charAt(34));
    var defaultMode;
    if (cap11ax == 1) {
        defaultMode = "11ax";
    } else {
        defaultMode = (band == "2G") ? "11bgn" : "11ac";
    }
    if (mode != defaultMode) {
        ApTurnMode += apManagementList[index].ApInst + "," + band + ";";
    }
}

function SetWlanInstData() {
    wlaninst = "";
    ApTurnMode = "";
    for (var i = 0;i < apDeviceList.length - 1; i++) {
        if (getCheckVal("apListId_" + i + "_2G") == 1) {
            wlaninst += GetInstByDomain(apDeviceList[i].domain) + ",1;";
            CheckTurnBandMode(i, "2G");
        }

        if (getCheckVal("apListId_" + i + "_5G") == 1) {
            wlaninst += GetInstByDomain(apDeviceList[i].domain) + ",2;";
            CheckTurnBandMode(i, "5G");
        }
    }
}

var times;
var getResultTime;
var getAllTimes = 0;
var wlaninst = "";

function OnclickTuningAll() {
    if (ConfirmEx("一键射频调优会自动修改当前的AP参数，可能会导致业务中断，是否继续调优？") == true) {
        SubmitTuningAll();
    }
}
function SubmitTuningAll() {
    SetWlanInstData();
    if (wlaninst == "") {
        alert("请勾选需要配置的AP频段");
        return;
    }
    if (ApTurnMode != "") {
        alert("调优AP频段的模式需为最高模式");
        return;
    }
    AjaxData();
    percent = 0;
    $(".upgline").css("width", "0px");
    $(".upgline_back").css('width', barLength + 'px');

    setDisplay("wifiAlertContent", 1);
    setDisplay("wifiBackground", 1);
    times = setInterval("setPrograss()",1000);
}

var apOnlineNums = 0;
function LoadFrame() {
    if (curWebFrame == 'frame_UNICOM') {
        $("#wifiAlertContent").css({ 
            "width": "76%", 
            "height": "100px" ,
            "top": "120px"
        });
        $("#progress_bar").css({ 
            "width": "400px", 
        });
        $(".upgline_back").css({ 
            "width": "400px", 
        });
    }
    InitApInst();
    document.getElementById('ApTotalNum').innerHTML = apOnlineNums;

    var checkScenario = getElement("rml")
    for (var i = 0; i < checkScenario.length; i++) {
        if (checkScenario[i].value == WifiScenario) {
            checkScenario[i].checked = true;
        }
    }

    if (isBpon == 1) {
        setDisplay("TurnScenTable", 1);
    }

    if (isBpon != 1) {
        setDisplay("dacEnableDiv", 1);
        setDisplay("dacEnableSpread", 1);
        setCheck("dacEnable", dacEnable);
    }

    if (scnVar) {
        setDisable('dacEnable', 1);
        setDisable('tuningAll', 1);
    }
}

function getRadioValue(sId) {
    var item = getElement(sId);
    if (item == null) {
        debug(sId + " is not existed" );
        return -1;
    }

    if (item.length > 0) {
        for (i = 0; i < item.length; i++) {
            if (item[i].checked == true) {
                return item[i].value;
            }
        }
    } else if (item.checked == true) {
        return item.value;
    }

    return -1;
}

function ModifyForRadio() {
    if (isBpon != 1) {
        return;
    }
    var Form = new webSubmitForm();
    Form.addParameter('x.ScenarioType', getRadioValue("rml"));
    Form.setAction('set.cgi?x=InternetGatewayDevice.LANDevice.1.X_HW_WifiScenario&RequestFile=html/amp/wlaninfo/wifiApTurn.asp');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.submit();
}

var checkVal = 1;
function chooseAll() {
    for (var i = 0;i < apDeviceList.length - 1; i++) {
        if (apDeviceList[i].UplinkType == "Wireless" || apDeviceList[i].ApOnlineFlag == 0) {
            continue;
        }
        setCheck("apListId_" + i + "_2G", checkVal);
        setCheck("apListId_" + i + "_5G", checkVal);
    }
    checkVal = 1 - checkVal;
}

function SubmitDacEnable() {
    var enable = getCheckVal('dacEnable');
    if (enable == 1) {
        if (confirm("自动射频调优运行时有可能导致STA断开重新连接")) {
            var Form = new webSubmitForm();
            Form.addParameter('x.dacEnable', enable);
            Form.setAction('set.cgi?x=InternetGatewayDevice.LANDevice.1.WiFi.FttrDcaConfig&RequestFile=html/amp/wlaninfo/wifiApTurn.asp');
            Form.addParameter('x.X_HW_Token', getValue('onttoken'));
            Form.submit();
        } else {
            setCheck('dacEnable', 0);
        }
    } else {
        var Form = new webSubmitForm();
        Form.addParameter('x.dacEnable', enable);
        Form.setAction('set.cgi?x=InternetGatewayDevice.LANDevice.1.WiFi.FttrDcaConfig&RequestFile=html/amp/wlaninfo/wifiApTurn.asp');
        Form.addParameter('x.X_HW_Token', getValue('onttoken'));
        Form.submit();
    }
}
</script>

<style>
.mainbody {
    margin-left: 30px; 
    margin-right: 30px;
}
.blackBackgroundWifi {
    width: 100%;
    height: 100%;
    position: fixed;
    background-color: rgba(0, 0, 0, 0.7);
    z-index: 100;
    left: 0;
    top: 0;
}
.contentAlert {
    width:80%;
    height:150px;
    z-index:100;
    background-color:#fff;
    border:1px solid #C7C7C4;
    position:absolute;
    top:200px;
    left:5%;
    padding: 34px 40px 40px;
}

.upgline {
    width: 0px;
    height: 20px;
    overflow: hidden;
    background-color: #4eaff5;
    float:left;
}
.upgline_back {
    width: 600px;
    height: 20px;
    overflow: hidden;
    background-color: #D6DAE1;
    float:left;
}
</style>

</head>

<body class="mainbody" onLoad="LoadFrame();" >
<input type="hidden" id="onttoken"  name="onttoken" value="<%HW_WEB_GetToken();%>"/>
<table width="100%" height="5" border="0" cellpadding="0" cellspacing="0"><tr> <td></td></tr></table>  
<div id="WifiCoverCfgtitle" class="PageTitle_title">射频管理</div>
<div id="WifiCoverCfg_content" class="PageTitle_content">
<div>1. 此页面可以使能自动射频调优，一键射频调优，修改选中有线AP频段的信道、频宽和模式等配置</div>
<div>2. 此页面可以手动修改有线AP的参数</div>
<div>3. SRCN开启场景下无法使用射频调优功能</div>
</div>
<div class="title_spread"></div>

<div class="blackBackgroundWifi" id="wifiBackground" style="display:none;">

</div>

<div id="wifiAlertContent" class="contentAlert" style="display:none;">
    <div class="PageTitle_title">正在调优中...</div>
    <div id="progress_bar" style="margin-top:20px;width:600px;">
        <div>
            <div class="upgline"></div>
            <div class="upgline_back"></div>
        </div>
    </div>
</div>

<div id="dacEnableDiv" style="display:none;">
    <input type="checkbox" id="dacEnable" name="dacEnable" onClick="SubmitDacEnable();">
    <span class="gray">自动射频调优</span>
</div>
<div id="dacEnableSpread" class="title_spread" style="display:none;"></div>
<div style="text-align: center;">
    <button id="tuningAll" class="NewDelbuttoncss" onClick="OnclickTuningAll()">一键射频调优</button>
</div>
<div class="title_spread"></div>

<table id="TurnScenTable" style="font-size: 14px;display:none;">
    <tr>
        <td>
            <input type="radio" name="rml" id="rml" value="0" onclick="ModifyForRadio()">
        </td>
        <td>
            普通场景，默认推荐场景(2.4G:20M,5G:40M)
        </td>
    </tr>
    <tr>
        <td>
            <input type="radio" name="rml" id="rml" value="1" onclick="ModifyForRadio()">
        </td>
        <td>
            高密场景，AP间布放间隔较小(<5m),单个AP的5G频段接入数<8个(2.4G:20M,5G:20M)
        </td>
    </tr>
    <tr>
        <td>
            <input type="radio" name="rml" id="rml" value="2" onclick="ModifyForRadio()">
        </td>
        <td>
            低密场景，AP间布放间隔较大(>20m);AP间WIFI重叠信号较弱(<-70)(2.4G:20M,5G:Auto 20/40/80M)
        </td>
    </tr>
    <tr>
        <td>
            <input type="radio" name="rml" id="rml" value="3" onclick="ModifyForRadio()">
        </td>
        <td>
            稀疏场景，对单AP WIFI性能有较高要求;AP间布放相互无WIFI信号重叠(2.4G:Auto 20/40M,5G:Auto 20/40/80/160M)
        </td>
    </tr>
</table>
<div class="title_spread"></div>

<div id="TurnResult" style="display:none;font-size: 14px;">
    <div class="title_spread"></div>
    <div>2G频段共计<span id="num2gTotal"></span>个射频，调优配置成功<span id="num2gSuccess"></span>个，配置失败<span id="num2gFail"></span>个；
        <span id="failList2g" style="display:none;"></span></div>
    <div>5G频段共计<span id="num5gTotal"></span>个射频，调优配置成功<span id="num5gSuccess"></span>个，配置失败<span id="num5gFail"></span>个；
        <span id="failList5g" style="display:none;"></span></div>
    <div>调优结束后，请刷新本页面查看最新调优生效结果；如果AP调优失败，请检查AP是否在线或工作在雷达信道频段。</div>
</div>

<div style="font-size: 14px;">AP数目： <span id="ApTotalNum" ></span></div>
<div id="basicSetting2G" style="overflow:auto;overflow-y:auto;max-height:430px">
    <table width="100%" border="0" cellpadding="0" cellspacing="0">
    <tbody>
        <tr>
            <td id="Wireless">
                <div id="DivSSIDList_Table_Container">        
                    <table width="100%" border="0" cellspacing="1" class="tabal_bg" id="apInstInfo">
                        <tbody>
                            <tr class="head_title align_center" style="word-break: keep-all;">
                                <td class="align_center">
                                    <input type="checkbox" id="EnableAll" name="EnableAll" value="ON" onClick="chooseAll()">
                                </td>
                                <td class="align_center">AP ID</td>
                                <td class="align_center">AP名称</td>
                                <td class="align_center">频段</td>
                                <td class="align_center">开关</td>
                                <td class="align_center">发射功率</td>
                                <td class="align_center">信道</td>
                                <td class="align_center">频宽</td>
                                <td class="align_center">模式</td>
                                <td class="align_center">操作</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </td>
        </tr>
    </tbody>
    </table>
</div>

<div>
    
</div>

</body>
</html>
