<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Pragma" content="no-cache" />
    <link rel="stylesheet" href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
    <link rel="stylesheet" href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
    <link rel="stylesheet" href='../common/<%HW_WEB_CleanCache_Resource(wlan_style.css);%>' type='text/css'>
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
    <script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
    <script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
    <script type="text/javascript"
        src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
    <script language="javascript" src="../common/wlan_list.asp"></script>

    <script>
        var kppUsedFlag = '<%HW_WEB_GetFeatureSupport(FT_WLAN_PWD_KPP_USED);%>';
        var modifyFlag = '<%HW_WEB_GetFeatureSupport(FT_UNICOM_MODIFYSSIDNAME);%>';
        function checkUnicomSSIDName(ssid, curSsidIdx)
        {
            if (modifyFlag == 1) {
                return true;
            }
            if (('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SSID1_STARTWITH_CU);%>' == 1) && (curSsidIdx == 0) && (ssid.indexOf("CU_") != 0)) {
                AlertEx(cfg_wlancfgother_language['amp_ssid_must_be_cu']);
                return false;
            }
            if (('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_LNCU);%>' == 1) && (curSsidIdx == 0) && (ssid.indexOf("lnunicom_") != 0)) {
                AlertEx(cfg_wlancfgother_language['amp_ssid_must_be_lnunicom']);
                return false;
            }
            
            var ssid5G = 0;
            if ((curSsidIdx >= 0) && (curSsidIdx < Wlan.length)) {
                ssid5G = getWlanInstFromDomain(Wlan[curSsidIdx].domain);
            }
            if (('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SSID1_STARTWITH_CU);%>' == 1) && (ssid5G == 5) && (ssid.indexOf("CU_") != 0)) {
                AlertEx(cfg_wlancfgother_language['amp_ssid_must_be_cu_5G']);
                return false;
            }
            if (('<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_LNCU);%>' == 1) && (ssid5G == 5) && (ssid.indexOf("lnunicom_") != 0)) {
                AlertEx(cfg_wlancfgother_language['amp_ssid_must_be_lnunicom_5G']);
                return false;
            }
            return true;
        }

        function stPreSharedKey(domain, psk, kpp) {
            this.domain = domain;
            this.value = psk;

            if (kppUsedFlag == '1') {
                this.value = kpp;
            }
        }

        function dealDataWithFun(str) {
            if (typeof str === 'string' && str.indexOf('function') === 0) {
                return Function('"use strict";return (' + str + ')')()();
            }
            return str;
        }

        function dealDataWithStr(str, repStr) {
            var funStr = '';
            if (repStr) {
                var newRepStr = 'return ' + repStr;
                funStr = str.replace(repStr, newRepStr);
            } else {
                funStr = 'return ' + str + ';';
            }
            str = 'function() {' + funStr + '}';
            return dealDataWithFun(str);
        }

        var IsSingleWifi = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SINGLE_WLAN);%>';
        var IsDoubleWifi = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
        var trimssidFlag = '<%HW_WEB_GetFeatureSupport(FT_WLAN_NOT_TRIM_SSID);%>';
        var curUserType = '<%HW_WEB_GetUserType();%>';
        var WlanInfoList = '<%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|SSID|X_HW_ServiceEnable|Enable,stWlanInfo);%>';

        if (WlanInfoList !== '') {
            var WlanInfo = dealDataWithStr(WlanInfoList);
        } else {
            var WlanInfo = new Array();
        }


        var ssid1 = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID);%>';
        var ssid2 = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID);%>';

        var wpaPskKey = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.PreSharedKey.1, PreSharedKey|KeyPassphrase, stPreSharedKey);%>;
        var wifiPasswordMask = '<%HW_WEB_GetWlanPsdMask();%>';

        function stConfigurationByRadio(domain, RssiThreshold, RssiBackoffThreshold) {
            this.domain = domain;
            this.RssiThreshold = RssiThreshold;
            this.RssiBackoffThreshold = RssiBackoffThreshold;
        }
        var configurationByRadio = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.LANDevice.1.WiFi.X_HW_GlobalConfig.X_HW_UseBandSteering.{i}, RssiThreshold|RssiBackoffThreshold, stConfigurationByRadio);%>;

        var SsidPerBand = '<%HW_WEB_GetSPEC(AMP_SPEC_SSID_NUM_MAX_BAND.UINT32);%>';

        var ssidEnd2G = SsidPerBand - 1;
        var ssidStart5G = SsidPerBand;

        function stWlan(domain,name,ssid,BeaconType,BasicEncryptionModes,BasicAuthenticationMode,WPAEncryptionModes,WPAAuthenticationMode,
                IEEE11iEncryptionModes,IEEE11iAuthenticationMode,X_HW_WPAand11iEncryptionModes,X_HW_WPAand11iAuthenticationMode)
        {
            this.domain = domain;
            this.name = name;
            this.ssid = ssid;
            this.BeaconType = BeaconType;
            this.BasicEncryptionModes = BasicEncryptionModes;
            this.BasicAuthenticationMode = BasicAuthenticationMode;
            this.WPAEncryptionModes = WPAEncryptionModes;
            this.WPAAuthenticationMode = WPAAuthenticationMode;
            this.IEEE11iEncryptionModes = IEEE11iEncryptionModes;
            this.IEEE11iAuthenticationMode = IEEE11iAuthenticationMode;
            this.X_HW_WPAand11iEncryptionModes = X_HW_WPAand11iEncryptionModes;
            this.X_HW_WPAand11iAuthenticationMode = X_HW_WPAand11iAuthenticationMode;

        }

        var Wlan = new Array();

        var WlanArr = <%HW_WEB_CmdGetWlanConf(InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i},Name|SSID|BeaconType|BasicEncryptionModes|BasicAuthenticationMode|WPAEncryptionModes|WPAAuthenticationMode|IEEE11iEncryptionModes|IEEE11iAuthenticationMode|X_HW_WPAand11iEncryptionModes|X_HW_WPAand11iAuthenticationMode,stWlan);%>;

        var wlanArrLen = WlanArr.length - 1;

        for (var i = 0; i < wlanArrLen; i++) {
            Wlan[i] = new stWlan();
            Wlan[i] = WlanArr[i];
        }

        function IsWlanSameSsid() 
        {
            var WlanWifi2G;
            var WlanWifi5G;

            for (var i = 0; i < Wlan.length; i++) {
                if (getInstIdByDomain(Wlan[i].domain) == 1) {
                    WlanWifi2G = Wlan[i];
                }

                if (getInstIdByDomain(Wlan[i].domain) == parseInt(ssidStart5G) + 1) {
                    WlanWifi5G = Wlan[i];
                }
            }

            if (WlanWifi2G.ssid != WlanWifi5G.ssid) {
                return false;
            }

            if (WlanWifi2G.BeaconType != WlanWifi5G.BeaconType) {
                return false;
            }

            if ((WlanWifi2G.BeaconType == 'Basic') || (WlanWifi2G.BeaconType == 'None')) {
                if ((WlanWifi2G.BasicAuthenticationMode != WlanWifi5G.BasicAuthenticationMode)
                    || (WlanWifi2G.BasicEncryptionModes != WlanWifi5G.BasicEncryptionModes)) {
                    return false;
                }
            } else if (WlanWifi2G.BeaconType == 'WPA') {
                if ((WlanWifi2G.WPAAuthenticationMode != WlanWifi5G.WPAAuthenticationMode)
                    || (WlanWifi2G.WPAEncryptionModes != WlanWifi5G.WPAEncryptionModes)) {
                    return false;
                }
            } else if ((WlanWifi2G.BeaconType == '11i') || (WlanWifi2G.BeaconType == 'WPA2')) {
                if (WlanWifi2G.IEEE11iAuthenticationMode != WlanWifi5G.IEEE11iAuthenticationMode
                    || WlanWifi2G.IEEE11iEncryptionModes != WlanWifi5G.IEEE11iEncryptionModes) {
                    return false;
                }
            } else if ((WlanWifi2G.BeaconType == 'WPAand11i') || (WlanWifi2G.BeaconType == 'WPA/WPA2') ||
                (WlanWifi2G.BeaconType == 'WPA3') || (WlanWifi2G.BeaconType == 'WPA2/WPA3')) {
                if (WlanWifi2G.X_HW_WPAand11iAuthenticationMode != WlanWifi5G.X_HW_WPAand11iAuthenticationMode
                    || WlanWifi2G.X_HW_WPAand11iEncryptionModes != WlanWifi5G.X_HW_WPAand11iEncryptionModes) {
                    return false;
                }
            }

            return true;
        }

        var Is2gPasswdSet = true;
        function Is2gWifiPasswdSet() 
        {
            var wifi2G;
            var wifi5G;
            for (var i = 0; i < Wlan.length; i++) {
                if (getInstIdByDomain(Wlan[i].domain) == 1) {
                    wifi2G = Wlan[i];
                }
            }

            if ((wifi2G.BeaconType == 'Basic') || (wifi2G.BeaconType == 'None')) {
                Is2gPasswdSet = false;
            } else if (wifi2G.BeaconType == 'WPA') {
                if (wifi2G.WPAAuthenticationMode == 'EAPAuthentication') {
                    Is2gPasswdSet = false;
                }
            } else if ((wifi2G.BeaconType == '11i') || (wifi2G.BeaconType == 'WPA2')) {
                if (wifi2G.IEEE11iAuthenticationMode == 'EAPAuthentication') {
                    Is2gPasswdSet = false;
                }
            } else if ((wifi2G.BeaconType == 'WPAand11i') || (wifi2G.BeaconType == 'WPA/WPA2') ||
                (wifi2G.BeaconType == 'WPA3') || (wifi2G.BeaconType == 'WPA2/WPA3')) {
                if (wifi2G.X_HW_WPAand11iAuthenticationMode == 'EAPAuthentication') {
                    Is2gPasswdSet = false;
                }
            }
        }

        var Is5gPasswdSet = true;
        function Is5gWifiPasswdSet() 
        {
            var wifi5G;
            for (var i = 0; i < Wlan.length; i++) {
                if (getInstIdByDomain(Wlan[i].domain) == parseInt(ssidStart5G) + 1) {
                    wifi5G = Wlan[i];
                }
            }

            if ((wifi5G.BeaconType == 'Basic') || (wifi5G.BeaconType == 'None')) {
                Is5gPasswdSet = false;
            } else if (wifi5G.BeaconType == 'WPA') {
                if (wifi5G.WPAAuthenticationMode == 'EAPAuthentication') {
                    Is5gPasswdSet = false;
                }
            } else if ((wifi5G.BeaconType == '11i') || (wifi5G.BeaconType == 'WPA2')) {
                if (wifi5G.IEEE11iAuthenticationMode == 'EAPAuthentication') {
                    Is5gPasswdSet = false;
                }
            } else if ((wifi5G.BeaconType == 'WPAand11i') || (wifi5G.BeaconType == 'WPA/WPA2') ||
                (wifi5G.BeaconType == 'WPA3') || (wifi5G.BeaconType == 'WPA2/WPA3')) {
                if (wifi5G.X_HW_WPAand11iAuthenticationMode == 'EAPAuthentication') {
                    Is5gPasswdSet = false;
                }
            }
        }

        function LoadFrame() {
            if (IsWlanSameSsid()) {
                setRadio('bandsteering', 1);
            } else {
                setRadio('bandsteering', 0);
            }
            Is2gWifiPasswdSet();
            Is5gWifiPasswdSet();
            setText("name2g", ssid1);
            setText("name5g", ssid2);

            for (var i = 0; i < wpaPskKey.length - 1; i++) {
                var curWlanInst = getWlanInstFromDomain(wpaPskKey[i].domain);
                if (curWlanInst == "1") {
                    setText("pwd_wifipw", wpaPskKey[i].value);
                    setText("txt_wifipw", wpaPskKey[i].value);
                    if (Is2gPasswdSet) {
                        setDisable("pwd_wifipw", 0);
                        setDisable("txt_wifipw", 0);
                        setDisable("cb_2g_pwd", 0);
                    } else {
                        setDisable("pwd_wifipw", 1);
                        setDisable("txt_wifipw", 1);
                        setDisable("cb_2g_pwd", 1);
                    }
                }
                if (curWlanInst == "5") {
                    setText("pwd_wifipw_5G", wpaPskKey[i].value);
                    setText("txt_wifipw_5G", wpaPskKey[i].value);
                    if (Is5gPasswdSet) {
                        setDisable("pwd_wifipw_5G", 0);
                        setDisable("txt_wifipw_5G", 0);
                        setDisable("cb_5g_pwd", 0);
                    } else {
                        setDisable("pwd_wifipw_5G", 1);
                        setDisable("txt_wifipw_5G", 1);
                        setDisable("cb_5g_pwd", 1);
                    }
                }
            }

            BandSteeringChange();

            if (wifiPasswordMask == 1) {
                setDisplay('cb_2g_pwd', 0);
                setDisplay('hidetext_2g', 0);
                setDisplay('cb_5g_pwd', 0);
                setDisplay('hidetext_5g', 0);
            } else {
                setDisplay('cb_2g_pwd', 1);
                setDisplay('hidetext_2g', 1);
                setDisplay('cb_5g_pwd', 1);
                setDisplay('hidetext_5g', 1);
            }

            setDisplay("pwd_wifipw", 1);
            setDisplay("txt_wifipw", 0);
            setCheck('cb_2g_pwd', 1);

            setDisplay("pwd_wifipw_5G", 1);
            setDisplay("txt_wifipw_5G", 0);
            setCheck('cb_5g_pwd', 1);
        }

        function ResetWpaPskKey() {
            for (var i = 0; i < wpaPskKey.length - 1; i++) {
                var curWlanInst = getWlanInstFromDomain(wpaPskKey[i].domain);
                if (curWlanInst == "1") {
                    setText("pwd_wifipw", wpaPskKey[i].value);
                    setText("txt_wifipw", wpaPskKey[i].value);
                }
                if (curWlanInst == "5") {
                    setText("pwd_wifipw_5G", wpaPskKey[i].value);
                    setText("txt_wifipw_5G", wpaPskKey[i].value);
                }
            }
        }

        function DevideSsidInit()
        {
            if (ssid1 == ssid2) {
                tmpSsid1 = ssid1 + "_2.4G";
                tmpSsid2 = ssid2 + "_5G";
                if (ssid1.length > 27) {
                    tmpSsid1 = ssid1.substring(0, 27) + "_2.4G";
                }
                if (ssid2.length > 29) {
                    tmpSsid2 = ssid1.substring(0, 29) + "_5G";
                }
                setText('name2g', tmpSsid1);
                setText('name5g', tmpSsid2);
            } else {
                setText('name2g', ssid1);
                setText('name5g', ssid2);
            }
        }

        function BandSteeringChange() {
            if (getRadioVal('bandsteering') == '1') {
                setDisplay('ssid2g', 0);
                setDisplay('ssid5g', 0);
                setDisplay('ssidname5g', 0);
                setDisplay('ssidpwd5g', 0);
                setText('name2g', ssid1);
                setText('name5g', ssid2);
                ResetWpaPskKey();
            } else {
                setDisplay('ssid2g', 1);
                setDisplay('ssid5g', 1);
                setDisplay('ssidname5g', 1);
                setDisplay('ssidpwd5g', 1);
                if (ssid1 == ssid2) {
                    DevideSsidInit();
                } else {
                    setText('name2g', ssid1);
                    setText('name5g', ssid2);
                }
                ResetWpaPskKey();
            }
        }

        function CheckSsid(ssid, freq) {
            if (freq == '2G') {
                curSsidIdx = 0;
            } else {
                curSsidIdx = 4
            }
            ssid = ltrim(ssid);
            if (ssid == '') {
                AlertEx(cfg_wlancfgother_language['amp_empty_ssid']);
                return false;
            }

            if (ssid.length > 32) {
                AlertEx(cfg_wlancfgother_language['amp_ssid_check1'] + ssid + cfg_wlancfgother_language['amp_ssid_too_loog']);
                return false;
            }
            if (curLanguage.toUpperCase() != "CHINESE") {
                if (isValidAscii(ssid) != '') {
                    AlertEx(cfg_wlancfgother_language['amp_ssid_check1'] + ssid + cfg_wlancfgother_language['amp_ssid_invalid'] + isValidAscii(ssid));
                    return false;
                }
            } else {
                if (GetChineseNumLength(ssid) > 32) {
                    AlertEx(cfg_wlancfgother_language['amp_ssid_check1'] + ssid + cfg_wlancfgother_language['amp_ssid_too_loog']);
                    return false;
                }
            }

            for (i = 0; i < Wlan.length; i++) {
                if ((getWlanPortNumber(Wlan[i].name) > 3) && ((1 == DoubleFreqFlag) && ('2G' == freq))) {
                    continue;
                }
                
                if ((getWlanPortNumber(Wlan[i].name) <= 3) && ((1 == DoubleFreqFlag) && ('5G' == freq))) {
                    continue;
                }

                if ((getWlanPortNumber(Wlan[i].name) > 3) && (1 != DoubleFreqFlag)) {
                    continue;
                }
                
                if (curSsidIdx != i) {
                    if (Wlan[i].ssid == ssid) {
                        AlertEx(cfg_wlancfgother_language['amp_ssid_exist']);
                        return false;
                    }
                } else {
                    continue;
                }
            }

            if (checkUnicomSSIDName(ssid, curSsidIdx) != true) {
                return false;
            }
            return true;
        }

        function getWlanPortNumber(name) {
            if (name != '') {
                if (name.length > 4) {
                    return parseInt(name.charAt(name.length - 2) + name.charAt(name.length - 1));
                } else {
                    return parseInt(name.charAt(name.length - 1));
                }
            }
        }

        function ltrim(str) {
            if (trimssidFlag == 0) {
                return str.toString().replace(/(^\s*)/g, "");
            } else {
                return str.toString();
            }
        }

        function CheckWlanSsid(id) {
            var freq = (id == 'name2g') ? '2G' : '5G';
            var ssid = ltrim(getValue(id));
            if (!CheckSsid(ssid, freq)) {
                return false;
            }

            var index = (id == 'name2g') ? 0 : ssidStart5G;

            for (var i = 0; i < WlanInfo.length - 1; i++) {
                if ((getWlanPortNumber(WlanInfo[i].name) > ssidEnd2G) && ((IsDoubleWifi == 1) && (freq == '2G'))) {
                    continue;
                }

                if ((getWlanPortNumber(WlanInfo[i].name) <= ssidEnd2G) && ((IsDoubleWifi == 1) && (freq == '5G'))) {
                    continue;
                }

                if ((getWlanPortNumber(WlanInfo[i].name) > ssidEnd2G) && ((IsDoubleWifi != 1))) {
                    continue;
                }

                if (getWlanPortNumber(WlanInfo[i].name) != index) {
                    if (WlanInfo[i].ssid == ssid) {
                        alert('Duplicate SSID.');
                        return false;
                    }
                }
            }

            return true;
        }

        function CheckPasswordSsid(id) {
            if (!isValidWPAPskKey(getValue(id))) {
                return false;
            }

            return true;
        }

        function CheckWiFiParameter() {
            if ((IsSingleWifi != 1) && (IsDoubleWifi != 1)) {
                return true;
            }

            if (!CheckWlanSsid('name2g')) {
                return false;
            }

            if ((Is2gPasswdSet) && (!CheckPasswordSsid("pwd_wifipw"))) {
                alert("The wifi password of " + getElById('name2g').value + " must be between 8 and 63 characters or 64 hexadecimal characters.");
                return false;
            }

            var enable = getRadioVal('bandsteering');
            if (enable == 0) {
                if (!CheckWlanSsid('name5g')) {
                    return false;
                }

                if ((Is5gPasswdSet) && (!CheckPasswordSsid('pwd_wifipw_5G'))) {
                    alert("The wifi password of " + getElById('name5g').value + " must be between 8 and 63 characters or 64 hexadecimal characters.");
                    return false;
                }
            }

            return true;
        }

        function SubmitBandSteeringInfo() {
            if (!CheckWiFiParameter()) {
                return false;
            }
            var Form = new webSubmitForm();
            var url = 'set.cgi';
            var enable = getRadioVal('bandsteering');
            var wpakeyUrl2G = '';
            var wpakeyUrl5G = '';
            if (enable == 1) {
                if (((wifiPasswordMask != 1) || (getValue('pwd_wifipw') != '********')) && ((Is2gPasswdSet) && (Is5gPasswdSet))) {
                    Form.addParameter('x.PreSharedKey', getValue('pwd_wifipw'));
                    Form.addParameter('y.PreSharedKey', getValue('pwd_wifipw'));
                    wpakeyUrl2G += '&x=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1';
                    wpakeyUrl5G += '&y=InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1';
                }

                Form.addParameter('m.SSID', ltrim(getValue('name2g')));
                Form.addParameter('n.SSID', ltrim(getValue('name2g')));
            } else {
                if (((wifiPasswordMask != 1) || (getValue('pwd_wifipw') != '********')) && (Is2gPasswdSet)) {
                    Form.addParameter('x.PreSharedKey', getValue('pwd_wifipw'));
                    wpakeyUrl2G += '&x=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1';
                }

                if (((wifiPasswordMask != 1) || (getValue('pwd_wifipw_5G') != '********')) && (Is5gPasswdSet)) {
                    Form.addParameter('y.PreSharedKey', getValue('pwd_wifipw_5G'));
                    wpakeyUrl5G += '&y=InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey.1';
                }

                Form.addParameter('m.SSID', ltrim(getValue('name2g')));
                Form.addParameter('n.SSID', ltrim(getValue('name5g')));
            }

            Form.setAction(url
                + '?m=InternetGatewayDevice.LANDevice.1.WLANConfiguration.1'
                + '&n=InternetGatewayDevice.LANDevice.1.WLANConfiguration.5'
                + wpakeyUrl2G + wpakeyUrl5G
                + '&RequestFile=html/amp/wlanbasic/bandsteering_unicom.asp');

            Form.addParameter('x.X_HW_Token', getValue('onttoken'));
            setDisable('applyButton', 1);
            setDisable('cancelButton', 1);
            Form.submit();
        }

        function CancelConfig() {
            LoadFrame();
        }

        function showPwd(id) {
            var pwdId = "pwd_wifipw" + id;
            var txtId = "txt_wifipw" + id;

            if (getElById(pwdId).style.display == "none") {
                setDisplay(pwdId, 1);
                setDisplay(txtId, 0);
            } else {
                setDisplay(pwdId, 0);
                setDisplay(txtId, 1);
            }
        }
    </script>
</head>

<body class="mainbody" onLoad="LoadFrame();">

    <script language="JavaScript" type="text/javascript">
        HWCreatePageHeadInfo("", "", cfg_wlan_bsd_language['amp_bsd_config_header'], false);
    </script>

    <div class="title_spread"></div>
    <table id="BandsteeringForm" width="100%" cellpadding="0" cellspacing="1" class="tabal_noborder_bg">
        <tr>
            <td class="table_title width_per30" style="font-weight:bold"><script>document.write(cfg_wlan_bsd_language['amp_bsd_config_bandsteering']);</script></td>
            <td class="table_right width_per70">
                <input name="bandsteering" id="bandenable" type="radio" value="1"
                    onclick="BandSteeringChange(this);"><script>document.write(cfg_wlan_bsd_language['amp_bsd_config_enabled']);</script></input>
                <input name="bandsteering" id="banddisable" type="radio" value="0"
                    onclick="BandSteeringChange(this);"><script>document.write(cfg_wlan_bsd_language['amp_bsd_config_disabled']);</script></input>
            </td>
        </tr>

        <tr class="head_title" id="ssid2g">
            <td class="block_title" colspan="2" style="padding-left:5px;">2.4G SSID</td>
        </tr>

        <tr id="ssidname2g">
            <td class="table_title width_per30"><script>document.write(cfg_wlancfgbasic_language['amp_ssid_name']);</script>:</td>
            <td class="table_right width_per70">
                <input id="name2g" type="text" class="TextBox" maxlength="32">
                <font color="red">*</font>
                <span class="gray"><script>document.write(cfg_wlancfgdetail_language['amp_linkname_note']);</script></span>
            </td>
        </tr>

        <tr id="ssidpwd2g">
            <td class="table_title width_per30" id="wds_Ap3_BSSIDColleft" BindText="amp_wds_address_ap3"><script>document.write(cfg_wlancfgdetail_language['amp_wpa_psk']);</script></td>
            <td id="wds_Ap3_BSSIDCol" class="table_right width_per70">
                <input type="password" autocomplete="off" name="pwd_wifipw" id="pwd_wifipw" class="textboxbg"
                    onchange="pwd=getValue('pwd_wifipw');getElById('txt_wifipw').value = pwd;">
                <input type="text" autocomplete="off" name="txt_wifipw" id="txt_wifipw" class="textboxbg"
                    style="display:none;" onchange="pwd=getValue('txt_wifipw');getElById('pwd_wifipw').value = pwd;">
                <input id="cb_2g_pwd" type="checkbox" checked="true" onClick="showPwd('');" />
                <span id="hidetext_2g" class="gray" style="font-size: 14px;"><script>document.write(cfg_wlancfgdetail_language['amp_wlanpassword_hide']);</script></span>
                <font class="color_red" id="hidewlWpaPsk_icon">*</font>
                <span class="gray" id="hidewlWpaPsk_note"><script>document.write(cfg_wlancfgdetail_language['amp_wpa_psknote']);</script></span>
            </td>
        </tr>

        <tr class="head_title" id="ssid5g">
            <td class="block_title" colspan="2" style="padding-left:5px;">5G SSID</td>
        </tr>

        <tr id="ssidname5g">
            <td class="table_title width_per30"><script>document.write(cfg_wlancfgbasic_language['amp_ssid_name']);</script>:</td>
            <td class="table_right width_per70">
                <input id="name5g" type="text" class="TextBox" maxlength="32">
                <font color="red">*</font>
                <span class="gray"><script>document.write(cfg_wlancfgdetail_language['amp_linkname_note']);</script></span>
            </td>
        </tr>

        <tr id="ssidpwd5g">
            <td class="table_title width_per30"><script>document.write(cfg_wlancfgdetail_language['amp_wpa_psk']);</script></td>
            <td class="table_right width_per70">
                <input type="password" autocomplete="off" name="pwd_wifipw_5G" id="pwd_wifipw_5G" class="textboxbg"
                    onchange="pwd=getValue('pwd_wifipw_5G');getElById('txt_wifipw_5G').value = pwd;">
                <input type="text" autocomplete="off" name="txt_wifipw_5G" id="txt_wifipw_5G" class="textboxbg"
                    style="display:none;"
                    onchange="pwd=getValue('txt_wifipw_5G');getElById('pwd_wifipw_5G').value = pwd;">
                <input id="cb_5g_pwd" type="checkbox" checked="true" onClick="showPwd('_5G');" />
                <span id="hidetext_5g" class="gray" style="font-size: 14px;"><script>document.write(cfg_wlancfgdetail_language['amp_wlanpassword_hide']);</script></script></span>
                <font class="color_red" id="hidewlWpaPsk_icon">*</font>
                <span class="gray" id="hidewlWpaPsk_note"><script>document.write(cfg_wlancfgdetail_language['amp_wpa_psknote']);</script></span>
            </td>
        </tr>

    </table>

    <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table_button">
        <tr>
            <td class="table_submit width_per25"></td>
            <td class="table_submit">
                <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                <button id="applyButton" name="applyButton" type="button" class="ApplyButtoncss buttonwidth_100px"
                    onClick="SubmitBandSteeringInfo();">
                    <script>document.write(cfg_wlancfgother_language['amp_wlancfg_apply']);</script>
                </button>
                <button id="cancelButton" name="cancelButton" type="button" class="CancleButtonCss buttonwidth_100px"
                    onClick="CancelConfig();">
                    <script>document.write(cfg_wlancfgother_language['amp_wlancfg_cancel']);</script>
                </button>
            </td>
        </tr>
    </table>
</body>

</html>