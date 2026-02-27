<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Pragma" content="no-cache" />
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
    <link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css" />
    <link rel="stylesheet" href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
    <script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
    <script language="javascript" src="../common/wan_list_info.asp"></script>
    <script language="javascript" src="../common/wan_list.asp"></script>
    <script language="javascript" src="../common/wan_check.asp"></script>
    <script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
    <script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>

    <script language="JavaScript" type="text/javascript">

        var defaultRequstedStatus = 'Requested';
        var defaultAutoStatus = 'Auto';
        var defaultStopStatus = 'Stop';
        var defaultNoneStatus = 'None';
        var defaultPort = '80,443';
        var defaultTimeout = '60';
        var portMin = 1;
        var portMax = 65535;
        var timeoutMin = 30;
        var timeoutMax = 120;
        var defaultDuration = '1440';
        var durationMin = 1;
        var durationMax = 10080;
        var defaultInterval = '10';
        var intervalMin = 1;
        var intervalMax = 10080;
        var protocolType_IPv4 = 'IPv4';
        var protocolType_IPv6 = 'IPv6';
        var protocolType_IPv4_IPv6 = 'IPv4_IPv6';
        var resultFlag = '[@#@]';
        var resultNone = 'NONE';

        var timerHandle = null;
        var diagnoseType = '';
        var diagnoseText = '';

        var curBinMode = '<%HW_WEB_GetBinMode();%>';
        var curCfgMode = '<%HW_WEB_GetCfgMode();%>';

        function Loadlanguage() {
            var all = document.getElementsByTagName("td");
            for (var i = 0; i < all.length; i++) {
                var b = all[i];
                if (b.getAttribute("BindText") == null) {
                    continue;
                }
                setObjNoEncodeInnerHtmlValue(b, diagnose_language[b.getAttribute("BindText")]);
            }
        }

        function NetworkResultClass(domain, DiagnosticsState, Interface, DomainList, AutoDiagTime, AutoDiagInterval, Protocol, Port, Timeout) {
            this.domain = domain;
            this.DiagnosticsState = DiagnosticsState;
            this.Interface = Interface;
            this.DomainList = DomainList;
            this.AutoDiagTime = AutoDiagTime;
            this.AutoDiagInterval = AutoDiagInterval;
            this.Protocol = Protocol;
            this.Port = Port;
            this.Timeout = Timeout;
        }

        var networkResultList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_InternetDiagnose,DiagnosticsState|Interface|DomainList|AutoDiagTime|AutoDiagInterval|Protocol|Port|Timeout, NetworkResultClass);%>;
        var networkResult = networkResultList[0];

        function CheckDomainList() {
            var domainList = getValue("domainList");
            if (domainList != '') {
                var domain = domainList.split(",");
                for (var i = 0; i < domain.length; i++) {
                    if (domain[i] == '') {
                        return false;
                    }
                    if (!CheckIpOrDomainIsValid(domain[i])) {
                        return false;
                    }
                }
            }

            return true;
        }

        function CheckPortList() {
            var portList = getValue("port");
            if (portList != '') {
                var port = portList.split(",");
                for (var i = 0; i < port.length; i++) {
                    if (port[i] == '') {
                        return false;
                    }
                    if (CheckNumber(port[i], portMin, portMax) == false) {
                        return false;
                    }
                }
            }

            return true;
        }

        function CheckForm() {
            if (!CheckDomainList()) {
                AlertEx(diagnose_network_language['diagnose_net_domain_invalid']);
                return false;
            }

            if (!CheckPortList()) {
                AlertEx(diagnose_network_language['diagnose_net_port_invalid']);
                return false;
            }

            if (getRadioVal("checkMode") == '0') {
                if (CheckNumber(getValue("maxTimeout"), timeoutMin, timeoutMax) == false) {
                    AlertEx(diagnose_network_language['diagnose_net_timeout_invalid']);
                    return false;
                }
            } else {
                if (CheckNumber(getValue("duration"), durationMin, durationMax) == false) {
                    AlertEx(diagnose_network_language['diagnose_net_duration_invalid']);
                    return false;
                }

                if (CheckNumber(getValue("interval"), intervalMin, intervalMax) == false) {
                    AlertEx(diagnose_network_language['diagnose_net_interval_invalid']);
                    return false;
                }
            }
            return true;
        }

        function OnApply() {
            if (CheckForm() == false) {
                return;
            }

            setDisable('ButtonApply', 1);
            var Form = new webSubmitForm();

            Form.addParameter('x.DomainList', getValue("domainList"));
            Form.addParameter('x.Interface', getSelectVal("wanNameList"));
            Form.addParameter('x.Protocol', getSelectVal("protocolType"));

            var port = getValue("port");
            if (port == '') {
                port = defaultPort;
            }
            Form.addParameter('x.Port', port);

            if (getRadioVal("checkMode") == '0') {
                Form.addParameter('x.DiagnosticsState', defaultRequstedStatus);

                var maxTimeout = getValue("maxTimeout");
                if (maxTimeout == '') {
                    maxTimeout = defaultTimeout;
                }
                Form.addParameter('x.Timeout', maxTimeout);
            } else {
                Form.addParameter('x.DiagnosticsState', defaultAutoStatus);
                Form.addParameter('x.AutoDiagTime', getValue("duration"));
                Form.addParameter('x.AutoDiagInterval', getValue("interval"));
            }

            Form.addParameter('x.X_HW_Token', getValue('onttoken'));
            Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_InternetDiagnose&RequestFile=html/bbsp/maintenance/diagnoseNetwork.asp');
            Form.submit();
        }

        function OnStopPing() {
            if ((networkResult.DiagnosticsState != defaultAutoStatus) && networkResult.DiagnosticsState != defaultRequstedStatus) {
                return;
            }

            var Form = new webSubmitForm();

            Form.addParameter('x.DomainList', '');
            Form.addParameter('x.Interface', '');
            Form.addParameter('x.Protocol', '');
            Form.addParameter('x.Port', defaultPort);
            Form.addParameter('x.DiagnosticsState', defaultStopStatus);
            Form.addParameter('x.Timeout', defaultTimeout);
            Form.addParameter('x.AutoDiagTime', defaultDuration);
            Form.addParameter('x.AutoDiagInterval', defaultInterval);

            Form.addParameter('x.X_HW_Token', getValue('onttoken'));
            Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_InternetDiagnose&RequestFile=html/bbsp/maintenance/diagnoseNetwork.asp');
            Form.submit();
        }

        function SetDiagnosing() {
            setDisable('ButtonApply', 1);
            getElement("DiagnoseResultArea").value = diagnose_network_language['diagnose_net_wait_tip'];
            setDisplay("DiagnoseResultDiv", 1);
            GetInternetDiagnose();
            if (timerHandle == null) {
                timerHandle = setInterval("GetInternetDiagnose()", 10000);
            }
        }

        function ShowDiagnoseResult() {
            setDisplay("DiagnoseResultDiv", 1);
            GetInternetDiagnoseResult();
            getElement("DiagnoseResultArea").value = diagnoseText;
        }

        function IsDiagnoseStatusIdel() {
            if ((networkResult.DiagnosticsState == defaultNoneStatus) || (networkResult.DiagnosticsState == defaultStopStatus)) {
                return true;
            }
            return false;
        }

        function IsDiagnoseStatusBusy() {
            if ((networkResult.DiagnosticsState == defaultAutoStatus) || (networkResult.DiagnosticsState == defaultRequstedStatus)) {
                return true;
            }
            return false;
        }

        function LoadControl() {
            InitWanList();

            var modeVal = '0';
            if (networkResult.DiagnosticsState == defaultAutoStatus) {
                modeVal = '1';
                SetDiagnosing();
            } else if (networkResult.DiagnosticsState == defaultRequstedStatus) {
                SetDiagnosing();
            } else if (!IsDiagnoseStatusIdel()) {
                ShowDiagnoseResult();
                if (diagnoseType == defaultAutoStatus) {
                    modeVal = '1';
                }
            }
            setRadio('checkMode', modeVal);
            OnCheckMode();

            setSelect("wanNameList", networkResult.Interface);
            OnWanName();
            if (networkResult.Protocol != '') {
                setSelect("protocolType", networkResult.Protocol);
            }

            setText("domainList", networkResult.DomainList);

            var port = networkResult.Port;
            if (port == '') {
                port = defaultPort;
            }
            setText("port", port);

            var timeout = networkResult.Timeout;
            if (timeout == '') {
                timeout = defaultTimeout;
            }
            setText("maxTimeout", timeout);

            var autoDiagTime = networkResult.AutoDiagTime;
            if (autoDiagTime == '') {
                autoDiagTime = defaultDuration;
            }
            setText("duration", autoDiagTime);

            var autoDiagInterval = networkResult.AutoDiagInterval;
            if (autoDiagInterval == '') {
                autoDiagInterval = defaultInterval;
            }
            setText("interval", autoDiagInterval);
        }

        function LoadFrame() {
            Loadlanguage();
            LoadControl();
        }

        function IsValidWan(Wan) {
            if ((Wan.Mode == "IP_Routed") && (Wan.Enable == 1)) {
                return true;
            }
            return false;
        }

        function InitWanList() {
            var Option = document.createElement("Option");
            Option.value = "";
            Option.innerText = "";
            Option.text = "";
            getElById("wanNameList").appendChild(Option);

            InitWanNameListControl2("wanNameList", IsValidWan);
        }

        function OnCheckMode() {
            var mode = getRadioVal("checkMode");
            if (mode == '0') {
                setDisplay("maxTimeoutRow", 1);
                setDisplay("durationRow", 0);
                setDisplay("intervalRow", 0);
                if (!IsDiagnoseStatusIdel()) {
                    if (diagnoseType != defaultAutoStatus) {
                        setDisplay("DiagnoseResultDiv", 1);
                    } else {
                        setDisplay("DiagnoseResultDiv", 0);
                    }
                }

            } else {
                setDisplay("maxTimeoutRow", 0);
                setDisplay("durationRow", 1);
                setDisplay("intervalRow", 1);
                if (!IsDiagnoseStatusIdel()) {
                    if (diagnoseType != defaultAutoStatus) {
                        setDisplay("DiagnoseResultDiv", 0);
                    } else {
                        setDisplay("DiagnoseResultDiv", 1);
                    }
                }
            }
        }

        function OnWanName() {
            var curProtocolType = GetWanProtocolType();
            if (curProtocolType == protocolType_IPv4_IPv6) {
                setDisable("protocolType", 0);
                setSelect("protocolType", 'IPv4');
            } else if (curProtocolType == protocolType_IPv4) {
                setSelect("protocolType", 'IPv4');
                setDisable("protocolType", 1);
            } else {
                setSelect("protocolType", 'IPv6');
                setDisable("protocolType", 1);
            }
            return;
        }

        function GetWanProtocolType() {
            var wanName = getSelectVal("wanNameList");
            if (wanName == "") {
                return protocolType_IPv4_IPv6;
            }

            var wanList = GetWanList();
            for (i = 0; i < wanList.length; i++) {
                var curWan = wanList[i];
                if (wanName != curWan.domain) {
                    continue;
                }
                if ((curWan.IPv4Enable == "1") && (curWan.IPv6Enable == "1")) {
                    return protocolType_IPv4_IPv6;
                } else if (curWan.IPv6Enable == "1") {
                    return protocolType_IPv6;
                }
                return protocolType_IPv4;
            }
            return protocolType_IPv4;
        }

        function UpdateInternetDiagnoseStatus() {
            $.ajax({
                type: "POST",
                async: false,
                cache: false,
                url: "./GetInternetDiagnoseStatus.asp",
                success: function (data) {
                    networkResult.DiagnosticsState = data;
                },
                complete: function (XHR, TS) {
                    XHR = null;
                }
            });
        }

        function GetInternetDiagnoseResult() {
            var resultContent = "";
            $.ajax({
                type: "POST",
                async: false,
                cache: false,
                url: "./GetInternetDiagnoseResult.asp",
                success: function (data) {
                    resultContent = eval(data);
                    ParseDiagnoseResult(resultContent);
                },
                complete: function (XHR, TS) {
                    resultContent = null;
                    XHR = null;
                }
            });
        }

        function ParseDiagnoseResult(resultContent) {
            var subString = resultContent.split(resultFlag);
            if (subString.length == 2) {
                diagnoseType = subString[0];
                diagnoseText = subString[1];
                return;
            }

            diagnoseType = resultNone;
            diagnoseText = '';
            return;
        }

        function GetInternetDiagnose() {
            UpdateInternetDiagnoseStatus();
            GetInternetDiagnoseResult()

            if ((networkResult.DiagnosticsState == defaultRequstedStatus) || (networkResult.DiagnosticsState == defaultAutoStatus)) {
                if (timerHandle == null) {
                    timerHandle = setInterval("GetInternetDiagnose()", 10000);
                }
            } else {
                setDisable('ButtonApply', 0);
                setDisplay("DiagnoseResultDiv", 1);
                getElement("DiagnoseResultArea").value = diagnoseText;
                if (timerHandle != null) {
                    clearInterval(timerHandle);
                }
            }
        }

    </script>
    <title>Diagnose Network Configuration</title>
</head>

<body class="mainbody pageBg" onLoad="LoadFrame();">
    <form></form>
    <div id="ThirdPlayerPanel">
        <script language="JavaScript" type="text/javascript">
            var path = "diagnose_net_desc_path_cu";
            if (curBinMode.toUpperCase() == 'CMCC') {
                path = "diagnose_net_desc_path_cmcc";
            } else if (curBinMode.toUpperCase() == 'E8C') {
                path = "diagnose_net_desc_path_e8c";
            } else if ((curCfgMode.toUpperCase() == 'BJCU') || (curCfgMode.toUpperCase() == 'BJUNICOM')) {
                path = "iagnose_net_desc_path_bjcu";
            }
            var desc = diagnose_network_language['diagnose_net_desc_head'] + diagnose_network_language[path] + diagnose_network_language['diagnose_net_desc_tail'];
            HWCreatePageHeadInfo("diagnosenettitle", GetDescFormArrayById(diagnose_network_language, "diagnose_net_head"), desc, false);
        </script>
        <div class="title_spread"></div>

        <form id="table_network">
            <table border="0" cellpadding="0" cellspacing="1" width="100%" class="tabal_noborder_bg">
                <li id="checkMode" RealType="RadioButtonList" DescRef="diagnose_net_checkmode" RemarkRef="Empty"
                    ErrorMsgRef="Empty" Require="FALSE" BindField=""
                    InitValue="[{TextRef:'diagnose_net_checkmode_once',Value:'0'},{TextRef:'diagnose_net_checkmode_auto',Value:'1'}]"
                    ClickFuncApp="onclick=OnCheckMode" />
                <li id="domainList" RealType="TextBox" DescRef="diagnose_net_domain"
                    RemarkRef="diagnose_net_domain_remark" ErrorMsgRef="Empty" Require="FALSE" BindField="x.Host"
                    InitValue="Empty" MaxLength="2048" />
                <li id="wanNameList" RealType="DropDownList" DescRef="diagnose_net_wanname" RemarkRef="Empty"
                    ErrorMsgRef="Empty" Require="FALSE" BindField="Empty" InitValue="Empty"
                    ClickFuncApp="onclick=OnWanName" />
                <li id="protocolType" RealType="DropDownList" DescRef="diagnose_net_protocol_type" RemarkRef="Empty"
                    ErrorMsgRef="Empty" Require="FALSE" BindField="Empty"
                    InitValue="[{TextRef:'diagnose_net_protocol_ipv4',Value:'IPv4'},{TextRef:'diagnose_net_protocol_ipv6',Value:'IPv6'}]" />
                <li id="port" RealType="TextBox" DescRef="diagnose_net_port" RemarkRef="diagnose_net_port_remark"
                    ErrorMsgRef="Empty" Require="FALSE" BindField="x.Host" InitValue="Empty" MaxLength="256" />
                <li id="maxTimeout" RealType="TextBox" DescRef="diagnose_net_maxtimeout"
                    RemarkRef="diagnose_net_maxtimeoutt_remark" ErrorMsgRef="Empty" Require="FALSE"
                    BindField="x.Timeout" InitValue="Empty" />
                <li id="duration" RealType="TextBox" DescRef="diagnose_net_duration"
                    RemarkRef="diagnose_net_duration_remark" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Timeout"
                    InitValue="Empty" />
                <li id="interval" RealType="TextBox" DescRef="diagnose_net_interval"
                    RemarkRef="diagnose_net_interva_remark" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Timeout"
                    InitValue="Empty" />
            </table>
            <script>
                var TableClass = new stTableClass("width_per25", "width_per75", "ltr");
                var diagnoseNetworkFormList = HWGetLiIdListByForm("table_network", null);
                HWParsePageControlByID("table_network", TableClass, diagnose_network_language, null);
            </script>
            <table id="OperatorPanel" class="table_button" style="width: 100%;">
                <tr>
                    <td class="table_submit width_per25"></td>
                    <td class="table_submit width_per75">
                        <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                        <button id="ButtonApply" type="button" onclick="javascript: OnApply();"
                            class="ApplyButtoncss buttonwidth_100px">
                            <script>document.write(diagnose_network_language['diagnose_net_start']);</script>
                        </button>
                        <button id="ButtonStopPing" type="button" onclick="javascript: OnStopPing();"
                            class="CancleButtonCss buttonwidth_100px">
                            <script>document.write(diagnose_network_language['diagnose_net_stop']);</script>
                        </button>
                    </td>
                </tr>
            </table>

            <div class="func_spread"></div>

            <div id="DiagnoseResultDiv" style="display:none;">
                <textarea name="DiagnoseResultArea" id="PingResultArea" wrap="off" readonly="readonly"
                    style="width: 100%;height: 300px;margin-top: 10px;">
                </textarea>
            </div>

        </form>
    </div>
</body>

</html>