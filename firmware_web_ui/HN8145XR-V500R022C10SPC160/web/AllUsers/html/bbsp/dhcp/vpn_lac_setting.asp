<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<title>L2TPLACQOPTION</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>

<script language="JavaScript" type="text/javascript">

var appName = navigator.appName;
var L2TPAddFlag = false;
var selctOptionIndex = -1;
var l2tptypename = null;

function loadlanguage() {
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++) {
        var b = all[i];
        if (b.getAttribute("BindText") == null) {
            continue;
        }
        b.innerHTML = vpn_l2tp_lac_setting_language[b.getAttribute("BindText")];
    }
}

function stVPN_L2TP_LAC(domain, Enable, LNSAddress, LNSPort, LocalHostName, WANInterface) {
    this.domain = domain;
    this.Enable = Enable;
    this.LNSAddress = LNSAddress;
    this.LNSPort = LNSPort;
    this.LocalHostName = LocalHostName;
    this.WANInterface = WANInterface;
}

var MASK = '********************************';
function stVPN_L2TP_PPPCONFIG(domain, AuthenticationProtocol, UserName) {
    this.domain = domain;
    this.AuthenticationProtocol = AuthenticationProtocol;
    this.UserName = UserName;
    this.Password = MASK;
}

var VPN_L2TP_LAC = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLAC.{i}, Enable|LNSAddress|LNSPort|LocalHostName|WANInterface, stVPN_L2TP_LAC);%>;

var VPN_L2TP_PPPCONFIG = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLAC.{i}.PPPCONFIG.{i}, AuthenticationProtocol|UserName, stVPN_L2TP_PPPCONFIG);%>;

var L2tpLacNum = 0;
var L2tpLacInst = new Array();


for (var i = 0; i < VPN_L2TP_LAC.length - 1; i++) {
    L2tpLacInst[L2tpLacNum++] = VPN_L2TP_LAC[i];
}

function AddSubmitParam(SubmitForm, type) {
    var url;
    var selectObj = getElement('WANInterface');
    var index = 0;
    var idx = 0;

    index = parseInt(selectObj.selectedIndex,10);
    if (index < 0) {
         AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_wan']);
         return false;
    }
    idx = selectObj.options[index].id.split('_')[1];

    SubmitForm.addParameter('x.Enable', getCheckVal("lac_enable"));  
    SubmitForm.addParameter('x.LNSAddress', getElById("lac_LNSAddress").value); 
    SubmitForm.addParameter('x.LNSPort', getElById("lac_LNSPort").value);  
    SubmitForm.addParameter('x.LocalHostName', getElById("lac_LocalHostName").value); 
    SubmitForm.addParameter('x.WANInterface', getSelectVal("WANInterface"));
    SubmitForm.addParameter('y.AuthenticationProtocol', "CHAP");
    SubmitForm.addParameter('y.UserName', getElById("lac_UserName").value);
    var lacPasswd = getElById("lac_Password").value;
    if (lacPasswd !== MASK) {
      SubmitForm.addParameter('y.Password', lacPasswd);
    }

    if (L2TPAddFlag == true) {
        url = 'addcfg.cgi?x=InternetGatewayDevice.X_HW_VPN.L2TPLAC' + '&y=x.PPPCONFIG' +
              '&RequestFile=html/bbsp/dhcp/vpn_lac_setting.asp';
    } else {
        url = 'set.cgi?x=' + VPN_L2TP_LAC[selectedIndex].domain + '&y=' + VPN_L2TP_PPPCONFIG[selectedIndex].domain +
              '&RequestFile=html/bbsp/dhcp/vpn_lac_setting.asp';
    }

    SubmitForm.setAction(url);

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
}

function CheckForm(type) {
    var IpAddress = getElById("lac_LNSAddress").value;
    if ((isAbcIpAddress(IpAddress) == false) || (isDeIpAddress(IpAddress) == true) ||
        (isBroadcastIpAddress(IpAddress) == true) || (isLoopIpAddress(IpAddress) == true)) {
         AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_LNSAddress'] + IpAddress + vpn_l2tp_lac_setting_language['vpn_l2tp_lac_isinvalidp']);
         return false;
    }

    if ((isNum(getElById("lac_LNSPort").value) == false) || 
        (((parseInt(getElById("lac_LNSPort").value,10) >= 1) && (parseInt(getElById("lac_LNSPort").value,10) <= 65535)) == false)) {
        AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_LNSPort'] + getElById("lac_LNSPort").value + 
        vpn_l2tp_lac_setting_language['vpn_l2tp_lac_isinvalidp']);
        return false;
    }

    if (getSelectVal("WANInterface") == "") {
        AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_WANInterface_title'] + vpn_l2tp_lac_setting_language['vpn_l2tp_lac_invalid_wan']);
        return false;
    }

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
    return true;
}

function IsIPv4RouteWan(Wan) {
    if ((Wan.IPv4Enable == "1") && (Wan.Mode =="IP_Routed")) {
        return true;
    } 
    return false;
}

function filterWan(WanItem) {
    if (((WanItem.Tr069Flag == '0') && (Instance_IspWlan.IsWanHidden(domainTowanname(WanItem.domain)) == false)) == false) {
        return false;
    }
    return true;
}

var WanInfo = GetWanListByFilter(filterWan);

function ShowIfName(val) {
    for (var i = 0; i < WanInfo.length; i++) {
        if (WanInfo[i].domain == val) {
            return WanInfo[i].Name;
        } else if ('br0' == val) {
            return 'br0';
        }
    }
    return '&nbsp;';
}

function getWanOfStaticRoute(val) {
    for (var i = 0; i < WanInfo.length; i++) {
        if (WanInfo[i].domain == val) {
            return WanInfo[i];
        }
    }
   return '&nbsp;';
}

function IsValidWan(Wan) {
    if ((Wan.Mode != "IP_Routed") || (Wan.IPv4Enable != '1')) {
        return false;
    }

    if (Wan.Tr069Flag == "1") {
        return false;
    }

    if (Wan.ServiceList.match('INTERNET') == false) {
        return false;
    }

    return true;
}

function InitWanNameListControlWanname(WanListControlId, IsThisWanOkFunction) {
    var Control = getElById(WanListControlId);
    var WanList = GetWanListByFilter(IsThisWanOkFunction);
    var i = 0;

    for (i = 0; i < WanList.length; i++) {
        var Option = document.createElement("Option");
        Option.value = WanList[i].domain;
        Option.innerText = MakeWanName1(WanList[i]);
        Option.text = MakeWanName1(WanList[i]);
        Control.appendChild(Option);
    }
}

function LoadFrame() {
    if (L2tpLacNum == 0) {
        selectLine('record_no');
        setDisplay('ConfigForm', 0);
    } else {
        selectLine('record_0');
        setDisplay('ConfigForm', 0);
    }

    InitWanNameListControlWanname("WANInterface", IsValidWan);

    loadlanguage();
}

function setCtlDisplay(option) {
}

var selectedIndex = -1;

function setControl(index) {
    var option1;
    selctOptionIndex = index;

    if (index == -1) {
        if ((VPN_L2TP_LAC.length - 1) >= 1) {
            AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_invalid_num']);
            return false;
        }
        L2TPAddFlag = true;
        setDisplay('ConfigForm', 1);
        setCheck('lac_enable', 0);
        setText('lac_LNSAddress', "");
        setText('lac_LNSPort', "1701");
        setText('lac_LocalHostName', "");
        setSelect('WANInterface', "");
        setText('lac_UserName', "");
        setText('lac_Password', "");
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        L2TPAddFlag = false;
        setDisplay('ConfigForm', 1);
        option1 = document.getElementById("rml" + index).value;
        for (var i = 0; i < VPN_L2TP_LAC.length - 1 ; i++) {
            if (option1 == VPN_L2TP_LAC[i].domain) {
                setCheck('lac_enable', VPN_L2TP_LAC[i].Enable);

                if (VPN_L2TP_LAC[i].Enable == 0) {
                    setDisable('lac_LNSAddress',1);
                    setDisable('lac_LNSPort',1);
                    setDisable('lac_LocalHostName',1);
                    setDisable('WANInterface',1);
                    setDisable('lac_UserName',1);
                    setDisable('lac_Password',1);
                } else {
                    setDisable('lac_LNSAddress',0);
                    setDisable('lac_LNSPort',0);
                    setDisable('lac_LocalHostName',0);
                    setDisable('WANInterface',0);
                    setDisable('lac_UserName',0);
                    setDisable('lac_Password',0);
                }

                setText('lac_LNSAddress', VPN_L2TP_LAC[i].LNSAddress);
                setText('lac_LNSPort', VPN_L2TP_LAC[i].LNSPort);
                setText('lac_LocalHostName', VPN_L2TP_LAC[i].LocalHostName);
                setSelect('WANInterface', VPN_L2TP_LAC[i].WANInterface);
                setText('lac_UserName', VPN_L2TP_PPPCONFIG[i].UserName);
                setText('lac_Password', VPN_L2TP_PPPCONFIG[i].Password);
                selectedIndex = i;
            }
        }
    }

    setDisable('btnApply1', 0);
    setDisable('cancelValue', 0);
}

function lacEnable() {
    if (getCheckVal("lac_enable") == 0) {
        setDisable('lac_LNSAddress',1);
        setDisable('lac_LNSPort',1);
        setDisable('lac_LocalHostName',1);
        setDisable('WANInterface',1);
        setDisable('lac_UserName',1);
        setDisable('lac_Password',1);
    } else {
        setDisable('lac_LNSAddress',0);
        setDisable('lac_LNSPort',0);
        setDisable('lac_LocalHostName',0);
        setDisable('WANInterface',0);
        setDisable('lac_UserName',0);
        setDisable('lac_Password',0);
    }
}

function selectRemoveCnt(obj) {
}

function clickRemove() {
    if (L2tpLacNum == 0) {
        AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_nooption']);
        return;
    }

    if (selctOptionIndex == -1) {
        AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_nosaveoption']);
        return;
    }

    var rml = getElement('rml');
    var noChooseFlag = true;
    if (rml.length > 0) {
        for (var i = 0; i < rml.length; i++) {
            if (rml[i].checked == true) {
                noChooseFlag = false;
            }
        }
    } else if (rml.checked == true) {
        noChooseFlag = false;
    }

    if (noChooseFlag) {
        AlertEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_selectoption']);
        return ;
    }

    if (ConfirmEx(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_deloption']) == false) {
        document.getElementById("DeleteButton").disabled = false;
        return;
    }

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
    removeInst('html/bbsp/dhcp/vpn_lac_setting.asp');
}

function CancelConfig() {
    setDisplay("ConfigForm", 0);

    if (selctOptionIndex == -1) {
        var tableRow = getElement("l2TPOptionInst");
        if (tableRow.rows.length == 1) {
        } else if (tableRow.rows.length = 2) {
            addNullInst('L2TPLACQOPTION');
        } else {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    } else {
        var optionrecord = L2tpLacInst[selctOptionIndex];
        setCtlDisplay(optionrecord);
    }
}

</script>

</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<form id="CoForm" action="../application/set.cgi"> 
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vpn_l2tp_lac_setting_language, ""), GetDescFormArrayById(vpn_l2tp_lac_setting_language, "vpn_l2tp_lac_title"), false);
</script> 
<div class="title_spread"></div>

<script language="JavaScript" type="text/javascript">
    writeTabCfgHeader('L2TPLACQOPTION','100%');
</script> 
<table class="tabal_bg" id="l2TPOptionInst" width="100%"  cellpadding="0" cellspacing="1"> 
    <tr class="head_title"> 
        <td class="tabal_left width_25p">&nbsp;</td> 
        <td class="tabal_left width_75p" BindText='vpn_l2tp_lac_LNSAddress_title'></td>
        <td class="tabal_left width_75p" BindText='vpn_l2tp_lac_LNSPort_title'></td>
        <td class="tabal_left width_75p" BindText='vpn_l2tp_lac_LocalHostName_title'></td>
        <td class="tabal_left width_75p" BindText='vpn_l2tp_lac_WANInterface_title'></td>
    </tr> 
    <script language="JavaScript" type="text/javascript">
        if (L2tpLacNum == 0) {
            document.write('<TR id="record_no"' +' class="tabal_center01 " onclick="selectLine(this.id);">');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('</TR>');
        } else {
            for (var i = 0; i < L2tpLacNum; i++) {
                document.write('<TR id="record_' + i +'" class="tabal_center01 restrict_dir_ltr" onclick="selectLine(this.id);">');
                document.write('<TD >' + '<input id = "rml'+i+'" type="checkbox" name="rml" value="' + L2tpLacInst[i].domain +'" onclick="selectRemoveCnt(this);">' + '</TD>');
                document.write('<TD >' + L2tpLacInst[i].LNSAddress + '</TD>'); 
                document.write('<TD >' + L2tpLacInst[i].LNSPort + '</TD>'); 
                document.write('<TD >' + L2tpLacInst[i].LocalHostName + '</TD>'); 
                if (L2tpLacInst[i].WANInterface == "") {
                    document.write('<TD >--</TD>');
                } else {
                    document.write('<TD >' + MakeWanName(getWanOfStaticRoute(L2tpLacInst[i].WANInterface)) + '</TD>'); 
                }
                document.write('</TR>');
            }
        }
    </script> 
</table> 
<div id="ConfigForm" style="display:none"> 
    <table cellpadding="0" cellspacing="1" width="100%" class="tabal_bg">
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_enable'></td>
        <td class="table_right"> <input id='lac_enable' type='checkbox' name='lac_enable' onclick="lacEnable();"></td> 
        </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_LNSAddress'></td>
        <td class="table_right"> <input id='lac_LNSAddress' type='text' name='lac_LNSAddress' maxlength='256' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_LNSAddressmh']);</script></span></td> 
        </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_LNSPort'></td>
        <td class="table_right"> <input id='lac_LNSPort' type='text' name='lac_LNSPort' maxlength='256' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_LNSPortmh']);</script></span></td> 
        </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_LocalHostName'></td>
        <td class="table_right"> <input id='lac_LocalHostName' type='text' name='lac_LocalHostName' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_LocalHostNamemh']);</script></span></td> 
        </tr> 
        <tr>
        <td  class="table_title width_per25" BindText='vpn_l2tp_lac_WANInterface'></td> 
        <td class="table_right"> <select name="WANInterface" id="WANInterface" style="width:260px"> </select> <font color="red">*</font></td> 
        </tr>
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_UserName'></td>
        <td class="table_right"> <input id='lac_UserName' type='text' name='lac_UserName' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_UserNamemh']);</script></span>
        </td> </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_l2tp_lac_Password'></td>
        <td class="table_right"> <input id='lac_Password' type='Password' name='lac_Password' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_Passwordmh']);</script></span>
        </td> </tr> 
    </table>
    <table cellpadding="0" cellspacing="1" width="100%" class="table_button"> 
    <tr> 
      <td class="width_per25" ></td> 
      <td class="table_submit">
      <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
        <button id="btnApply1" name="btnApply1" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Submit(2);"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_app']);</script></button> 
        <button name="cancelValue" id="cancelValue" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelConfig();"><script>document.write(vpn_l2tp_lac_setting_language['vpn_l2tp_lac_cancel']);</script></button> 
    </td> 
    </tr> 
    </table>
</div>
</form>
</body>
</html>
