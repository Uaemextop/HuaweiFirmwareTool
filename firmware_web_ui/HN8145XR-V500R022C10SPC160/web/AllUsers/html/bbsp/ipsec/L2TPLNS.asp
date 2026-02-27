<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script type="text/javascript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<title>L2TP LNS</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(errdes.html);%>"></script>
<script language="JavaScript" type="text/javascript">

var appName = navigator.appName;
var VXLANAddFlag = false;
var selctOptionIndex = -1;


function stVPN_L2TP_LAC(domain,Enable,WANInterface) {
    this.domain = domain;
    this.Enable = Enable;
    this.WANInterface = WANInterface;
}

var VPN_L2TP_LAC = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLAC.{i}, Enable|WANInterface, stVPN_L2TP_LAC);%>;
var MASK = '********************************';
function ftLNSUserInfo(domain, Enable, UserName) {
    this.domain = domain;
    this.Enable = Enable;
    this.UserName = UserName;
    this.Password = MASK;
}

var VXLAN_VXLANConfig = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLNS.1.User.{i}, Enable|UserName, ftLNSUserInfo);%>;
var VXLANConfigNum = 0;
var VXLANConfigInst = new Array();

for (var i = 0; i < VXLAN_VXLANConfig.length - 1; i++) {
    VXLANConfigInst[VXLANConfigNum++] = VXLAN_VXLANConfig[i];
}

function ftL2TPLNSINFOs(domain, Enable, WANInterface, LocalHostName, AddressPool) {
    this.domain = domain;
    this.Enable = Enable;
    this.WANInterface = WANInterface;
    this.LocalHostName = LocalHostName;
    this.AddressPool = AddressPool;
}

var L2TPLNSINFOs = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLNS.{i}, Enable|WANInterface|LocalHostName|AddressPool, ftL2TPLNSINFOs);%>;
var L2TPLNSinfo = L2TPLNSINFOs[0];

function stVPNPoolInfos(domain, Name, MinAddress, MaxAddress, SubnetMask) {
    this.domain = domain;
    this.Name = Name;
    this.MinAddress = MinAddress;
    this.MaxAddress = MaxAddress;
    this.SubnetMask = SubnetMask;
}

var vpnPoolInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.AddressPool.{i}, Name|MinAddress|MaxAddress|SubnetMask, stVPNPoolInfos);%>;
var vpnPoolInfo = new stVPNPoolInfos("", "", "", "", "");
for (var i = 0; i < vpnPoolInfos.length - 1; i++) {
    if ((vpnPoolInfos[i].Name == 'lnsaddresspool') || ((L2TPLNSinfo != null) && (vpnPoolInfos[i].domain == L2TPLNSinfo.AddressPool))) {
        vpnPoolInfo = vpnPoolInfos[i];
    }
}

function AddSubmitParam(SubmitForm,type) {
    var url;
    var index = 0;
    var Form = new webSubmitForm();

    SubmitForm.addParameter('x.Enable', getCheckVal("LNSUserEnable"));
    SubmitForm.addParameter('x.UserName', getElById("LNSUsername").value);
    var lasPassword = getElById("LNSPassword").value;
    if (lasPassword !== MASK) {
      SubmitForm.addParameter('x.Password', lasPassword);
    }
    SubmitForm.addParameter('x.X_HW_Token', getValue('onttoken'));

    if(selctOptionIndex == -1) {
        url = 'add.cgi?x=InternetGatewayDevice.X_HW_VPN.L2TPLNS.1.User' + '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp';
    } else {
        url = 'set.cgi?x=' + VXLAN_VXLANConfig[selctOptionIndex].domain + '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp';
    }

    SubmitForm.setAction(url);
    setDisable('btnLNSAddUser', 1);
    setDisable('btnLNSAddCancel', 1);
}

function LnsShowResult(Result) {
    var errorCodeArray = new Array('0xf7376001','0xf7376002', '0xf7376003', '0xf7376004', '0xf7376005', '0xf7376006', '0xf7376007');
    var errorstring = new Array('ipsec_0x01', 'ipsec_0x02', 'ipsec_0x03', 'ipsec_0x04', 'ipsec_0x05', 'ipsec_0x06', 'ipsec_0x07');
    try {
        var ResultInfo = JSON.parse(hexDecode(Result));
        if (0 == ResultInfo.result) {
            return;
        }
        
        for (i = 0; i < errorCodeArray.length; i++) {
            if (errorCodeArray[i] == ResultInfo.error) {
                errFlag = 1;
                AlertEx(ipsec_language[errorstring[i]]);
                return;
            }
        }

        var errData = errLanguage['s' + ResultInfo.error];
        if ('string' != typeof(errData)) {
            errData = errLanguage['s0xf7205001'];
        }
        errFlag = 1;
        AlertEx(errData);
    } catch(e){
        errData = errLanguage['s0xf7205001'];
        errFlag = 1;
        AlertEx(errData);
    }
    return;
}

function EnableFirstLns(addressPool, enable) {
    var minAddress = getValue("vpn_MinAddress");
    var maxAddress = getValue("vpn_MaxAddress");
    var subnetMask = getValue("vpn_SubnetMask");

    setDisable('LNSEnableApply',0);
    setDisable('LNSEnableCancel',0);

    if ((VPN_L2TP_LAC[0] != null) && (VPN_L2TP_LAC[0].Enable == 1) && (enable == true)) {
        AlertEx(l2tplns_language['l2tplns_s020']);
        return;
    }

    if (CheckFormLns() == true) {
        if (addressPool == "") {
            if (vpnPoolInfos.length > 8) {
                AlertEx(l2tplns_language['l2tplns_s021']);
                return false;
            }
            $.ajax({
                type : "POST",
                async : false,
                cache : false,
                data : 'x.Name=lnsaddresspool' + '&x.MinAddress=' + minAddress + '&x.MaxAddress=' + maxAddress +
                       '&x.SubnetMask=' + subnetMask + '&x.X_HW_Token=' + getValue('onttoken'),
                url :  'addajax.cgi?x=InternetGatewayDevice.X_HW_VPN.AddressPool' +
                       '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp',
                success : function(data) {
                        LnsShowResult(data);
                        },
                error:function(XMLHttpRequest, textStatus, errorThrown) {
                    if(XMLHttpRequest.status == 404) {
                    }
                }
            });
        } else {
            $.ajax({
                type : "POST",
                async : false,
                cache : false,
                data : 'x.MinAddress=' + minAddress + '&x.MaxAddress=' + maxAddress + '&x.SubnetMask=' + subnetMask +
                       '&x.X_HW_Token=' + getValue('onttoken'),
                url :  'setajax.cgi?x=' + addressPool + '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp',
                success : function(data) {
                        LnsShowResult(data);
                        },
                error:function(XMLHttpRequest, textStatus, errorThrown) {
                    if(XMLHttpRequest.status == 404) {
                    }
                }
            });
        }
    } else {
        return false;
    }

    return true;
}

function GetVPNPoolInfo() {
    var tmp = '';
    $.ajax({
            type : "POST",
            async : false,
            cache : false,
            url : "/html/bbsp/ipsec/GetVPNPoolInfo.asp",
            success : function(data) {
                tmp = dealDataWithFun(data);  
            }
        });
    
    return tmp;
}

function EnableSubmitLns() {
    var form = new webSubmitForm();
    var enable = getCheckVal("EnableLNS");
    var wanInterface = getValue('LNSAddress');
    var localHostName = getValue("vpn_name");
    var addressPool = vpnPoolInfo.domain;
    var vpnPoolList = '';
    
    if (EnableFirstLns(addressPool, enable) == true) {
        vpnPoolList = GetVPNPoolInfo();
        for (var i = 0; i < vpnPoolList.length - 1; i++) {
            if (vpnPoolList[i].Name == "lnsaddresspool") {
                addressPool = vpnPoolList[i].domain;
            }
        }
        form.addParameter('x.AddressPool', addressPool);
        form.addParameter('x.Enable', enable);
        form.addParameter('x.WANInterface', wanInterface);
        form.addParameter('x.LocalHostName', localHostName);
        form.addParameter('x.X_HW_Token', getValue('onttoken'));

        if (L2TPLNSinfo == null) {
            form.setAction('add.cgi?x=InternetGatewayDevice.X_HW_VPN.L2TPLNS' +
                           '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp');
        } else {
            form.setAction('set.cgi?x=' + L2TPLNSinfo.domain +
                           '&RequestFile=/html/bbsp/ipsec/L2TPLNS.asp');
        }
        form.submit();
    }
}

function CheckForm(type) {
    var userName = getElById("LNSUsername").value;
    var password = getElById("LNSPassword").value;
    if ((userName == '') || (password == '')) {
        AlertEx(l2tplns_language['l2tplns_s022']);
        return;
    }

    if (!isSafeStringSN(userName)) {
        AlertEx(l2tplns_language['l2tplns_s033']);
        return;
    }

    setDisable('btnLNSAddUser', 1);
    setDisable('btnLNSAddCancel', 1);
    return true;
}

function CheckFormLns() {
    var wanInterface = getValue('LNSAddress');
    var localHostName = getValue("vpn_name");
    var minAddress = getValue("vpn_MinAddress");
    var maxAddress = getValue("vpn_MaxAddress");
    var subnetMask = getValue("vpn_SubnetMask");

    if (wanInterface == '') {
        AlertEx(l2tplns_language['l2tplns_s023']);
        return false;
    }
    if (localHostName == '') {
        AlertEx(l2tplns_language['l2tplns_s024']);
        return false;
    }
    if ((isAbcIpAddress(minAddress) == false) || (isDeIpAddress(minAddress) == true) ||
        (isBroadcastIpAddress(minAddress) == true) || (isLoopIpAddress(minAddress) == true) ) {
        AlertEx(l2tplns_language['l2tplns_s025']);
        return false;
    }
    if ((isAbcIpAddress(maxAddress) == false) || (isDeIpAddress(maxAddress) == true) ||
        (isBroadcastIpAddress(maxAddress) == true) || (isLoopIpAddress(maxAddress) == true) ) {
        AlertEx(l2tplns_language['l2tplns_s026']);
        return false;
    }
    if (isValidSubnetMask(subnetMask) == false) {
        AlertEx(l2tplns_language['l2tplns_s027']);
        return false;
    }

    setDisable('btnLNSAddUser', 1);
    setDisable('btnLNSAddCancel', 1);
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

var wanInfo = GetWanListByFilter(filterWan);

function ShowIfName(val) {
   for (var i = 0; i < wanInfo.length; i++) {
      if (wanInfo[i].domain == val) {
          return wanInfo[i].Name;
      } else if ('br0' == val) {
          return 'br0';
      }
   }

   return '&nbsp;';
}

function getWanOfStaticRoute(val) {
   for (var i = 0; i < wanInfo.length; i++) {
      if (wanInfo[i].domain == val) {
          return wanInfo[i];
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

    if(Wan.X_HW_VXLAN_Enable == 1) {
        return false;
    }

    return true;
}

function InitWanNameListControlWanname(WanListControlId, IsThisWanOkFunction) {
    var control = getElById(WanListControlId);
    var wanList = GetWanListByFilter(IsThisWanOkFunction);
    var i = 0;

    for (i = 0; i < wanList.length; i++) {
        var Option = document.createElement("Option");
        Option.value = wanList[i].domain;
        Option.innerText = MakeWanName1(wanList[i]);
        Option.text = MakeWanName1(wanList[i]);
        control.appendChild(Option);
    }
}

function LoadFrame() {
    if (VXLANConfigNum == 0) {
        selectLine('record_no');
        setDisplay('ConfigForm', 0);
    } else {
        selectLine('record_0');
        setDisplay('ConfigForm', 0);
    }

    InitWanNameListControlWanname("LNSAddress", IsValidWan);

    if (L2TPLNSinfo == null) {
        setCheck("EnableLNS", 0);
        lnsEnable();
        setText("vpn_name", "");
        setText("vpn_MinAddress", "");
        setText("vpn_MaxAddress", "");
        setText("vpn_SubnetMask", "");
    } else {
        setCheck("EnableLNS", L2TPLNSinfo.Enable);
        lnsEnable();
        setText("vpn_name", L2TPLNSinfo.LocalHostName);
        setText("vpn_MinAddress", vpnPoolInfo.MinAddress);
        setText("vpn_MaxAddress", vpnPoolInfo.MaxAddress);
        setText("vpn_SubnetMask", vpnPoolInfo.SubnetMask);
        setSelect("LNSAddress", L2TPLNSinfo.WANInterface);
    }

}

function lnsEnable() {
    if (getCheckVal("EnableLNS") == 0) {
        setDisable('LNSAddress',1);
        setDisable('vpn_name',1);
        setDisable('vpn_MinAddress',1);
        setDisable('vpn_MaxAddress',1);
        setDisable('vpn_SubnetMask',1);
    } else {
        setDisable('LNSAddress',0);
        setDisable('vpn_name',0);
        setDisable('vpn_MinAddress',0);
        setDisable('vpn_MaxAddress',0);
        setDisable('vpn_SubnetMask',0);
    }
}

var selectedIndex = -1;

function setControl(index) {
    var option1;
    selctOptionIndex = index;
    if (index == -1) {
        VXLANAddFlag = true;
        setDisplay('ConfigForm', 1);
        setCheck('LNSUserEnable', 0);
        setText('LNSUsername', "");
        setText('LNSPassword', "");
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        VXLANAddFlag = false;
        setDisplay('ConfigForm', 1);
        option1 = document.getElementById("rml" + index).value;
        for (var i = 0; i < VXLAN_VXLANConfig.length - 1; i++) {
            if (option1 == VXLAN_VXLANConfig[i].domain) {
                setCheck('LNSUserEnable', VXLAN_VXLANConfig[i].Enable);
                setText('LNSUsername', VXLAN_VXLANConfig[i].UserName);
                setText('LNSPassword', VXLAN_VXLANConfig[i].Password);
                selectedIndex = i;
            }
        }
    }

    setDisable('btnLNSAddUser', 0);
    setDisable('btnLNSAddCancel', 0);
}

function clickRemove() {
    if (VXLANConfigNum == 0) {
        AlertEx(l2tplns_language['l2tplns_s028']);
        return;
    }

    if (selctOptionIndex == -1) {
        AlertEx(l2tplns_language['l2tplns_s029']);
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
        AlertEx(l2tplns_language['l2tplns_s029']);
        return ;
    }

    if (ConfirmEx(l2tplns_language['l2tplns_s030']) == false) {
        document.getElementById("DeleteButton").disabled = false;
        return;
    }

    setDisable('btnLNSAddUser', 1);
    setDisable('btnLNSAddCancel', 1);
    removeInst('html/bbsp/ipsec/L2TPLNS.asp');
}

function CancelConfig() {
    setDisplay("ConfigForm", 0);
    if (selctOptionIndex == -1) {
        var tableRow = getElement("VXLANOptionInst");
        if (tableRow.rows.length == 1) {

        } else if (tableRow.rows.length = 2) {
            addNullInst('VXLAN');
        } else {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    } else {
        var optionrecord = VXLANConfigInst[selctOptionIndex];
    }
}

function selectRemoveCnt(obj) {

}

function CancelLNS() {
    if (L2TPLNSinfo == null) {
        setCheck("EnableLNS", 0);
        lnsEnable();
        setSelect('LNSAddress',"");
        setText("vpn_name", "");
        setText("vpn_MinAddress", "");
        setText("vpn_MaxAddress", "");
        setText("vpn_SubnetMask", "");
    } else {
        setCheck("EnableLNS", L2TPLNSinfo.Enable);
        lnsEnable();
        setSelect('LNSAddress',L2TPLNSinfo.WANInterface);
        setText("vpn_name", L2TPLNSinfo.LocalHostName);
        setText("vpn_MinAddress", vpnPoolInfo.MinAddress);
        setText("vpn_MaxAddress", vpnPoolInfo.MaxAddress);
        setText("vpn_SubnetMask", vpnPoolInfo.SubnetMask);
    }
}

</script>
</head>
<body onLoad="LoadFrame();" class="mainbody">
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("L2TPLNStitle", GetDescFormArrayById(l2tplns_language, "l2tplns_s001"), GetDescFormArrayById(l2tplns_language, "l2tplns_s002"), false);
</script>
<div class="title_spread"></div>
<form id="ipIncomingFltForm" name="ipIncomingFltForm">
<table class="tabal_bg" id="EnableLNSTable" width="100%"  cellpadding="0" cellspacing="1">
    <tbody>
        <tr>
            <td class="table_title table_title width_per25 align_left" BindText='l2tplns_s003'></td>
            <td class="table_right table_right align_left"><input id="EnableLNS" type="checkbox" realtype="CheckBox" class="CheckBox" onclick="lnsEnable();"></td>
        </tr>
        <tr>
            <td class="table_title table_title width_per25 align_left" BindText='l2tplns_s004'></td>
            <td class="table_right table_right align_left"><select size="1" id='LNSAddress' name='LNSAddress' class="width_123px"></select><font color="red">*</font></td>
        <tr>
            <td class="table_title table_title width_per25 align_left" BindText='l2tplns_s005'></td>
            <td class="table_right table_right align_left"><input id='vpn_name' type='text' name='vpn_name' maxlength='256' style="width:150px"><font color="red">*</font><span class="gray"></span></td>
        </tr>
        <tr>
            <td class="table_title table_title width_per25 align_left" BindText='l2tplns_s006'></td>
            <td class="table_right table_right align_left"><input id='vpn_MinAddress' type='text' name='vpn_MinAddress' maxlength='256' style="width:150px"><font color="red">*</font><span class="gray">(xxx.xxx.xxx.xxx)</span></td>
        </tr>
        <tr>
            <td class="table_title table_title width_per25 align_left" BindText='l2tplns_s007'></td>
            <td class="table_right table_right align_left"><input id='vpn_MaxAddress' type='text' name='vpn_MaxAddress' maxlength='256' style="width:150px"><font color="red">*</font><span class="gray">(xxx.xxx.xxx.xxx)</span></td>
        </tr>
        <tr>
            <td class="table_title width_per25" BindText='l2tplns_s008'></td>
            <td class="table_right"> <input id='vpn_SubnetMask' type='text' name='vpn_SubnetMask' maxlength='256' style="width:150px"><font color="red">*</font><span class="gray">(xxx.xxx.xxx.xxx)</span></td>
        </tr>
    </tbody>
</table>
<table cellpadding="0" cellspacing="1" width="100%" class="table_button">
    <tr>
        <td class="width_per25" ></td>
        <td class="table_submit">
            <button id="LNSEnableApply"  type="button" class="ApplyButtoncss buttonwidth_100px" onClick="EnableSubmitLns();" BindText='l2tplns_s009'></button>
            <button  id="LNSEnableCancel" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelLNS();" BindText='l2tplns_s010'></button>
        </td>
    </tr>
</table>
</form>

<div class="func_spread"></div>

<form id="CoForm" action="../application/set.cgi">
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(l2tplns_language, ""), GetDescFormArrayById(l2tplns_language, "l2tplns_s011"), false);
</script>
<div class="title_spread"></div>
<script language="JavaScript" type="text/javascript">
    writeTabCfgHeader('VXLAN','100%');
</script>
<table class="tabal_bg" id="VXLANOptionInst" width="100%"  cellpadding="0" cellspacing="1">
    <tr class="head_title">
        <td class="tabal_left width_10p">&nbsp;</td>
        <td class="tabal_left width_24p" BindText='l2tplns_s012'></td>
        <td class="tabal_left width_24p" BindText='l2tplns_s013'></td>
        <td class="tabal_left width_24p" BindText='l2tplns_s014'></td>
    </tr>
    <script language="JavaScript" type="text/javascript">
        if (VXLANConfigNum == 0) {
            document.write('<TR id="record_no"' +' class="tabal_center01 " onclick="selectLine(this.id);">');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('</TR>');
        } else {
            for (var i = 0; i < VXLAN_VXLANConfig.length - 1; i++) {
                document.write('<TR id="record_' + i +'" class="tabal_01 restrict_dir_ltr" align="center" onclick="selectLine(this.id);">');
                document.write('<TD >' + '<input id = "rml'+i+'" type="checkbox" name="rml" value="' + VXLAN_VXLANConfig[i].domain +'" onclick="selectRemoveCnt(this);">' + '</TD>');
                if (VXLAN_VXLANConfig[i].Enable == 1) {
                    document.write('<TD >' + l2tplns_language['l2tplns_s015'] + '</TD>');
                } else {
                    document.write('<TD >' + l2tplns_language['l2tplns_s016'] + '</TD>');
                }
                document.write('<TD >' + htmlencode(VXLAN_VXLANConfig[i].UserName) + '</TD>');
                document.write('<TD > ****** </TD>');
                document.write('</TR>');
            }
        }
    </script>
</table>
<div id="ConfigForm" style="display:none">
    <table cellpadding="0" cellspacing="1" width="100%" class="tabal_bg">
        <tr>
            <td class="table_title width_per25" BindText='l2tplns_s017'></td>
            <td class="table_right"> <input id='LNSUserEnable' type='checkbox'></td>
        </tr>
        <tr>
            <td class="table_title width_per25" BindText='l2tplns_s018'></td>
            <td class="table_right"> 
                <input id='LNSUsername' type='text'  maxlength='256' style="width:260px">
                <br><span class="gray"><script>document.write(l2tplns_language['l2tplns_s032']);</script></span>
            </td>
        </tr>
        <tr>
            <td class="table_title width_per25" BindText='l2tplns_s019'></td>
            <td class="table_right"> 
                <input id='LNSPassword' autocomplete="off" type='password' maxlength='256' style="width:260px">
                <br><span class="gray"><script>document.write(l2tplns_language['l2tplns_s031']);</script></span>
            </td>
        </tr>
        <tr>
    </table>
    <table cellpadding="0" cellspacing="1" width="100%" class="table_button">
        <tr>
            <td class="width_per25" ></td>
            <td class="table_submit">
                <input type="hidden" name="onttoken" id="onttoken" value="<%HW_WEB_GetToken();%>">
                <button id="btnLNSAddUser" name="btnLNSAddUser" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Submit(2);" BindText='l2tplns_s009'></button>
                <button name="cancelValue" id="btnLNSAddCancel" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelConfig();" BindText='l2tplns_s010'></button>
            </td>
        </tr>
    </table>
</div>
<script> 
     ParseBindTextByTagName(l2tplns_language, "td", 1);
     ParseBindTextByTagName(l2tplns_language, "button", 1);
</script> 
</form>
</body>
</html>
