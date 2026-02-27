<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<script language="javascript" src="../../amp/common/wlan_list.asp"></script>
<title>VXLAN</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>

<script language="JavaScript" type="text/javascript">

var appName = navigator.appName;
var VXLANAddFlag = false;
var selctOptionIndex = -1;
var l2tptypename = null;
var LANPath = "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.";
var SSIDPath = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.";
var TopoInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_Topo,X_HW_EthNum|X_HW_SsidNum,TopoInfo);%>;
var TopoInfo = TopoInfoList[0];
var is5182H = "<%HW_WEB_GetFeatureSupport(BBSP_FT_DATAPATH_NP);%>";
var doubleFreqFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
var curLANPortList = new Array();
var curLanInterfaceValue = "";
var specWanMaxNum = '<%HW_WEB_GetSPEC(BBSP_SPEC_IFM_WANNUM.UINT32);%>';
var curBinMode = '<%HW_WEB_GetBinMode();%>';
var vxlanMaxInstNum = 10;
var isFullCfgVxlan = "<%HW_WEB_GetFeatureSupport(FT_WEB_FULLCFG_VXLAN);%>";
var vxlanGlobalEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_VXLAN.Enable);%>';

if (specWanMaxNum == 8) {
    vxlanMaxInstNum = 6;
}

function TopoInfo(Domain, EthNum, SSIDNum)
{   
    this.Domain = Domain;
    this.EthNum = EthNum;
    this.SSIDNum = SSIDNum;
}

function stOutWANInterface(domain,RemoteEndPoints) {
    this.domain = domain;
    this.RemoteEndPoints = RemoteEndPoints;
}

function stInnerWANInterface(domain, WANInterface,VNI) {
    this.domain = domain;
    this.WANInterface = WANInterface;
    this.VNI = VNI;
}
function stVXLANConfig(domain, Enable, RemoteEndPoints, OutWANInterface, SourcePort, RemotePort, InterfaceNumberOfEntries) {
    this.domain = domain;
    this.Enable = Enable;
    this.RemoteEndPoints = RemoteEndPoints;
    this.OutWANInterface = OutWANInterface;
    this.SourcePort = SourcePort;
    this.RemotePort = RemotePort;
    this.InterfaceNumberOfEntries = InterfaceNumberOfEntries;
}

function stVXLANINTERFACE(domain, Enable, VNI, WANInterface, WorkMode, MaxMTUSize, IPAddress, SubnetMask, AddressingType, NATEnabled, DNSServers_Master, DNSServers_Slave, DefaultGateway, X_HW_VLAN, X_HW_LANInterface, X_HW_VLANEnable) {
    this.domain = domain;
    this.Enable = Enable;
    this.VNI = VNI;
    this.WANInterface = WANInterface;
    this.WorkMode = WorkMode;
    this.MaxMTUSize = MaxMTUSize;
    this.IPAddress = IPAddress;
    this.SubnetMask = SubnetMask;
    this.AddressingType = AddressingType;
    this.NATEnabled = NATEnabled;
    this.DNSServers_Master = DNSServers_Master;
    this.DNSServers_Slave = DNSServers_Slave;
    this.DefaultGateway = DefaultGateway;
    this.X_HW_VLAN = X_HW_VLAN;
    this.X_HW_LANInterface = X_HW_LANInterface;
    this.X_HW_VLANEnable = X_HW_VLANEnable;
}

var VXLAN_VXLANConfig = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VXLAN.VXLANConfig.{i},Enable|RemoteEndPoints|OutWANInterface|SourcePort|RemotePort|InterfaceNumberOfEntries, stVXLANConfig);%>;
var VXLAN_Interface = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VXLAN.VXLANConfig.{i}.Interface.{i}, Enable|VNI|WANInterface|WorkMode|MaxMTUSize|IPAddress|SubnetMask|AddressingType|NATEnabled|DNSServers_Master|DNSServers_Slave|DefaultGateway|X_HW_VLAN|X_HW_LANInterface|X_HW_VLANEnable, stVXLANINTERFACE);%>;


var VXLANConfigNum = 0;
var VXLANConfigInst = new Array();


for (var i = 0; i < VXLAN_VXLANConfig.length - 1; i++) {
    VXLANConfigInst[VXLANConfigNum++] = VXLAN_VXLANConfig[i];
} 

var VXLANInterfaceNum = 0;
var VXLANInterfaceInst = new Array();
for (var i = 0; i < VXLAN_Interface.length - 1; i++) {
    VXLANInterfaceInst[VXLANInterfaceNum++] = VXLAN_Interface[i];
}

function CheckRepeatPort(value)
{
    var lanInterfaceValue = "";

    if (VXLANConfigNum == 0) {
        return false;
    }

    for (var i = 0; i < VXLAN_VXLANConfig.length - 1; i++) {
        if (selctOptionIndex != i) {
            lanInterfaceValue = VXLAN_Interface[i].X_HW_LANInterface.toUpperCase();
            if (lanInterfaceValue.indexOf(value.toUpperCase()) != -1) {
                return true;
            }
        }
    }

    return false;
}

function CheckLanInterfaceValue() {
    var itemId = "";
    var itemValue = "";
    var tempLANPortValue = "";
    var firstItem = 1;
    var i = 0;

    for (i = 1; i <= TopoInfo.EthNum; i++) {
        itemId = "Vxlan_LAN" + i;

        if (getCheckVal(itemId) == 1) {
            itemValue = LANPath + i;
            if (CheckRepeatPort(itemValue) == true) {
                return false;
            }

            if (firstItem == 1) {
                tempLANPortValue = itemValue;
                firstItem = 0;
            } else {
                tempLANPortValue = tempLANPortValue + "," + itemValue;
            }
        }
    }

    for (i = 1; i <= TopoInfo.SSIDNum; i++) {
        itemId = "Vxlan_SSID" + i;

        if (getCheckVal(itemId) == 1) {
            itemValue = SSIDPath + i;
            if (CheckRepeatPort(itemValue) == true) {
                return false;
            }

            if (firstItem == 1) {
                tempLANPortValue = itemValue;
                firstItem = 0;
            } else {
                tempLANPortValue = tempLANPortValue + "," + itemValue;
            }
        }
    }

    curLanInterfaceValue = tempLANPortValue;

    return true;;
}

function AddSubmitParam(SubmitForm, type) {
    var url;

    SubmitForm.addParameter('x.RemoteEndPoints', getElById("vxlan_RemoteAddress").value);
    SubmitForm.addParameter('y.VNI', getElById("vpn_vxlan_VNI").value);
    SubmitForm.addParameter('x.Enable', getCheckVal("vxlanEnable"));
    SubmitForm.addParameter('y.Enable', getCheckVal("vxlanEnable"));

    if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
        SubmitForm.addParameter('y.WorkMode', getElById("vpn_WorkMode").value);
        SubmitForm.addParameter('y.MaxMTUSize', getElById("MaxMTUSize").value);
        SubmitForm.addParameter('y.AddressingType', getElById("AddressingType").value);
        SubmitForm.addParameter('y.NATEnabled', getCheckVal("NATEnabled"));
        if ((getElById("vpn_WorkMode").value == "Layer3Model") && (getElById("AddressingType").value == "Static")) {
            SubmitForm.addParameter('y.IPAddress', getElById("IPAddress").value);
            SubmitForm.addParameter('y.SubnetMask', getElById("SubnetMask").value);
            SubmitForm.addParameter('y.DNSServers_Master', getElById("DNSServers_Master").value);
            SubmitForm.addParameter('y.DNSServers_Slave', getElById("DNSServers_Slave").value);
            SubmitForm.addParameter('y.DefaultGateway', getElById("DefaultGateway").value);
        }
        SubmitForm.addParameter('y.X_HW_VLANEnable', getCheckVal("VLANEnable"));
        if (getCheckVal("VLANEnable") == 1) {
            SubmitForm.addParameter('y.X_HW_VLAN', getElById("VLAN").value);
        } else {
            SubmitForm.addParameter('y.X_HW_VLAN', 0);
        }
        SubmitForm.addParameter('x.OutWANInterface', getSelectVal("OutWANInterface"));
        SubmitForm.addParameter('y.X_HW_LANInterface', curLanInterfaceValue);
    } else {
        SubmitForm.addParameter('y.WANInterface', getElById("InnerWANInterface").value);
    }

    if (VXLANAddFlag == true) {
        url = 'addcfg.cgi?x=InternetGatewayDevice.X_HW_VXLAN.VXLANConfig' + '&y=x.Interface' + '&RequestFile=html/bbsp/vxlan/vxlan.asp';
    } else {
        url = 'set.cgi?x=' + VXLAN_VXLANConfig[selectedIndex].domain + '&y=' + VXLAN_Interface[selectedIndex].domain+ '&RequestFile=html/bbsp/vxlan/vxlan.asp';
    }

    SubmitForm.setAction(url);

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
}

function CheckParameters() {
    var maxMTU = getElById("MaxMTUSize").value;
    var ipAddress = getElById("IPAddress").value;
    var ipMask = getElById("SubnetMask").value;
    var dnsMaster = getElById("DNSServers_Master").value;
    var dnsSlave = getElById("DNSServers_Slave").value;
    var gateway = getElById("DefaultGateway").value;
    var VLAN = getElById("VLAN").value;
    var workMode = getElById("vpn_WorkMode").value;

    if (isNaN(maxMTU)) {
        AlertEx(vxlan_setting_language["vpn_vxlan_MTU_isNaN"]);
        return false;
    }
    if (maxMTU == '') {
        AlertEx(vxlan_setting_language["vpn_vxlan_MTU_NULL"]);
        return false;
    }

    if (CheckNumber(maxMTU, 1, 1974) == false) {
        AlertEx(vxlan_setting_language['vpn_vxlan_MTU_RangeError']);
        return false;
    }

    if ((workMode == "Layer3Model") && (getElById("AddressingType").value == "Static")) {

        if ((isValidIpAddress(ipAddress) == false) || (isAbcIpAddress(ipAddress) == false)) {
            AlertEx(vxlan_setting_language['vpn_vxlan_IPAddress']);
            return false;
        }

        for (var i = 0; i < VXLAN_Interface.length - 1; i++) {
            if ((selctOptionIndex != i) && (VXLAN_Interface[i].IPAddress == ipAddress)) {
                AlertEx(vxlan_setting_language['IPAddressIsUserd'] );
                return false;
            }
        }

        if ((ipMask == '') || ((ipMask != '') && (isValidSubnetMask(ipMask) == false))) {
            AlertEx(vxlan_setting_language['vpn_vxlan_subnetmaskp']);
            return false;
        }

        if ((dnsMaster != '') && ((isValidIpAddress(dnsMaster) == false) || (isAbcIpAddress(dnsMaster) == false))) {
            AlertEx(vxlan_setting_language['vpn_vxlan_firstdns_invalid']);
            return false;
        }

        if ((dnsSlave != '') && ((isValidIpAddress(dnsSlave) == false) || (isAbcIpAddress(dnsSlave) == false))) {
            AlertEx(vxlan_setting_language['vpn_vxlan_seconddns_invalid']);
            return false; 
        }

        if ((gateway != '') && ((isValidIpAddress(gateway) == false) || (isAbcIpAddress(gateway) == false))) {
            AlertEx(vxlan_setting_language['vpn_vxlan_gateway_invalid']);
            return false;
        }
    }

    if ((getCheckVal("VLANEnable") == 1)) {
        if (isNaN(VLAN)) {
            AlertEx(vxlan_setting_language["vpn_vxlan_VLAN_isNaN"]);
            return false;
        }

        if (CheckNumber(VLAN, 1, 4096) == false) {
            AlertEx(vxlan_setting_language['vpn_vxlan_VLAN_RangeError']);
            return false;
        }

        if ((is5182H == 0) && (workMode == "Layer2Model")) {
            var wanList = GetWanList();
            for (var i=0; i < wanList.length; i++) {
                if (((selctOptionIndex == -1) || ((selctOptionIndex >= 0) && (wanList[i].domain != VXLAN_Interface[selctOptionIndex].WANInterface))) &&
                    (wanList[i].Mode != "IP_Routed") && (wanList[i].VlanId == VLAN)) {
                        AlertEx(vxlan_setting_language['vpn_vxlan_VLAN_repeat']);
                        return false;
                }
            }
        }

    }

    if (CheckLanInterfaceValue() == false) {
        AlertEx(vxlan_setting_language['vpn_vxlan_lancfgrepeat']);
        return false;
    }

    return true;
}

function CheckVNIRepeat(VNI) {
    for (var i = 0; i < VXLAN_Interface.length - 1; i++) {
        if ((selctOptionIndex != i) && (VXLAN_Interface[i].VNI == VNI)) {
            AlertEx(vxlan_setting_language['vpn_vxlan_Vnicfgrepeat'] );
            return false;
        }
    }
    return true;
}
function CheckForm(type) {
    var RemoteVTEP = getElById("vxlan_RemoteAddress").value;
    var VNI = getElById("vpn_vxlan_VNI").value;
    var vniMin = 1;
    var vniErr = vxlan_setting_language['vpn_vxlan_VNI_RangeError'];

    if ((isAbcIpAddress(RemoteVTEP) == false) || (isDeIpAddress(RemoteVTEP) == true) ||
       (isBroadcastIpAddress(RemoteVTEP) == true) || (isLoopIpAddress(RemoteVTEP) == true)) {
        AlertEx(vxlan_setting_language['vpn_vxlan_Remote_Address'] + RemoteVTEP + vxlan_setting_language['vpn_vxlan_isinvalidp']);
        return false;
    }

    if ((is5182H != 1) && ((isFullCfgVxlan != 1)) && (getSelectVal("InnerWANInterface") == "")) {
        AlertEx(vxlan_setting_language['vpn_vxlan_InnerWANInterface_title']+vxlan_setting_language['vpn_vxlan_invalid_wan']);
        return false;
    }

    if (isNaN(VNI)) {
        AlertEx(vxlan_setting_language["vpn_vxlan_VNI_isNaN"]);
        return false;
    }
    if (VNI == '') {
        AlertEx(vxlan_setting_language["vpn_vxlan_VNI_NULL"]);
        return false;
    }

    if ((curBinMode.toUpperCase() == 'CMCC') ||
        (curBinMode.toUpperCase() == 'A8C')) {
        vniMin = 0;
        vniErr = vxlan_setting_language['vpn_vxlan_VNI_CmccRangeError'];
    }

    if (CheckNumber(VNI, vniMin, 16777215) == false) {
        AlertEx(vniErr);
        return false;
    }

    if ((is5182H != 1) && ((isFullCfgVxlan != 1)) && (VXLANAddFlag == 1)) {
        for (var i = 0; i < VXLAN_Interface.length - 1; i++) {
            if (VXLAN_Interface[i].WANInterface == getSelectVal("InnerWANInterface")) {
               AlertEx(vxlan_setting_language['vpn_vxlan_repeat_InnerWANInterface'] );
               return false;
            }
        }
    }

    if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
        if (CheckParameters() == false) {
            return false;
        }

        if (CheckVNIRepeat(VNI) == false) {
            return false;
        }
    }

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
    return true;
}

function IsIPv4RouteWan(Wan) {
    if ((Wan.IPv4Enable == "1") && (Wan.Mode == "IP_Routed")) {
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

function IsValidOutWAN(Wan) {
    if ((Wan.Mode != "IP_Routed") || (Wan.IPv4Enable != '1')) {
        return false;
    }

    if (Wan.Tr069Flag == "1") {
        return false;
    }

    if (Wan.ServiceList.indexOf("INTERNET") == -1) {
        return false;
    }

    if (Wan.X_HW_VXLAN_Enable == 1) {
        return false;
    }

    return true;
}

function IsValidInnerWAN(Wan) {
    if (Wan.Tr069Flag == "1") {
        return false;
    }

    if (Wan.ServiceList.indexOf("INTERNET") == -1) {
        return false;
    }

    if (Wan.X_HW_VXLAN_Enable != 1) {
        return false;
    }

    return true;
}

function InitWanNameListControlWanname(WanListControlId, IsThisWanOkFunction) {
    var Control = getElById(WanListControlId);
    var WanList = GetWanListByFilter(IsThisWanOkFunction);
    var i = 0;

    if (WanListControlId == "OutWANInterface") {
        var Option = document.createElement("Option");
        Option.value = "";
        Option.innerText = "";
        Option.text = "";
        Control.appendChild(Option);
    }

    for (i = 0; i < WanList.length; i++) {
        var Option = document.createElement("Option");
        Option.value = WanList[i].domain;
        Option.innerText = MakeWanName1(WanList[i]);
        Option.text = MakeWanName1(WanList[i]);
        Control.appendChild(Option);
    }
}

function AddressingTypeSelect(AddressingType) {
    if (AddressingType == 'DHCP') {
        setDisplay('IPAddressRow', 0);
        setDisplay('SubnetMaskRow', 0);
        setDisplay('DNSServers_MasterRow', 0);
        setDisplay('DNSServers_SlaveRow', 0);
        setDisplay('DefaultGatewayRow', 0);
    } else if (AddressingType == 'Static') {
        setDisplay('IPAddressRow', 1);
        setDisplay('SubnetMaskRow', 1);
        setDisplay('DNSServers_MasterRow', 1);
        setDisplay('DNSServers_SlaveRow', 1);
        setDisplay('DefaultGatewayRow', 1);
    }
}

function vpnWorkMode(WorkMode, isDisplay) {
    if (WorkMode == 'Layer2Model') {
        if (!isDisplay && (ConfirmEx(vxlan_setting_language['vpn_vxlan_layer2model_tip']) == false)) {
            setSelect('vpn_WorkMode', "Layer3Model");
            return;
        }
        setDisplay('EnableRow', 1);
        setDisplay('remoteRow', 1);
        setDisplay('VNIRow', 1);
        setDisplay('MaxMTUSizeRow', 0);
        setDisplay('IPAddressRow', 0);
        setDisplay('SubnetMaskRow', 0);
        setDisplay('AddressingType_selectRow', 0);
        setDisplay('NATEnabledRow', 0);
        setDisplay('DNSServers_MasterRow', 0);
        setDisplay('DNSServers_SlaveRow', 0);
        setDisplay('DefaultGatewayRow', 0);
        setDisplay('WorkRow', 1);

    } else if (WorkMode == 'Layer3Model') {
        setDisplay('EnableRow', 1);
        setDisplay('remoteRow', 1);
        setDisplay('VNIRow', 1);
        setDisplay('MaxMTUSizeRow', 1);
        setDisplay('IPAddressRow', 0);
        setDisplay('SubnetMaskRow', 0);
        setDisplay('AddressingType_selectRow', 1);
        setDisplay('NATEnabledRow', 1);
        AddressingTypeSelect(getElById("AddressingType").value);
        setDisplay('WorkRow', 0);
    }
}

function GetLANPortListInfo(index) {
    var lanPortList = new Array();
    var tempLANPortValue = "";
    var tempLANPortList = VXLAN_Interface[index].X_HW_LANInterface.toUpperCase().split(",");

    for (var i = 0; i < tempLANPortList.length; i++) {
        if (tempLANPortList[i].indexOf(LANPath.toUpperCase()) != -1) {
            tempLANPortValue = tempLANPortList[i].replace(LANPath.toUpperCase(), "LAN");
        } else {
            tempLANPortValue = tempLANPortList[i].replace(SSIDPath.toUpperCase(), "SSID");
        }

        var tempLANPortInfoList = tempLANPortValue.split(".");
        lanPortList[i] = tempLANPortInfoList[0];
    }
    curLANPortList = lanPortList;
}

function InitLanInterface() {
    var i;
    var ispPortList = Instance_IspWlan.GetISPPortList();

    for (i = 1; i <= TopoInfo.EthNum; i++) {
        setCheck("Vxlan_LAN" + i, 0);
    }

    if (doubleFreqFlag != 1) {
        for (var i = parseInt(TopoInfo.SSIDNum) + 1; i <= 8; i++) {
            setDisplay("Div_SSID" + i, 0);
        }
    }

    if (ispPortList.length > 0) {
        for (i = 1; i <= parseInt(TopoInfo.SSIDNum); i++) {
            var pos = ArrayIndexOf(ispPortList, 'SSID'+i);
            if (pos >= 0) {
                setDisplay("Div_SSID" + i, 0);
            }
        }
    }

    if (doubleFreqFlag == 1) {
        for (i = 0; i < WlanList.length; i++) {
            var tid = parseInt(i + 9);
            var tidssid = tid - 8;
            if (WlanList[i].bindenable == "0") {  
                setDisable("Vxlan_SSID" + tidssid, 1);
            }

            if (WlanList[i].bindenable == "1") {
                if (enbl5G != 1 && tidssid > 4) {
                    setDisable("Vxlan_SSID" + tidssid, 1);
                }

                if (enbl2G != 1 && tidssid < 5) {
                    setDisable("Vxlan_SSID" + tidssid, 1);
                }
            }
        }
    } else {
        for (i = 0; i < WlanList.length; i++) {
            var tidssid = parseInt(i + 1);
            if (WlanList[i].bindenable == "0") {
                setDisable("Vxlan_SSID" + tidssid, 1);
            }
        }
    }

    for (i = 1; i <= TopoInfo.SSIDNum; i++) {
        setCheck("Vxlan_SSID" + i, 0);
    }
}

function SetLanInterfaceValue(index) {
    InitLanInterface();

    GetLANPortListInfo(index);

    for(var i = 0; i < curLANPortList.length; i++) {
        setCheck("Vxlan_" + curLANPortList[i].toUpperCase(), 1);
    }
}

function InitCfgTable() {
    if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
        setDisplay('InnerWANInterfaceRow', 0);
        setDisplay('WorkModeRow', 1);
        setDisplay('MaxMTUSizeRow', 1);
        setDisplay('AddressingType_selectRow', 1);
        setDisplay('NATEnabledRow', 1);
        setDisplay('IPAddressRow', 1);
        setDisplay('SubnetMaskRow', 1);
        setDisplay('DNSServers_MasterRow', 1);
        setDisplay('DNSServers_SlaveRow', 1);
        setDisplay('DefaultGatewayRow', 1);
        setDisplay('VLANEnableRow', 1);
        setDisplay('VLANRow', 1);
        setDisplay('LANInterfaceRow', 1);
        setDisplay('OutWANInterfaceRow', 1);
    } else {
        setDisplay('InnerWANInterfaceRow', 1);
        setDisplay('WorkModeRow', 0);
        setDisplay('MaxMTUSizeRow', 0);
        setDisplay('AddressingType_selectRow', 0);
        setDisplay('NATEnabledRow', 0);
        setDisplay('IPAddressRow', 0);
        setDisplay('SubnetMaskRow', 0);
        setDisplay('DNSServers_MasterRow', 0);
        setDisplay('DNSServers_SlaveRow', 0);
        setDisplay('DefaultGatewayRow', 0);
        setDisplay('VLANEnableRow', 0);
        setDisplay('VLANRow', 0);
        setDisplay('LANInterfaceRow', 0);
        setDisplay('OutWANInterfaceRow', 0);
    }
    
    for (var i = parseInt(TopoInfo.EthNum) + 1; i <= 8; i++) {
        setDisplay("Div_LAN" + i, 0);
    }

    if (doubleFreqFlag != 1) {
        for (var i = parseInt(TopoInfo.SSIDNum) + 1; i <= 8; i++) {
            setDisplay("Div_SSID" + i, 0);
        }
    }
}

function LoadFrame() {
    InitCfgTable();

    if (VXLANConfigNum == 0) {
        selectLine('record_no');
        setDisplay('ConfigForm', 0);
    } else {
        selectLine('record_0');
        setDisplay('ConfigForm', 0);
    }

    InitWanNameListControlWanname("InnerWANInterface", IsValidInnerWAN);
    if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
        InitWanNameListControlWanname("OutWANInterface", IsValidOutWAN);
    }

    if (vxlanGlobalEnable == '0') {
        setDisable('Newbutton', 1);
        setDisable('DeleteButton', 1);
    } else {
        setDisable('Newbutton', 0);
        setDisable('DeleteButton', 0);
    }
}

function setCtlDisplay(option) {
}

var selectedIndex = -1;  

function setControl(index) {
    var option1;
    selctOptionIndex = index;

    if (index == -1) {
        if ((VXLAN_VXLANConfig.length - vxlanMaxInstNum) >= 1) {
            if (vxlanMaxInstNum == 6) {
                AlertEx(vxlan_setting_language['vpn_vxlan_invalid_num2']);
            } else {
                AlertEx(vxlan_setting_language['vpn_vxlan_invalid_num']);
            }
            return false;
    }
        VXLANAddFlag = true;
        setDisplay('ConfigForm', 1);
        setText('vxlan_RemoteAddress', "");
        setText('vpn_vxlan_VNI', "");
        document.getElementById("vxlanEnable").checked = true;
        if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
            vpnWorkMode("Layer3Model");
            setSelect('vpn_WorkMode', "Layer3Model");
            setText('MaxMTUSize', "1440");
            setSelect('AddressingType', "DHCP");
            AddressingTypeSelect("DHCP");
            setText('IPAddress', "");
            setText('SubnetMask', "");
            setText('DNSServers_Master', "");
            setText('DNSServers_Slave', "");
            setText('DefaultGateway', "");
            document.getElementById("NATEnabled").checked = false;
            setCheck('VLANEnable', 0);
            setDisplay('VLANRow', 0);
            setText('VLAN', "");
            InitLanInterface();
            setSelect('OutWANInterface', "");
        } else {
            setSelect('InnerWANInterface', "");
        }
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        VXLANAddFlag = false;
        setDisplay('ConfigForm', 1);
        option1 = document.getElementById("rml" + index).value;
        for (var i = 0; i < VXLAN_VXLANConfig.length - 1 ; i++) {
            if (option1 == VXLAN_VXLANConfig[i].domain) {
                document.getElementById("vxlanEnable").checked = (VXLAN_VXLANConfig[i].Enable || VXLAN_Interface[i].Enable) == "1" ? true:false;
                setText('vxlan_RemoteAddress', VXLAN_VXLANConfig[i].RemoteEndPoints);
                setText('vpn_vxlan_VNI', VXLAN_Interface[i].VNI);
                if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
                    setSelect('vpn_WorkMode', VXLAN_Interface[i].WorkMode);
                    setSelect('AddressingType', VXLAN_Interface[i].AddressingType);
                    vpnWorkMode(VXLAN_Interface[i].WorkMode, true);
                    document.getElementById("NATEnabled").checked = VXLAN_Interface[i].NATEnabled == "1" ? true:false;
                    setText('MaxMTUSize', VXLAN_Interface[i].MaxMTUSize);
                    setText('IPAddress', VXLAN_Interface[i].IPAddress);
                    setText('SubnetMask', VXLAN_Interface[i].SubnetMask);
                    setText('DNSServers_Master', VXLAN_Interface[i].DNSServers_Master);
                    setText('DNSServers_Slave', VXLAN_Interface[i].DNSServers_Slave);
                    setText('DefaultGateway', VXLAN_Interface[i].DefaultGateway);
                    setCheck('VLANEnable', VXLAN_Interface[i].X_HW_VLANEnable);
                    if (VXLAN_Interface[i].X_HW_VLANEnable == 1) {
                        setDisplay('VLANRow', 1);
                    } else {
                        setDisplay('VLANRow', 0);
                    }
                    setText('VLAN', VXLAN_Interface[i].X_HW_VLAN);
                    SetLanInterfaceValue(i);
                    setSelect('OutWANInterface', VXLAN_VXLANConfig[i].OutWANInterface);
                } else {
                    setSelect('InnerWANInterface', VXLAN_Interface[i].WANInterface);
                }

                selectedIndex = i;
            }
        }
    }

    if (vxlanGlobalEnable == '0') {
        setDisable('btnApply1', 1);
        setDisable('cancelValue', 1);
    } else {
        setDisable('btnApply1', 0);
        setDisable('cancelValue', 0);
    }
}

function selectRemoveCnt(obj) {
}

function clickRemove() {
    if (VXLANConfigNum == 0) {
        AlertEx(vxlan_setting_language['vpn_vxlan_novxlan']);
        return;
    }

    if (selctOptionIndex == -1) {
        AlertEx(vxlan_setting_language['vpn_vxlan_nosavevxlan']);
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
        AlertEx(vxlan_setting_language['vpn_vxlan_selectoption']);
        return ;
    }

    if (ConfirmEx(vxlan_setting_language['vpn_vxlan_deloption']) == false) {
        document.getElementById("DeleteButton").disabled = false;
        return;
    }

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
    removeInst('html/bbsp/vxlan/vxlan.asp');
}

function CancelConfig(){
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
        setCtlDisplay(optionrecord);
    }
}

function OnChangeUI(controlObject) {
    if (controlObject == getElementById('VLANEnable')) {
        setCheck("VLANEnable", getCheckVal('VLANEnable'));
        if (getCheckVal('VLANEnable') == 1) {
            setDisplay('VLANRow', 1);
        } else {
           setDisplay('VLANRow', 0);
        }
    }
}

</script>

</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<form id="CoForm" action="../application/set.cgi"> 
<script language="JavaScript" type="text/javascript">
    if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
        HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vxlan_setting_language, "vpn_vxlan_s001"), GetDescFormArrayById(vxlan_setting_language, "vpn_vxlan_titlecommon"), false);
    } else {
        HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vxlan_setting_language, "vpn_vxlan_s001"), GetDescFormArrayById(vxlan_setting_language, "vpn_vxlan_title"), false);
    }
</script> 
<div class="title_spread"></div>

<script language="JavaScript" type="text/javascript">
    writeTabCfgHeader('VXLAN','100%');
</script> 
<table class="tabal_bg" id="VXLANOptionInst" width="100%"  cellpadding="0" cellspacing="1"> 
  <tr class="head_title"> 
    <td class="tabal_left width_10p">&nbsp;</td>
    <td class="tabal_left width_24p" BindText='vpn_vxlan_s002'></td>
    <td class="tabal_left width_24p" BindText='vpn_vxlan_s003'></td>
    <td class="tabal_left width_24p" BindText='vpn_vxlan_s004'></td>
    <script language="JavaScript" type="text/javascript">
        if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
            document.write('<td class="tabal_left width_24p" BindText="vpn_vxlan_s012a"></td>');
        } else {
            document.write('<td class="tabal_left width_24p" BindText="vpn_vxlan_s005"></td>');
        }
    </script>
  </tr> 
    <script language="JavaScript" type="text/javascript">
        if (VXLANConfigNum == 0) {
            document.write('<TR id="record_no"' +' class="tabal_center01 " onclick="selectLine(this.id);">');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('</TR>');
        } else {
            for (var i = 0; i < VXLANConfigNum; i++) {
                var showEnable = "";
                document.write('<TR id="record_' + i +'" class="tabal_01 restrict_dir_ltr" align="center" onclick="selectLine(this.id);">');
                document.write('<TD >' + '<input id = "rml'+i+'" type="checkbox" name="rml" value="' + VXLANConfigInst[i].domain +'" onclick="selectRemoveCnt(this);">' + '</TD>');
                if (VXLANConfigInst[i].Enable == '1') {
                    showEnable = vxlan_setting_language['vpn_vxlan_s006'];
                } else {
                    showEnable = vxlan_setting_language['vpn_vxlan_s007'];
                }
                document.write('<TD >' + showEnable + '</TD>');  
                document.write('<TD >' + VXLANConfigInst[i].RemoteEndPoints + '</TD>');
                document.write('<TD >' + VXLANInterfaceInst[i].VNI + '</TD>');  
                if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
                    var workModeRes = "";
                    if (VXLANInterfaceInst[i].WorkMode == 'Layer2Model') {
                    workModeRes = vxlan_setting_language['vpn_vxlan_s013'];
                    } else if (VXLANInterfaceInst[i].WorkMode == 'Layer3Model') {
                        workModeRes = vxlan_setting_language['vpn_vxlan_s014'];
                    } else {
                        workModeRes = '--'
                    }
                    document.write('<TD >' + workModeRes + '</TD>');
                } else {
                    if (VXLANInterfaceInst[i].WANInterface == "") {
                        document.write('<TD >--</TD>');
                    } else {
                        document.write('<TD >' + MakeWanName(getWanOfStaticRoute(VXLANInterfaceInst[i].WANInterface)) + '</TD>'); 
                    }
                }
                document.write('</TR>');
            }
        }
    </script> 
</table> 
<div id="ConfigForm" style="display:none"> 
    <table cellpadding="0" cellspacing="1" width="100%" class="tabal_bg">
        <tr id="EnableRow">
            <td  class="table_title width_per25" BindText='vpn_vxlan_s008'></td> 
            <td class="table_right"><input  type="checkbox" id="vxlanEnable" />
        </tr>
        <tr id="remoteRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s009'></td>
            <td class="table_right"> <input id='vxlan_RemoteAddress' type='text' name='vxlan_RemoteAddress' maxlength='15' style="width:260px"><font color="red">*</font> <span class="gray"></span></td> 
        </tr>
        <tr id="OutWANInterfaceRow">
            <td  class="table_title width_per25" BindText='vpn_vxlan_s028'></td> 
            <td class="table_right"> <select name="OutWANInterface" id="OutWANInterface" style="width:260px"> </select></td> 
        </tr>
        <tr id="VNIRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s010'></td>
            <td class="table_right"> <input id='vpn_vxlan_VNI' type='text' name='vpn_vxlan_VNI' maxlength='256' style="width:260px"><font color="red">*</font>
                <span class="gray">
                    <script>
                        if (curBinMode.toUpperCase() == 'CMCC') {
                            document.write(vxlan_setting_language['vpn_vxlan_VNI_CmccRange']);
                        } else {
                            document.write(vxlan_setting_language['vpn_vxlan_VNI_Range']);
                        }
                    </script>
                </span>
            </td> 
        </tr> 
        <tr id="InnerWANInterfaceRow">
            <td  class="table_title width_per25" BindText='vpn_vxlan_s011'></td> 
            <td class="table_right"> <select name="InnerWANInterface" id="InnerWANInterface" style="width:260px"> </select> <font color="red">*</font></td> 
        </tr>
        <tr id="WorkModeRow">
            <script>
            if ((is5182H == 1) || (isFullCfgVxlan == 1)) {
                document.write('<td class="table_title width_per25" BindText="vpn_vxlan_s012b"></td>')
            } else {
                document.write('<td class="table_title width_per25" BindText="vpn_vxlan_s012"></td>')
            }
            </script>
            <td class="table_right width_per75"> <select size="1" id='vpn_WorkMode' name='vpn_WorkMode' class="width_150px" onChange='vpnWorkMode(this.value)'>
                <option value="Layer2Model" BindText='vpn_vxlan_s013'></option> 
                <option value="Layer3Model" selected BindText='vpn_vxlan_s014'></option> 
            </select>
            <span id="WorkRow" class="gray">
                <script>
                        document.write(vxlan_setting_language['vpn_vxlan_s029']);
                </script>
            </span>
         </td> 
        </tr> 
        <tr id="MaxMTUSizeRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s015'></td>
            <td class="table_right"> <input id='MaxMTUSize' type='text' name='MaxMTUSize' maxlength='256' style="width:260px"> <span class="gray"><script>document.write(vxlan_setting_language['vpn_vxlan_MTU_Range']);</script></span></td>  
        </tr> 
        <tr id="AddressingType_selectRow"> 
            <td class="table_title width_per25" BindText='vpn_vxlan_s016'></td> 
            <td class="table_right width_per75"> <select size="1" id='AddressingType' name='AddressingType' class="width_150px" onChange='AddressingTypeSelect(this.value)'>
                <option value="DHCP" BindText='vpn_vxlan_s017'></option> 
                <option value="Static" selected BindText='vpn_vxlan_s018'></option> 
            </select> </td> 
        </tr> 
        <tr id="NATEnabledRow">
            <td  class="table_title width_per25"  BindText='vpn_vxlan_s019'></td> 
            <td class="table_right"><input  type="checkbox" id="NATEnabled" />
        </tr>
        <tr id="IPAddressRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s020'></td>
            <td class="table_right"> <input id='IPAddress' type='text' name='IPAddress' maxlength='15' style="width:260px"><font color="red">*</font> <span class="gray"></span></td> 
        </tr> 
        <tr id="SubnetMaskRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s021'></td>
            <td class="table_right"> <input id='SubnetMask' type='text' name='SubnetMask' maxlength='15' style="width:260px"><font color="red">*</font> <span class="gray"></span></td> 
        </tr> 
        <tr id="DefaultGatewayRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s024'></td>
            <td class="table_right"> <input id='DefaultGateway' type='text' name='DefaultGateway' maxlength='256' style="width:260px"> <span class="gray"></span></td> 
        </tr>
        <tr id="DNSServers_MasterRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s022'></td>
            <td class="table_right"> <input id='DNSServers_Master' type='text' name='DNSServers_Master' maxlength='15' style="width:260px"> <span class="gray"></span></td> 
        </tr> 
        <tr id="DNSServers_SlaveRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s023'></td>
            <td class="table_right"> <input id='DNSServers_Slave' type='text' name='DNSServers_Slave' maxlength='15' style="width:260px"> <span class="gray"></span></td> 
        </tr> 
        <tr id="VLANEnableRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s027'></td>
            <td class="table_right"> <input id='VLANEnable' type='checkbox' name='VLANEnable' value="True" onClick="OnChangeUI(this)"></td> 
        </tr> 
        <tr id="VLANRow">
        <td class="table_title width_per25" BindText='vpn_vxlan_s025'></td>
        <td class="table_right"> <input id='VLAN' type='text' name='VLAN' maxlength='256' style="width:260px"><span class="gray"><script>document.write(vxlan_setting_language['vpn_vxlan_VLAN_Range']);</script></span></td> 
        </tr> 
        <tr id="LANInterfaceRow">
            <td class="table_title width_per25" BindText='vpn_vxlan_s026'></td>
            <td class="table_right">
                <span id="Div_LAN1" ><input id="Vxlan_LAN1" name="Vlan_Port_checkbox1" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan1']);</script></span>
                <span id="Div_LAN2" ><input id="Vxlan_LAN2" name="Vlan_Port_checkbox2" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan2']);</script></span>
                <span id="Div_LAN3" ><input id="Vxlan_LAN3" name="Vlan_Port_checkbox3" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan3']);</script></span>
                <span id="Div_LAN4" ><input id="Vxlan_LAN4" name="Vlan_Port_checkbox4" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan4']);</script></span>
                <span id="Div_LAN5" ><input id="Vxlan_LAN5" name="Vlan_Port_checkbox5" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan5']);</script></span>
                <span id="Div_LAN6" ><input id="Vxlan_LAN6" name="Vlan_Port_checkbox6" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan6']);</script></span>
                <span id="Div_LAN7" ><input id="Vxlan_LAN7" name="Vlan_Port_checkbox7" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan7']);</script></span>
                <span id="Div_LAN8" ><input id="Vxlan_LAN8" name="Vlan_Port_checkbox8" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_lan8']);</script></span>
                </br>
                <span id="Div_SSID1" ><input id="Vxlan_SSID1" name="Vlan_Port_checkbox9" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid1']);</script></span>
                <span id="Div_SSID2" ><input id="Vxlan_SSID2" name="Vlan_Port_checkbox10" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid2']);</script></span>
                <span id="Div_SSID3" ><input id="Vxlan_SSID3" name="Vlan_Port_checkbox11" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid3']);</script></span>
                <span id="Div_SSID4" ><input id="Vxlan_SSID4" name="Vlan_Port_checkbox12" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid4']);</script></span>
                <span id="Div_SSID5" ><input id="Vxlan_SSID5" name="Vlan_Port_checkbox13" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid5']);</script></span>
                <span id="Div_SSID6" ><input id="Vxlan_SSID6" name="Vlan_Port_checkbox14" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid6']);</script></span>
                <span id="Div_SSID7" ><input id="Vxlan_SSID7" name="Vlan_Port_checkbox15" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid7']);</script></span>
                <span id="Div_SSID8" ><input id="Vxlan_SSID8" name="Vlan_Port_checkbox16" type="checkbox" value="True" ><script>document.write(vxlan_setting_language['vpn_vxlan_ssid8']);</script></span>
            </td> 
        </tr>
  </table>
  <table cellpadding="0" cellspacing="1" width="100%" class="table_button"> 
    <tr> 
      <td class="width_per25" ></td> 
      <td class="table_submit">
      <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
        <button id="btnApply1" name="btnApply1" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Submit(2);"><script>document.write(vxlan_setting_language['vpn_vxlan_app']);</script></button> 
        <button name="cancelValue" id="cancelValue" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelConfig();"><script>document.write(vxlan_setting_language['vpn_vxlan_cancel']);</script></button> 
    </td> 
    </tr> 
  </table>
</div>
</form>
<script> 
     ParseBindTextByTagName(vxlan_setting_language, "td", 1);
     ParseBindTextByTagName(vxlan_setting_language, "option", 1);
</script> 
</body>
</html>
