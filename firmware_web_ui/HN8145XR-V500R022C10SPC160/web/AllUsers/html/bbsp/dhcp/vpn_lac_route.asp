<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/wan_list_info.asp"></script>
<script language="javascript" src="../common/wan_list.asp"></script>
<title>Dhcp static config</title>
<style type="text/css">
.tabnoline td {
    border:0px;
}

.firstCol {
    width:24%;
    text-align:right ;
}

.secondCol {
    width:24%;
}

.thirdCol {
    width:20%;
    text-align:right ;
}

.alignledge {
    width:3%;
}

.InputDhcp {
    width:123px;
}
</style>
<script language="JavaScript" type="text/javascript">
var selctIndex = -1;
var AddFlag = true;
var ipaddrarg = ""
var macaddrarg = "";
var TableName = "LacRouteConfigList";
var cfgMode='<%HW_WEB_GetCfgMode();%>';

if (window.location.href.indexOf("?") > 0) {
    ipaddrarg = window.location.href.split("?")[1]; 
    macaddrarg = window.location.href.split("?")[2]; 
}

function stLacRoute(domain, DestIPAddress, DestSubnetMask, IPInterfaceName) {
    this.domain = domain;
    this.DestIPAddress = DestIPAddress;
    this.DestSubnetMask  = DestSubnetMask;
    this.IPInterfaceName = IPInterfaceName;
}

function MainDhcpInfo(domain, State, RemoteHostName, LocalIPAddress, RemoteIPAddress, LocalTunnelID, RemoteTunnelID, LocalPort, RemotePort, RxPackets, RxBytesLo, RxBytesHi, TxPackets, TxBytesLo, TxBytesHi) {
    this.domain = domain;
    this.State = State;
    this.RemoteHostName = RemoteHostName;
    this.LocalIPAddress = LocalIPAddress;
    this.RemoteIPAddress = RemoteIPAddress;
    this.LocalTunnelID = LocalTunnelID;
    this.RemoteTunnelID = RemoteTunnelID;
    this.LocalPort = LocalPort;
    this.RemotePort = RemotePort;
    this.RxPackets = RxPackets;
    this.RxBytesLo = RxBytesLo;
    this.RxBytesHi = RxBytesHi;
    this.TxPackets = TxPackets;
    this.TxBytesLo = TxBytesLo;
    this.TxBytesHi = TxBytesHi;
}
function loadlanguage() {
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++) {
        var b = all[i];
        if (b.getAttribute("BindText") == null) {
            continue;
        }
        b.innerHTML = vpn_l2tp_lac_route_language[b.getAttribute("BindText")];
    }
}
function L2TPInterfaceListArray(domain, Alias, ObjectPath) {
    this.domain = domain;
    this.Alias = Alias;
    this.ObjectPath  = ObjectPath;
}

var l2tpInterfaceList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.X_HW_InterfaceList.{i}, Alias|ObjectPath, L2TPInterfaceListArray);%>;
function l2tpRouteArray(domain, DestIPAddress, DestSubnetMask, IPInterfaceName)
{
    this.domain = domain;
    this.DestIPAddress = DestIPAddress;
    this.DestSubnetMask  = DestSubnetMask;
    this.IPInterfaceName = IPInterfaceName;
}
var l2tpRoute = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPRoute.{i},DestIPAddress|DestSubnetMask|IPInterfaceName,l2tpRouteArray);%>;
var LacRoutes = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPRoute.{i},DestIPAddress|DestSubnetMask|IPInterfaceName,stLacRoute);%>;
var MainDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLAC.{i}.Status,State|RemoteHostName|LocalIPAddress|RemoteIPAddress|LocalTunnelID|RemoteTunnelID|LocalPort|RemotePort|RxPackets|RxBytesLo|RxBytesHi|TxPackets|TxBytesLo|TxBytesHi,MainDhcpInfo);%>;
var LacRoute = new Array();

function ISIPInterfaceNameMatch(item) {
    if (cfgMode.toUpperCase() === 'CTMFTTR') {
        return (item.IPInterfaceName.indexOf("InternetGatewayDevice.X_HW_VPN.L2TPLAC.") >= 0)
               || (item.IPInterfaceName.indexOf("InternetGatewayDevice.X_HW_VPN.PPTPLAC.") >= 0)
    }
    
    return item.IPInterfaceName.indexOf("InternetGatewayDevice.X_HW_VPN.L2TPLAC.") >= 0
}

for (var i = 0; i < LacRoutes.length - 1; i++) {
    LacRoute[i] = LacRoutes[i];
    if (ISIPInterfaceNameMatch(LacRoute[i])) {
        for (var j = 0; j < l2tpInterfaceList.length - 1; j++) {
            if (LacRoute[i].IPInterfaceName == l2tpInterfaceList[j].ObjectPath) {
                LacRoute[i].IPInterfaceName = l2tpInterfaceList[j].Alias;
                break;
            }
        }
    }
}

function LoadFrame() {
    InitRemoteHostNameList('ipInterfaceName');
    InitTunnelAliasList("alias");
    loadlanguage();

    if (LacRoute.length > 0) {
       selectLine(TableName + '_record_0');
       setDisplay('TableConfigInfo',1);
    } else {
       selectLine('record_no');
       setDisplay('TableConfigInfo',0);
    }

    if (cfgMode.toUpperCase() === 'CTMFTTR') {
        setDisplay('routeInterfaceRow', 0);
        setDisplay('ipInterfaceNameRow', 0);
    }
}

function AddSubmitParam(SubmitForm,type) {
    if (CheckForm() == false) {
        return;
    }
    var url;
    var IPInterfaceName = getValue('ipInterfaceName');
    if (getRadioVal("routeInterface") == 0) {
        IPInterfaceName = getValue('alias');
    }

    if (AddFlag == true) {
        SubmitForm.addParameter('x.DestIPAddress', getElById("destIPAddress").value);  
        SubmitForm.addParameter('x.DestSubnetMask', getElById("destSubnetMask").value);
        SubmitForm.addParameter('x.IPInterfaceName', IPInterfaceName);
        
        url = 'addcfg.cgi?'+'x=InternetGatewayDevice.X_HW_VPN.L2TPRoute' + '&RequestFile=html/bbsp/dhcp/vpn_lac_route.asp';
    } else {
        SubmitForm.addParameter('x.DestIPAddress', getElById("destIPAddress").value);  
        SubmitForm.addParameter('x.DestSubnetMask', getElById("destSubnetMask").value); 
        SubmitForm.addParameter('x.IPInterfaceName', IPInterfaceName);
        
        url = 'set.cgi?x=' + LacRoute[selctIndex].domain + '&RequestFile=html/bbsp/dhcp/vpn_lac_route.asp';
    }

    SubmitForm.setAction(url);

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
}

function InitRemoteHostNameList(ipInterfaceNameId) {
    var interfaceNameElement = document.getElementById(ipInterfaceNameId);
    for (var i = 0; i < MainDhcpInfos.length - 1; i++) {
        var option = document.createElement("Option");
        option.value = MainDhcpInfos[i].RemoteHostName;
        option.innerText = MainDhcpInfos[i].RemoteHostName;
        option.text = MainDhcpInfos[i].RemoteHostName;
        interfaceNameElement.appendChild(option);
    }
}

function InitTunnelAliasList(TunnelAliasId) {
    var tunnelAliasElement = document.getElementById(TunnelAliasId);
    for (var i = 0; i < l2tpInterfaceList.length - 1; i++) {
        var option = document.createElement("Option");
        option.value = l2tpInterfaceList[i].ObjectPath;
        option.innerText = l2tpInterfaceList[i].Alias;
        option.text = l2tpInterfaceList[i].Alias;
        tunnelAliasElement.appendChild(option);
    }
}

function setCtlDisplay(record) {
    if (record == null) {
        setText('destIPAddress','');
        setText('destSubnetMask','');
        setSelect('ipInterfaceName','');
    } else {
        setText('destIPAddress',record.DestIPAddress);
        setText('destSubnetMask',record.DestSubnetMask);
        setSelect('ipInterfaceName',record.IPInterfaceName);
        if (cfgMode.toUpperCase() === 'CTMFTTR') {
            setSelect('alias',record.IPInterfaceName);
        }

        if (ISIPInterfaceNameMatch(record)) {
            setRadio('routeInterface', 0);
            setDisable('ipInterfaceName',1);
            setDisable('alias',0);
        } else {
            setRadio('routeInterface', 1);
            setDisable('ipInterfaceName',0);
            setDisable('alias',1);
        }
    }
}

function DeleteLineRow() {
    var tableRow = getElementById(TableName);
    if (tableRow.rows.length > 2) {
        tableRow.deleteRow(tableRow.rows.length - 1);
    }
    return false;
}

var g_Index = -1;
function setControl(index) {
    var record;
    selctIndex = index;

    if (index == -1) {
        record = null;
        AddFlag = true;
        setDisplay('TableConfigInfo', 1);
        setCtlDisplay(record);
        setRadio('routeInterface', 0);
        setDisable('ipInterfaceName',1);
        setDisable('alias',0);
    } else if (index == -2) {
        setDisplay('TableConfigInfo', 0);
    } else {
        record = l2tpRoute[index];
        AddFlag = false;
        setDisplay('TableConfigInfo', 1);
        setCtlDisplay(record);
    }

    g_Index = index;
    setDisable('btnApply_ex',0);
    setDisable('cancel',0);
}

function LacRouteConfigListselectRemoveCnt(val) {

}

function OnDeleteButtonClick(TableID) {
    if (LacRoute.length == 0) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_nooption']);
        return;
    }

    if (selctIndex == -1) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_nosaveoption']);
        return;
    }
    var CheckBoxList = document.getElementsByName(TableName+'rml');
    var Form = new webSubmitForm();
    var Count = 0;
    for (var i = 0; i < CheckBoxList.length; i++) {
        if (CheckBoxList[i].checked != true) {
            continue;
        }
        Count++;
        Form.addParameter(CheckBoxList[i].value,'');
    }
    if (Count <= 0) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_selectoption']);
        return;
    }

    if (ConfirmEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_deloption']) == false) {
        document.getElementById("DeleteButton").disabled = false;
        return;
    }

    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction('del.cgi?' +'x=InternetGatewayDevice.X_HW_VPN.L2TPRoute' + '&RequestFile=html/bbsp/dhcp/vpn_lac_route.asp');
    Form.submit();
        
    setDisable('btnApply_ex',1);
    setDisable('cancel',1);
}

function CheckForm() {
    var IpAddress = getValue('destIPAddress');
    var SubnetMask = getValue('destSubnetMask');
    if (IpAddress == "") {
        AlertEx(dhcpstatic_language['bbsp_ipnull']);
        return false;
    }

    if ((isAbcIpAddress(IpAddress) == false) || (isDeIpAddress(IpAddress) == true) ||
        (isBroadcastIpAddress(IpAddress) == true) || (isLoopIpAddress(IpAddress) == true)) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_mac'] + IpAddress + vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_invalid']);
        return false;
    }

    if (isValidSubnetMask(SubnetMask) == false) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_macmask'] + SubnetMask + vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_invalid']);
        return false;
    }
    if (isMaskOf24BitOrMore(SubnetMask) == false) {
        AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_macmask'] + SubnetMask + vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_invalid'] +
                vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_maskerrorinfo']);
        return false;
    }

    if (getRadioVal("routeInterface") == 0) {
        var alias = getValue('alias');
        if (alias == "") {
            AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_tunnelaliasNamenull']);
            return false;
        }
    } else {
        if (cfgMode.toUpperCase() === 'CTMFTTR') {
            return false;
        }
    
        var ipInterfaceName = getValue('ipInterfaceName');
        if (ipInterfaceName == "") {
            AlertEx(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_ipInterfaceNamenull']);
            return false;
        }
    }
    return true;
}

function Cancel() {
    setDisplay("TableConfigInfo", 0);

    if (AddFlag == true) {
        var tableRow = getElement("dhcpInst");
        
        if (tableRow.rows.length == 1) {
            selectLine('record_no');
        } else if (tableRow.rows.length == 2) {
            addNullInst('LacRoute');
        } else {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    } else {
        setText('destIPAddress',LacRoute[selctIndex].DestIPAddress);
        setText('destSubnetMask',LacRoute[selctIndex].DestSubnetMask);
        setSelect('ipInterfaceName',LacRoute[selctIndex].IPInterfaceName);
        if (cfgMode.toUpperCase() === 'CTMFTTR') {
            setSelect('alias',LacRoute[selctIndex].IPInterfaceName);
        }
    }
    setDisable('btnApply_ex',0);
    setDisable('cancel',0);
}
function radioClick(Obj)
{
    if (Obj.value == 0) {
        setDisable('ipInterfaceName',1);
        setDisable('alias',0);
    } else {
        setDisable('ipInterfaceName',0);
        setDisable('alias',1);
    }
}
</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<script language="JavaScript" type="text/javascript">
  var routeMenu = 'vpn_l2tp_lac_route_mune';
  var routeLanguage = 'vpn_l2tp_lac_route_title';
  if (cfgMode === 'CTMFTTR') {
    routeMenu = 'vpn_lac_route_menu';
    routeLanguage = 'vpn_lac_route_title';
  }
HWCreatePageHeadInfo("dhcpstatic", GetDescFormArrayById(vpn_l2tp_lac_route_language, routeMenu), GetDescFormArrayById(vpn_l2tp_lac_route_language, routeLanguage), false);
</script>
<div class="title_spread"></div>
<script language="JavaScript" type="text/javascript">
    var TableClass = new stTableClass("width_per25", "width_per75", "ltr");
    var ipInterfaceTitle = 'vpn_l2tp_lac_route_ipinterfacetitle';
    if (cfgMode === 'CTMFTTR') {
        ipInterfaceTitle = "vpn_l2tp_lac_route_tunnelalias";
    }

    var DhcpLacRouteConfiglistInfo = new Array(new stTableTileInfo("Empty","align_center","DomainBox"),
                                               new stTableTileInfo("vpn_l2tp_lac_route_mactitle","align_center","DestIPAddress"),
                                               new stTableTileInfo("vpn_l2tp_lac_route_macmasktitle","align_center","DestSubnetMask"),
                                               new stTableTileInfo(ipInterfaceTitle, "align_center","IPInterfaceName"),null);
    var ColumnNum = 4;
    var ShowButtonFlag = true;
    var DhcpStaticTableConfigInfoList = new Array();
    var TableDataInfo = HWcloneObject(LacRoute, 1);
    TableDataInfo.push(null);
    HWShowTableListByType(1, TableName, ShowButtonFlag, ColumnNum, TableDataInfo, DhcpLacRouteConfiglistInfo, vpn_l2tp_lac_route_language, null);
</script>

<form id="TableConfigInfo" style="display:none;"> 
<div class="list_table_spread"></div>
    <table border="0" cellpadding="0" cellspacing="1"  width="100%"> 
        <li   id="destIPAddress"    RealType="TextBox" DescRef="vpn_l2tp_lac_route_mac"         RemarkRef="" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Chaddr" Elementclass="InputDhcp"   InitValue="Empty"/>
        <li   id="destSubnetMask"   RealType="TextBox" DescRef="vpn_l2tp_lac_route_macmask"     RemarkRef="" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Yiaddr" Elementclass="InputDhcp"    InitValue="Empty"/>
        <li   id="routeInterface" RealType="RadioButtonList" DescRef="vpn_l2tp_lac_route_interface" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.routeInterface" InitValue="[{TextRef:'vpn_l2tp_lac_route_tunnelalias',Value:'0'},{TextRef:'vpn_l2tp_lac_route_exithostname',Value:'1'}]" ClickFuncApp="onclick=radioClick"/>
        <li   id="alias" RealType="DropDownList" DescRef="vpn_l2tp_lac_route_tunnelaliastitle" RemarkRef="Empty" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Yiaddr" InitValue="Empty" Elementclass="width_127px"/>
        <li   id="ipInterfaceName" RealType="DropDownList" DescRef="vpn_l2tp_lac_route_ipinterface" RemarkRef="Empty" ErrorMsgRef="Empty" Require="TRUE" BindField="x.Yiaddr" InitValue="Empty" Elementclass="width_127px"/>
    </table>
    <script language="JavaScript" type="text/javascript">
    LacRouteConfigFormList = HWGetLiIdListByForm("TableConfigInfo", null);
    HWParsePageControlByID("TableConfigInfo", TableClass, vpn_l2tp_lac_route_language, null);
    </script>
    <table   cellpadding="0" cellspacing="0" width="100%" class="table_button"> 
       <tr>
          <td class='width_per25'></td>
            <td class="table_submit">
                <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
                <button id="btnApply_ex" name="btnApply_ex" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Submit(2);"/><script>document.write(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_app']);</script></button>
                <button id="cancel" name="cancel" type="button" class="CancleButtonCss buttonwidth_100px" onClick="Cancel();"/><script>document.write(vpn_l2tp_lac_route_language['vpn_l2tp_lac_route_cancel']);</script></button>
            </td>
        </tr>
    </table>
</form>

</body>
</html>

