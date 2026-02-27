<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>

<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../common/managemode.asp"></script>
<script language="javascript" src="../common/topoinfo.asp"></script>
<script language="javascript" src="../common/lanuserinfo.asp"></script>                                      

<title>Dhcp Information</title>
<script language="JavaScript" type="text/javascript">

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

var MainDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.L2TPLAC.{i}.Status,State|RemoteHostName|LocalIPAddress|RemoteIPAddress|LocalTunnelID|RemoteTunnelID|LocalPort|RemotePort|RxPackets|RxBytesLo|RxBytesHi|TxPackets|TxBytesLo|TxBytesHi,MainDhcpInfo);%>;

function setControl(index) {
    var record;
    if (index == -1) {
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        setDisplay('ConfigForm', 1);

        document.getElementById("status_State").innerText           = MainDhcpInfos[index].State;
        document.getElementById("status_RemoteHostName").innerText  = MainDhcpInfos[index].RemoteHostName;
        document.getElementById("status_LocalIPAddress").innerText  = MainDhcpInfos[index].LocalIPAddress;
        document.getElementById("status_LocalPort").innerText       = MainDhcpInfos[index].LocalPort;
        document.getElementById("status_RemoteIPAddress").innerText = MainDhcpInfos[index].RemoteIPAddress;
        document.getElementById("status_RemotePort").innerText      = MainDhcpInfos[index].RemotePort;
        document.getElementById("status_LocalTunnelID").innerText   = MainDhcpInfos[index].LocalTunnelID;
        document.getElementById("status_RemoteTunnelID").innerText  = MainDhcpInfos[index].RemoteTunnelID;
        document.getElementById("status_RxPackets").innerText       = MainDhcpInfos[index].RxPackets;
        document.getElementById("status_RxBytes").innerText         = MainDhcpInfos[index].RxBytesLo;
        document.getElementById("status_TxPackets").innerText       = MainDhcpInfos[index].TxPackets;
        document.getElementById("status_TxBytes").innerText         = MainDhcpInfos[index].TxBytesLo;
    }
}

function setDisplay(sId, sh) {
    var status;
    if (sh > 0) {
        status = "";
    } else {
        status = "none";
    }
    var item = getElement(sId);
    if (item != null) {
        getElement(sId).style.display = status;
    }
}

function loadlanguage() {
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++)  {
        var b = all[i];
        if (b.getAttribute("BindText") == null) {
            continue;
        }
        b.innerHTML = vpn_l2tp_lac_status_dhcp_language[b.getAttribute("BindText")];
    }
}

function LoadFrame() {
    loadlanguage();
}


function CheckForm(type)
{
    with (getElById ("ConfigForm"))
    {
    }
    return true;
}

function AddSubmitParam(SubmitForm,type) {
}
</script>
</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<form id="Configure"> 
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vpn_l2tp_lac_status_dhcp_language, "vpn_l2tp_lac_status_mune"), GetDescFormArrayById(vpn_l2tp_lac_status_dhcp_language, "vpn_l2tp_lac_status_title"), false);
</script> 
<div class="title_spread"></div>
    <table class='tabal_bg width_per100' border="0" align="center" cellpadding="0" cellspacing="1" id="dhcpinfodat"> 
    <tr class="head_title"> 
        <td BindText = 'vpn_l2tp_lac_status_RemoteHostName_title'></td> 
        <td BindText = 'vpn_l2tp_lac_status_LocalIPAddress_title'></td> 
        <td BindText = 'vpn_l2tp_lac_status_LocalPort_title'></td> 
        <td BindText = 'vpn_l2tp_lac_status_RemoteIPAddress_title'></td>
        <td BindText = 'vpn_l2tp_lac_status_RemotePort_title'></td> 
        <td BindText = 'vpn_l2tp_lac_status_LocalTunnelID_title'></td> 
        <td BindText = 'vpn_l2tp_lac_status_RemoteTunnelID_title'></td>
    </tr> 

    <script language="JavaScript" type="text/javascript"> 
        if ((MainDhcpInfos.length-1) == 0) {
            document.write('<TR id="record_no"' + ' class="tabal_center01 ">');
            document.write('<td>--</td>');
            document.write('<td>--</td>');
            document.write('<td>--</td>');
            document.write('<td>--</td>');
            document.write('<td>--</td>');
            document.write('<td>--</td>');
            document.write('<td>--</td></tr>');
        } else {
            for (i=0; i < (MainDhcpInfos.length - 1); i++) {
                document.write('<tr id="record_' + i + '" onclick="selectLine(this.id);" class="tabal_01" align="center">');
                document.write('<td>'+MainDhcpInfos[i].RemoteHostName+'</td>');
                document.write('<td>'+MainDhcpInfos[i].LocalIPAddress+'</td>');
                document.write('<td>'+MainDhcpInfos[i].LocalPort+'</td>');
                document.write('<td>'+MainDhcpInfos[i].RemoteIPAddress+'</td>');
                document.write('<td>'+MainDhcpInfos[i].RemotePort+'</td>');
                document.write('<td>'+MainDhcpInfos[i].LocalTunnelID+'</td>');
                document.write('<td>'+MainDhcpInfos[i].RemoteTunnelID+'</td></tr>');
            }
        }
    </script>
    </table>
<div id="ConfigForm" style="display:none">
    <table class="tabal_bg" cellpadding="0" cellspacing="1" border="0" id="cfg_table" width="100%"> 
      <tr> 
        <td> <table cellpadding="0" cellspacing="1" class="tabal_bg" width="100%">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr class="tabal_head">
                <td BindText='vpn_l2tp_lac_status_title1'></td>
                </tr>
            </table>
            <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_State"></td>
                <td class="table_right width_per75" id='status_State'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RemoteHostName"></td>
                <td class="table_right" id='status_RemoteHostName'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_LocalIPAddress"></td>
                <td class="table_right" id='status_LocalIPAddress'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_LocalPort"></td>
                <td class="table_right" id='status_LocalPort'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RemoteIPAddress"></td>
                <td class="table_right" id='status_RemoteIPAddress'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RemotePort"></td>
                <td class="table_right" id='status_RemotePort'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_LocalTunnelID"></td>
                <td class="table_right" id='status_LocalTunnelID'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RemoteTunnelID"></td>
                <td class="table_right" id='status_RemoteTunnelID'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RxPackets"></td>
                <td class="table_right" id='status_RxPackets'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_RxBytes"></td>
                <td class="table_right" id='status_RxBytes'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_TxPackets"></td>
                <td class="table_right" id='status_TxPackets'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_l2tp_lac_status_TxBytes"></td>
                <td class="table_right" id='status_TxBytes'></td>
             </tr>
          </table></td> 
      </tr>	  
    </table> 
 </div>  
</form>
</body>
</html>
