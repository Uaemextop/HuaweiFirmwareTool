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

function MainDhcpInfo(domain, State, LocalHostName, PNSAddress, RxPackets, RxBytes, TxPackets, TxBytes) {
    this.domain = domain;
    this.State = State;
    this.LocalHostName = LocalHostName;
    this.PNSAddress = PNSAddress;
    this.RxPackets = RxPackets;
    this.RxBytes = RxBytes;
    this.TxPackets = TxPackets;
    this.TxBytes = TxBytes;
}

function stVPN_PPTP_LAC(domain, Enable, TunnelName, UserId, PNSAddress, LocalHostName, WANInterface) {
    this.domain = domain;
    this.Enable = Enable;
}

var MainDhcpInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.PPTPLAC.{i}.Status,State|LocalHostName|PNSAddress|RxPackets|RxBytes|TxPackets|TxBytes,MainDhcpInfo);%>;

var VPN_PPTP_LAC = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.PPTPLAC.{i}, Enable, stVPN_PPTP_LAC);%>;

var ispptpstatOK = 0;
if((VPN_PPTP_LAC.length - 1) > 0)
{
    ispptpstatOK = 1;
}

function setControl(index) {
    var record;
    if (index == -1) {
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        setDisplay('ConfigForm', 1);

        if (ispptpstatOK == 0) {
            document.getElementById("status_State").innerText = "";
            document.getElementById("status_LocalHostName").innerText = "";
            document.getElementById("status_PNSAddress").innerText = "";
            document.getElementById("status_RxPackets").innerText = 0;
            document.getElementById("status_RxBytes").innerText = 0;
            document.getElementById("status_TxPackets").innerText = 0;
            document.getElementById("status_TxBytes").innerText = 0;
        } else {
            document.getElementById("status_State").innerText = MainDhcpInfos[index].State;
            document.getElementById("status_LocalHostName").innerText = MainDhcpInfos[index].LocalHostName;
            document.getElementById("status_PNSAddress").innerText = MainDhcpInfos[index].PNSAddress;
            document.getElementById("status_RxPackets").innerText = MainDhcpInfos[index].RxPackets;
            document.getElementById("status_RxBytes").innerText = MainDhcpInfos[index].RxBytes;
            document.getElementById("status_TxPackets").innerText = MainDhcpInfos[index].TxPackets;
            document.getElementById("status_TxBytes").innerText = MainDhcpInfos[index].TxBytes;
        }

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
        b.innerHTML = vpn_pptp_lac_status_dhcp_language[b.getAttribute("BindText")];
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
    HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vpn_pptp_lac_status_dhcp_language, "vpn_pptp_lac_status_mune"), GetDescFormArrayById(vpn_pptp_lac_status_dhcp_language, "vpn_pptp_lac_status_title"), false);
</script> 
<div class="title_spread"></div>
    <table class='tabal_bg width_per100' border="0" align="center" cellpadding="0" cellspacing="1" id="dhcpinfodat"> 
    <tr class="head_title"> 
        <td BindText = 'vpn_pptp_lac_status_LocalHostName_title'></td> 
        <td BindText = 'vpn_pptp_lac_status_PNSAddress_title'></td> 
    </tr>
    <script language="JavaScript" type="text/javascript"> 
        if ((MainDhcpInfos.length - 1) == 0) {
            if (ispptpstatOK == 0) {
                document.write('<TR id="record_no"' + ' class="tabal_center01 ">');
            } else {
                document.write('<TR id="record_0"' + '" onclick="selectLine(this.id);" class="tabal_01" align="center">');
            }
            ispptpstatOK = 0;
            document.write('<td>--</td>');
            document.write('<td>--</td> </TR>');
        } else {
            for (i = 0; i < (MainDhcpInfos.length - 1); i++) {
                ispptpstatOK = 1;
                document.write('<tr id="record_' + i + '" onclick="selectLine(this.id);" class="tabal_01" align="center">');
                document.write('<td>'+ MainDhcpInfos[i].LocalHostName +'</td>');
                document.write('<td>'+ MainDhcpInfos[i].PNSAddress +'</td>');
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
                <td BindText='vpn_pptp_lac_status_title1'></td>
                </tr>
            </table>
            <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_State"></td>
                <td class="table_right width_per75" id='status_State'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_LocalHostName"></td>
                <td class="table_right" id='status_LocalHostName'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_PNSAddress"></td>
                <td class="table_right" id='status_PNSAddress'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_RxPackets"></td>
                <td class="table_right" id='status_RxPackets'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_RxBytes"></td>
                <td class="table_right" id='status_RxBytes'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_TxPackets"></td>
                <td class="table_right" id='status_TxPackets'></td>
             </tr>
             <tr class="table_title">
                <td class="table_title" BindText="vpn_pptp_lac_status_TxBytes"></td>
                <td class="table_right" id='status_TxBytes'></td>
             </tr>
          </table></td> 
      </tr>	  
    </table> 
 </div>  
</form>
</body>
</html>
