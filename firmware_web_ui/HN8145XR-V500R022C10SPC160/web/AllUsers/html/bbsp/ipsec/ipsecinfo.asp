<html>
<head>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="javascript" src="../../bbsp/common/managemode.asp"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript" src="../../bbsp/common/<%HW_WEB_DeepCleanCache_Resource(wan_list_info.asp);%>"></script>
<script language="javascript" src="../../bbsp/common/<%HW_WEB_DeepCleanCache_Resource(wan_list.asp);%>"></script> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache">
<title>IPSec Information</title>
<script>

function record_click(id) {
    selectLine(id);
}

var page_version;
if (location.href.indexOf("waninfoe8c.asp?") > 0) {
    page_version = location.href.split("?")[1]; 
}

function stIpSecVPN(domain,Enable,IPSecType,RemoteSubnet,LocalSubnet,IPSecEncapsulationMode,IPSecOutInterface,RemoteIP,RemoteDomain,ExchangeMode,IKEAuthenticationMethod,IKEAuthenticationAlgorithm,IKEEncryptionAlgorithm,IKEDHGroup,IKEIDType,IKELocalName,IKERemoteName,IPSecTransform,ESPAuthenticationAlgorithm,ESPEncryptionAlgorithm,IPSecPFS,AHAuthenticationAlgorithm,IKESAPeriod,IPSecSATimePeriod,IPSecSATrafficPeriod,DPDEnable,DPDThreshold,DPDRetry,X_HW_IKEVersion,ConnectionStatus)
{
    this.domain = domain;
    this.Enable = Enable;
    this.IPSecType = IPSecType;
    this.RemoteSubnet = RemoteSubnet;
    this.LocalSubnet = LocalSubnet;
    this.IPSecEncapsulationMode = IPSecEncapsulationMode;
    this.IPSecOutInterface= IPSecOutInterface;
    this.RemoteIP = RemoteIP;
    this.RemoteDomain = RemoteDomain;
    this.ExchangeMode = ExchangeMode;
    this.IKEAuthenticationMethod = IKEAuthenticationMethod;
    this.IKEAuthenticationAlgorithm = IKEAuthenticationAlgorithm;
    this.IKEEncryptionAlgorithm = IKEEncryptionAlgorithm;
    this.IKEDHGroup = IKEDHGroup;
    this.IKEIDType = IKEIDType;
    this.IKELocalName = IKELocalName;
    this.IKERemoteName = IKERemoteName;
    this.IPSecTransform = IPSecTransform;
    this.ESPAuthenticationAlgorithm = ESPAuthenticationAlgorithm;
    this.ESPEncryptionAlgorithm = ESPEncryptionAlgorithm;
    this.IPSecPFS = IPSecPFS;
    this.AHAuthenticationAlgorithm = AHAuthenticationAlgorithm;
    this.IKESAPeriod = IKESAPeriod;
    this.IPSecSATimePeriod = IPSecSATimePeriod;
    this.IPSecSATrafficPeriod = IPSecSATrafficPeriod;
    this.DPDEnable = DPDEnable;
    this.DPDThreshold = DPDThreshold;
    this.DPDRetry = DPDRetry;
    this.X_HW_IKEVersion = X_HW_IKEVersion;
    this.ConnectionStatus = ConnectionStatus;
    var index = domain.lastIndexOf('A8C_IPSecVPN');
    this.Interface = domain.substr(0,index - 1);
}

var IPSecVPN = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.A8C_IPSecVPN.{i},Enable|IPSecType|RemoteSubnet|LocalSubnet|IPSecEncapsulationMode|IPSecOutInterface|RemoteIP|RemoteDomain|ExchangeMode|IKEAuthenticationMethod|IKEAuthenticationAlgorithm|IKEEncryptionAlgorithm|IKEDHGroup|IKEIDType|IKELocalName|IKERemoteName|IPSecTransform|ESPAuthenticationAlgorithm|ESPEncryptionAlgorithm|IPSecPFS|AHAuthenticationAlgorithm|IKESAPeriod|IPSecSATimePeriod|IPSecSATrafficPeriod|DPDEnable|DPDThreshold|DPDRetry|X_HW_IKEVersion|ConnectionStatus,stIpSecVPN);%>;

function filterWan(WanItem) {
    if (((WanItem.Tr069Flag == '0') && (Instance_IspWlan.IsWanHidden(domainTowanname(WanItem.domain)) == false)) == false) {
        return false;
    }

    return true;
}

var WanInfo = GetWanListByFilter(filterWan);

function SetDivValue(Id, Value)
{
    try {
        var Div = document.getElementById(Id);
        Div.innerHTML = Value;
    } catch(ex) {
    }
}

function LoadFrame() {

}

</script>
</head>
<body class="mainbody" onLoad="LoadFrame();"> 
<script language="javascript" src="../../bbsp/common/ontstate.asp"></script> 
<script language="javascript" src="../../bbsp/common/wanipv6state.asp"></script> 
<script language="javascript" src="../../bbsp/common/wanaddressacquire.asp"></script>
<script language="javascript" src="../../bbsp/common/wandns.asp"></script> 
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<script language="JavaScript" type="text/javascript">

HWCreatePageHeadInfo("ipsecinfoasp", GetDescFormArrayById(ipsecinfo_language, "ipsecinfo_s001"), GetDescFormArrayById(ipsecinfo_language, "ipsecinfo_s002"), false);
</script>
<div class="title_spread"></div>
<script type="text/javascript" language="javascript">
if (navigator.appName == "Microsoft Internet Explorer") {
    document.write('<div  id="IPTable" style="overflow-x:auto;overflow-y:hidden;width:100%;">');
} else {
    document.write('<div  id="IPTable" style="overflow-x:auto;overflow-y:hidden;width:667;">');
}

</script>

<table class="tabal_bg width_100p"  cellspacing="1" id="IPsecPanel" style="width:100%;"> 
  <tr class="head_title">  
    <td id = "Table_wan_ipv4_1_1_table" nowrap BindText='ipsecinfo_s023'></td>
    <td id = "Table_wan_ipv4_1_2_table" nowrap BindText='ipsecinfo_s024'></td>
    <td id = "Table_wan_ipv4_1_3_table" nowrap BindText='ipsecinfo_s003'></td>
    <td id = "Table_wan_ipv4_1_4_table" nowrap BindText='ipsecinfo_s025'></td>
    <td id = "Table_wan_ipv4_1_5_table" nowrap BindText='ipsecinfo_s026'></td>
  </tr>
    <script type="text/javascript" language="javascript">

    function replaceSpace(str) {
        if (str.indexOf(" ") != -1) {
            str=str.replace(/ /g, "&#160;");
        }
        return str;
    }

    function AddTimeUnit(time,timeunit) {
        if ((time == 0) || (time == "--")) {
            return time;
        } else if (time == undefined) {
            return '--';
        } else {
            return time +" "+ timeunit;
        }
    }

    function GetWanName(WanInfo, Index) {
        var wanName = '--';
        for (var i = 0; i < WanInfo.length; i++) {
            if (WanInfo[i].domain == IPSecVPN[Index].IPSecOutInterface) {
                wanName = MakeWanName1(WanInfo[i]);
                return wanName;
            }
        }
        return wanName;
    }

    function SubnetShow(IPSecType) {
        if (IPSecType == 'Site-to-Site') {
            setDisplay('LocalSubnet_textRow', 1);
            setDisplay('RemoteSubnet_textRow', 1);
        } else if (IPSecType == 'PC-to-Site') {
            setDisplay('LocalSubnet_textRow', 1);
            setDisplay('RemoteSubnet_textRow', 0);
        }
    }

    function IKEIDTypeShow(IKEIDType) {
        if (IKEIDType == 'IP') {
            setDisplay('IKELocalName_textRow', 0);
            setDisplay('IKERemoteName_textRow', 0);
        } else if (IKEIDType == 'Name') {
            setDisplay('IKELocalName_textRow', 1);
            setDisplay('IKERemoteName_textRow', 1);
        }
    }

    function IKEVersionShow(IKEVersion) {
        if (IKEVersion == 'IKEv1') {
            setDisplay('ExchangeMode_textRow', 1);
        } else if (IKEVersion == 'IKEv2') {
            setDisplay('ExchangeMode_textRow', 0);
        }
    }

    function DisplayIPSecDetail(Index) {
        SubnetShow(IPSecVPN[Index].IPSecType);
        IKEIDTypeShow(IPSecVPN[Index].IKEIDType);
        IKEVersionShow(IPSecVPN[Index].X_HW_IKEVersion);
        var show_ExchangeMode = '';
        var show_IKEAuthenticationMethod = '';
        if (IPSecVPN[Index].ExchangeMode == 'Main') {
            show_ExchangeMode = ipsecinfo_language['ipsecinfo_s027'];
        } else if (IPSecVPN[Index].ExchangeMode == 'Aggressive') {
            show_ExchangeMode = ipsecinfo_language['ipsecinfo_s028'];
        }

        if (IPSecVPN[Index].IKEAuthenticationMethod == 'PreShareKey') {
            show_IKEAuthenticationMethod = ipsecinfo_language['ipsecinfo_s029'];
        } else if (IPSecVPN[Index].IKEAuthenticationMethod == 'RsaSignature') {
            show_IKEAuthenticationMethod = ipsecinfo_language['ipsecinfo_s030'];
        }

        document.getElementById("IPSecDetail").style.display = "";
        setElementInnerHtmlById("IPSecOutInterfacetitle", GetWanName(WanInfo, Index));
        setElementInnerHtmlById("LocalSubnet", IPSecVPN[Index].LocalSubnet);
        setElementInnerHtmlById("RemoteSubnet", IPSecVPN[Index].RemoteSubnet);
        setElementInnerHtmlById("ExchangeMode", show_ExchangeMode);
        setElementInnerHtmlById("IKEAuthenticationMethod", show_IKEAuthenticationMethod);
        setElementInnerHtmlById("IKEIDType", IPSecVPN[Index].IKEIDType);
        setElementInnerHtmlById("IKELocalName", IPSecVPN[Index].IKELocalName);
        setElementInnerHtmlById("IKERemoteName", IPSecVPN[Index].IKERemoteName);
        
        setNoEncodeInnerHtmlValue("IKESAPeriod", AddTimeUnit(IPSecVPN[Index].IKESAPeriod, ipsecinfo_language['ipsecinfo_s004']));
        setNoEncodeInnerHtmlValue("IPSecSATimePeriod", AddTimeUnit(IPSecVPN[Index].IPSecSATimePeriod, ipsecinfo_language['ipsecinfo_s004']));
        setNoEncodeInnerHtmlValue("IPSecSATrafficPeriod", AddTimeUnit(IPSecVPN[Index].IPSecSATrafficPeriod, 'KB'));
        
    }

    function setControl(Index) {
        DisplayIPSecDetail(Index);
    }

    function getVirtualServerId(tableID, colID) {
        var VirtualServerListId = "VirtualServer_" + tableID + "_" + colID + "_table";
        return VirtualServerListId;
    }

    var html = '' ;
    var showEnable = '';
    var showConnectionStatus = '';
    var showIPSecEncapsulationMode = '';
    var showConnectionStatus = '';
    var showIPSecType = '';
    var showRemoteIP = '';
    for (i = 0; i < IPSecVPN.length - 1; i++) {
        var tableID = i + 2;

        html += '<TR id=record_' + i +' class="tabal_01" align="center" onclick="record_click(this.id);">';
                
        if (IPSecVPN[i].Enable == '1') {
            showEnable = ipsecinfo_language['ipsecinfo_s031'];
        } else {
            showEnable = ipsecinfo_language['ipsecinfo_s032'];
        }
        if (IPSecVPN[i].ConnectionStatus == 'Unconfigured') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s005'];
        } else if (IPSecVPN[i].ConnectionStatus == 'PhaseI_Connecting') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s006'];
        } else if (IPSecVPN[i].ConnectionStatus == 'PhaseII_Connecting') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s007'];
        } else if (IPSecVPN[i].ConnectionStatus == 'Connected') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s008'];
        } else if (IPSecVPN[i].ConnectionStatus == 'Disconnecting') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s009'];
        } else if (IPSecVPN[i].ConnectionStatus == 'Disconnected') {
            showConnectionStatus = ipsecinfo_language['ipsecinfo_s010'];
        }
        if (IPSecVPN[i].IPSecType == 'Site-to-Site') {
            showIPSecType = ipsecinfo_language['ipsecinfo_s033'];
        } else if (IPSecVPN[i].IPSecType == 'PC-to-Site') {
            showIPSecType = ipsecinfo_language['ipsecinfo_s034'];
        }
        if (IPSecVPN[i].IPSecEncapsulationMode == 'Transport') {
            showIPSecEncapsulationMode = ipsecinfo_language['ipsecinfo_s036'];
        } else if (IPSecVPN[i].IPSecEncapsulationMode == 'Tunnel') {
            showIPSecEncapsulationMode = ipsecinfo_language['ipsecinfo_s035'];
        } else {
            showIPSecEncapsulationMode = '';
        }
        if (IPSecVPN[i].RemoteDomain != '') {
            showRemoteIP = IPSecVPN[i].RemoteDomain
        } else if (IPSecVPN[i].RemoteIP != '') {
            showRemoteIP = IPSecVPN[i].RemoteIP
        } else {
            showRemoteIP = '';
        }
        
        if (IPSecVPN[i].IPSecType == 'PC-to-Site') {
            showRemoteIP = '--';
        }
        html +=  '<TD id=' + getVirtualServerId(tableID,1) + '>' + showEnable + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,2) + '>' + showRemoteIP + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,3) + '>' + showConnectionStatus + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,4) + '>' + showIPSecType + '</TD>';
        html +=  '<TD id=' + getVirtualServerId(tableID,5) + '>' + showIPSecEncapsulationMode + '</TD>';
        html += '</TR>';
    }
    document.write(html);

    if(IPSecVPN.length == 1) {
        document.write("<tr class= \"tabal_center01\">");
        document.write('<td >'+'--'+'</td>');
        document.write('<td >'+'--'+'</td>');
        document.write('<td >'+'--'+'</td>');
        document.write('<td >'+'--'+'</td>');
        document.write('<td >'+'--'+'</td>');
        document.write("</tr>");
    }
    </script>
</table> 

<div  align='center' style="display:none" id="IPSecDetail">
<table id="table_ipsecdetail" class="tabal_bg width_100p"  cellspacing="1" style="width:100%;"> 
  <tr class="head_title align_left"> 
    <td  colspan="8" BindText='ipsecinfo_s011'></td> 
  </tr> 

  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s012'></td>
    <td  width="70%" id="IPSecOutInterfacetitle"></td>
  </tr>
  
  <tr class="tabal_01 align_left" id="LocalSubnet_textRow">
    <td  width="30%" BindText='ipsecinfo_s013'></td>
    <td  width="70%" id="LocalSubnet"></td>
  </tr>
  
  <tr class="tabal_01 align_left" id="RemoteSubnet_textRow">
    <td  width="30%" BindText='ipsecinfo_s014'></td>
    <td  width="70%" id="RemoteSubnet"></td>
 </tr>
  
  <tr class="tabal_01 align_left" id="ExchangeMode_textRow">
    <td  width="30%" BindText='ipsecinfo_s015'></td>
    <td  width="70%" id="ExchangeMode"></td>
  </tr>
  
  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s016'></td>
    <td  width="70%" id="IKEAuthenticationMethod"></td>
  </tr>

  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s017'></td>
    <td  width="70%" id="IKEIDType"></td>
  </tr>
  <tr class="tabal_01 align_left" id="IKELocalName_textRow">
    <td  width="30%" BindText='ipsecinfo_s018'></td>
    <td  width="70%" id="IKELocalName"></td>
  </tr>
  <tr class="tabal_01 align_left" id="IKERemoteName_textRow">
    <td  width="30%" BindText='ipsecinfo_s019'></td>
    <td  width="70%" id="IKERemoteName"></td>
  </tr>

  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s020'></td>
    <td  width="70%" id="IKESAPeriod"></td>
  </tr>
  
  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s021'></td>
    <td  width="70%" id="IPSecSATimePeriod"></td>
  </tr>
  
  <tr class="tabal_01 align_left">
    <td  width="30%" BindText='ipsecinfo_s022'></td>
    <td  width="70%" id="IPSecSATrafficPeriod"></td>
  </tr>
</table>
</div>
<script type="text/javascript" language="javascript">
    ParseBindTextByTagName(ipsecinfo_language, "td", 1);
</script>
<div class="func_spread"></div>

</div>  
</body>
</html>
