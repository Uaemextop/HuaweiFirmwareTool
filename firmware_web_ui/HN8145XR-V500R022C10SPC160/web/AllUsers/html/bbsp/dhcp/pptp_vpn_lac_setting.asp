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
<title>PPTPLACQOPTION</title>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>

<script language="JavaScript" type="text/javascript">

var UnSupportIpv6 = '<%HW_WEB_GetFeatureSupport(FT_CWMP_SUPPORT_IPV6);%>'
var appName = navigator.appName;
var PPTPAddFlag = false;
var selctOptionIndex = -1;
var pptptypename = null;

function loadlanguage() {
    var all = document.getElementsByTagName("td");
    for (var i = 0; i < all.length ; i++) {
        var b = all[i];
        if (b.getAttribute("BindText") == null) {
            continue;
        }
        b.innerHTML = vpn_pptp_lac_setting_language[b.getAttribute("BindText")];
    }
}

function stVPN_PPTP_LAC(domain, Enable, PNSAddress, PNSPort, UserId, LocalHostName, WANInterface) {
    this.domain = domain;
    this.Enable = Enable;
    this.PNSAddress = PNSAddress;
    this.PNSPort = PNSPort;
    this.UserId = UserId;
    this.LocalHostName = LocalHostName;
    this.WANInterface = WANInterface;
}

var MASK = '********************************';
function stVPN_PPTP_PPPCONFIG(domain, NatEnable, AuthenticationProtocol, UserName) {
    this.domain = domain;
    this.NatEnable = NatEnable;
    this.AuthenticationProtocol = AuthenticationProtocol;
    this.UserName = UserName;
    this.Password = MASK;
}

var VPN_PPTP_LAC = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.PPTPLAC.{i}, Enable|PNSAddress|PNSPort|UserId|LocalHostName|WANInterface, stVPN_PPTP_LAC);%>;
var VPN_PPTP_PPPCONFIG = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_VPN.PPTPLAC.{i}.PPPCONFIG.{i}, NatEnable|AuthenticationProtocol|UserName, stVPN_PPTP_PPPCONFIG);%>;

var PPtpLacNum = 0;
var pptpLacInst = new Array();

for (var i = 0; i < VPN_PPTP_LAC.length - 1; i++) {
    pptpLacInst[PPtpLacNum++] = VPN_PPTP_LAC[i];
}

function trim(str)
{
   if (str.charAt(0) == " ") {
      str = str.substring(1, str.length);
      str = trim(str);
   }
   if (str.charAt(str.length - 1) == " ") {
      str = str.substring(0, str.length - 1);
      str = trim(str);
   }
   return str;
}

function AddSubmitParam(SubmitForm, type) {
    var url;
    var selectObj = getElement('WANInterface');
    var index = 0;
    var idx = 0;
 
    index = parseInt(selectObj.selectedIndex, 10);
    if (index < 0) {
         AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_wan']);
         return false;
    }
    idx = selectObj.options[index].id.split('_')[1];
    SubmitForm.addParameter('x.Enable', getCheckVal("lac_enable"));
    SubmitForm.addParameter('x.PNSAddress', getElById("lac_PNSAddress").value); 
    SubmitForm.addParameter('x.PNSPort', getElById("lac_PNSPort").value);  
    SubmitForm.addParameter('x.LocalHostName', getElById("lac_LocalHostName").value); 
    SubmitForm.addParameter('x.WANInterface', getSelectVal("WANInterface"));
    SubmitForm.addParameter('y.NatEnable', getCheckVal("nat_enable")); 
    SubmitForm.addParameter('y.AuthenticationProtocol', "CHAP");
    SubmitForm.addParameter('y.UserName', getElById("lac_UserName").value);
    var lacPasswd = getElById("lac_Password").value;
    if (lacPasswd !== MASK) {
      SubmitForm.addParameter('y.Password', lacPasswd);
    }

    if (PPTPAddFlag == true) {
        url = 'addcfg.cgi?x=InternetGatewayDevice.X_HW_VPN.PPTPLAC' + '&y=x.PPPCONFIG' +
              '&RequestFile=html/bbsp/dhcp/pptp_vpn_lac_setting.asp';
    } else {
        url = 'set.cgi?x=' + VPN_PPTP_LAC[selectedIndex].domain + '&y=' + VPN_PPTP_PPPCONFIG[selectedIndex].domain +
              '&RequestFile=html/bbsp/dhcp/pptp_vpn_lac_setting.asp';
    }
    
    SubmitForm.setAction(url);
    
    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
}

function isSafeCharSN(val)
{
    if ( ( val == '<' )
      || ( val == '>' )
      || ( val == '\'' )
      || ( val == '\"' )
      || ( val == ' ' )
      || ( val == '%' )
      || ( val == '#' )
      || ( val == '{' )
      || ( val == '}' )
      || ( val == '\\' )
      || ( val == '|' )
      || ( val == '^' )
      || ( ( val == '[' ) && (0 == UnSupportIpv6) )
      || ( ( val == ']' ) && (0 == UnSupportIpv6) ) )
	{
	    return false;
	}
	
    return true;
}

function isSafeStringSN(val)
{
	if ( val == "" )
	{
		return false;
	}

	for ( var j = 0 ; j < val.length ; j++ )
	{
		if ( !isSafeCharSN(val.charAt(j)) )
		{
			return false;
		}
	}

	return true;
}

function CheckForm(type) {
    var lnsAddress = getElById("lac_PNSAddress").value;
    if ((trim(lnsAddress).length == 0) || (lnsAddress.length > 256)) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_lnsaddress_invalid']);
        return false;
    }

    if (!isSafeStringSN(lnsAddress)) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_PNSAddress'] + lnsAddress + vpn_pptp_lac_setting_language['vpn_pptp_lac_isinvalidp']);
        return false;
    }

    var localHostName = getElById("lac_LocalHostName").value;
    if (!isSafeStringSN(localHostName)) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_LocalHostName'] + localHostName + vpn_pptp_lac_setting_language['vpn_pptp_lac_isinvalidp']);
        return false;
    }

    if ((isNum(getElById("lac_PNSPort").value) == false) || 
        (((parseInt(getElById("lac_PNSPort").value,10) >= 1) && (parseInt(getElById("lac_PNSPort").value,10) <= 65535)) == false)) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_PNSPort'] + getElById("lac_PNSPort").value + 
        vpn_pptp_lac_setting_language['vpn_pptp_lac_isinvalidp']);
        return false;
    }

    if (getSelectVal("WANInterface") == "") {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_WANInterface_title'] + vpn_pptp_lac_setting_language['vpn_pptp_lac_invalid_wan']);
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

    if (Wan.X_HW_VXLAN_Enable == 1) {
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
    if (PPtpLacNum == 0) {
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
        if ((VPN_PPTP_LAC.length - 1) >= 1) {
            AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_invalid_num']);
            return false;
        }
        PPTPAddFlag = true;
        setDisplay('ConfigForm', 1);
        setCheck('lac_enable', 0);
        setText('lac_PNSAddress', "");
        setText('lac_PNSPort', "1723");
        setText('lac_LocalHostName', "");
        setSelect('WANInterface', "");
        setCheck('nat_enable', 0);
        setText('lac_UserName', "");
        setText('lac_Password', "");
    } else if (index == -2) {
        setDisplay('ConfigForm', 0);
    } else {
        PPTPAddFlag = false;
        setDisplay('ConfigForm', 1);
        option1 = document.getElementById("rml" + index).value;
        for (var i = 0; i < VPN_PPTP_LAC.length - 1 ; i++) {
            if (option1 == VPN_PPTP_LAC[i].domain) {
                setCheck('lac_enable', VPN_PPTP_LAC[i].Enable);

                if (VPN_PPTP_LAC[i].Enable == 0) {
                    setDisable('lac_PNSAddress',1);
                    setDisable('lac_PNSPort',1);
                    setDisable('lac_LocalHostName',1);
                    setDisable('WANInterface',1);
                    setDisable('lac_UserName',1);
                    setDisable('lac_Password',1);
                } else {
                    setDisable('lac_PNSAddress',0);
                    setDisable('lac_PNSPort',0);
                    setDisable('lac_LocalHostName',0);
                    setDisable('WANInterface',0);
                    setDisable('lac_UserName',0);
                    setDisable('lac_Password',0);
                }

                setText('lac_PNSAddress', VPN_PPTP_LAC[i].PNSAddress);
                setText('lac_PNSPort', VPN_PPTP_LAC[i].PNSPort);
                setText('lac_LocalHostName', VPN_PPTP_LAC[i].LocalHostName);
                setSelect('WANInterface', VPN_PPTP_LAC[i].WANInterface);
                setCheck('nat_enable', VPN_PPTP_PPPCONFIG[i].NatEnable);
                setText('lac_UserName', VPN_PPTP_PPPCONFIG[i].UserName);
                setText('lac_Password', VPN_PPTP_PPPCONFIG[i].Password);    
                selectedIndex = i;
            }
        }
    }

    setDisable('btnApply1', 0);
    setDisable('cancelValue', 0);
}

function lacEnable() {
    if (getCheckVal("lac_enable") == 0) {
        setDisable('lac_PNSAddress',1);
        setDisable('lac_PNSPort',1);
        setDisable('lac_LocalHostName',1);
        setDisable('WANInterface',1);
        setDisable('lac_UserName',1);
        setDisable('lac_Password',1);
    } else {
        setDisable('lac_PNSAddress',0);
        setDisable('lac_PNSPort',0);
        setDisable('lac_LocalHostName',0);
        setDisable('WANInterface',0);
        setDisable('lac_UserName',0);
        setDisable('lac_Password',0);
    }
}

function selectRemoveCnt(obj) {
}

function clickRemove() {
    if (PPtpLacNum == 0) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_nooption']);
        return;
    }

    if (selctOptionIndex == -1) {
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_nosaveoption']);
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
        AlertEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_selectoption']);
        return ;
    }

    if (ConfirmEx(vpn_pptp_lac_setting_language['vpn_pptp_lac_deloption']) == false) {
        document.getElementById("DeleteButton").disabled = false;
        return;
    }

    setDisable('btnApply1', 1);
    setDisable('cancelValue', 1);
    removeInst('html/bbsp/dhcp/pptp_vpn_lac_setting.asp');
}

function CancelConfig() {
    setDisplay("ConfigForm", 0);

    if (selctOptionIndex == -1) {
        var tableRow = getElement("PPTPOptionInst");
        if (tableRow.rows.length == 1) {
        } else if (tableRow.rows.length = 2) {
            addNullInst('PPTPLACQOPTION');
        } else {
            tableRow.deleteRow(tableRow.rows.length-1);
            selectLine('record_0');
        }
    } else {
        var optionrecord = pptpLacInst[selctOptionIndex];
        setCtlDisplay(optionrecord);
    }
}

</script>

</head>
<body onLoad="LoadFrame();" class="mainbody"> 
<form id="CoForm" action="../application/set.cgi"> 
<script language="JavaScript" type="text/javascript">
    HWCreatePageHeadInfo("wandhcpparatitle", GetDescFormArrayById(vpn_pptp_lac_setting_language, "vpn_pptp_lac_mune"), GetDescFormArrayById(vpn_pptp_lac_setting_language, "vpn_pptp_lac_title"), false);
</script> 
<div class="title_spread"></div>

<script language="JavaScript" type="text/javascript">
    writeTabCfgHeader('PPTPLACQOPTION','100%');
</script> 
<table class="tabal_bg" id="PPTPOptionInst" width="100%"  cellpadding="0" cellspacing="1"> 
  <tr class="head_title"> 
    <td class="tabal_left width_10p">&nbsp;</td> 
    <td class="tabal_left width_24p" BindText='vpn_pptp_lac_PNSAddress_title'></td>
    <td class="tabal_left width_24p" BindText='vpn_pptp_lac_PNSPort_title'></td>  
    <td class="tabal_left width_24p" BindText='vpn_pptp_lac_LocalHostName_title'></td>  
    <td class="tabal_left width_24p" BindText='vpn_pptp_lac_WANInterface_title'></td> 
  </tr> 
    <script language="JavaScript" type="text/javascript">
        if (PPtpLacNum == 0) {
            document.write('<TR id="record_no"' +' class="tabal_center01 " onclick="selectLine(this.id);">');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('<TD >--</TD>');
            document.write('</TR>');
        } else {
            for (var i = 0; i < PPtpLacNum; i++) {
                document.write('<TR id="record_' + i +'" class="tabal_01  restrict_dir_ltr" align="center" onclick="selectLine(this.id);">');
                document.write('<TD >' + '<input id = "rml'+i+'" type="checkbox" name="rml" value="' + pptpLacInst[i].domain +'" onclick="selectRemoveCnt(this);">' + '</TD>');
                document.write('<TD >' + pptpLacInst[i].PNSAddress + '</TD>');  
                document.write('<TD >' + pptpLacInst[i].PNSPort + '</TD>'); 
                document.write('<TD >' + pptpLacInst[i].LocalHostName + '</TD>'); 
                if (pptpLacInst[i].WANInterface == "") {
                    document.write('<TD >--</TD>');
                } else {
                    document.write('<TD >' + MakeWanName(getWanOfStaticRoute(pptpLacInst[i].WANInterface)) + '</TD>'); 
                }
                document.write('</TR>');
            }
        }
    </script> 
</table> 
<div id="ConfigForm" style="display:none"> 
  <table cellpadding="0" cellspacing="1" width="100%" class="tabal_bg">
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_enable'></td>
        <td class="table_right"> <input id='lac_enable' type='checkbox' name='lac_enable' onclick="lacEnable();"></td> 
        </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_nat_enable'></td>
        <td class="table_right"> <input id='nat_enable' type='checkbox' name='nat_enable'></td> 
        </tr>  
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_PNSAddress'></td>
        <td class="table_right"> <input id='lac_PNSAddress' type='text' name='lac_PNSAddress' maxlength='256' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_PNSAddressmh']);</script></span></td> 
        </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_PNSPort'></td>
        <td class="table_right"> <input id='lac_PNSPort' type='text' name='lac_PNSPort' maxlength='256' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_PNSPortmh']);</script></span></td> 
        </tr>
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_LocalHostName'></td>
        <td class="table_right"> <input id='lac_LocalHostName' type='text' name='lac_LocalHostName' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_LocalHostNamemh']);</script></span></td> 
        </tr> 
        <tr>
        <td  class="table_title width_per25" BindText='vpn_pptp_lac_WANInterface'></td> 
        <td class="table_right"> <select name="WANInterface" id="WANInterface" style="width:260px"> </select> <font color="red">*</font></td> 
        </tr>
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_UserName'></td>
        <td class="table_right"> <input id='lac_UserName' type='text' name='lac_UserName' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_UserNamemh']);</script></span>
        </td> </tr> 
        <tr>
        <td class="table_title width_per25" BindText='vpn_pptp_lac_Password'></td>
        <td class="table_right"> <input id='lac_Password' type='Password' name='lac_Password' maxlength='64' style="width:260px"><font color="red">*</font> <span class="gray"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_Passwordmh']);</script></span>
        </td> </tr> 
  </table>
  <table cellpadding="0" cellspacing="1" width="100%" class="table_button"> 
    <tr> 
      <td class="width_per25" ></td> 
      <td class="table_submit">
      <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>"> 
          <button id="btnApply1" name="btnApply1" type="button" class="ApplyButtoncss buttonwidth_100px" onClick="Submit(2);"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_app']);</script></button> 
        <button name="cancelValue" id="cancelValue" class="CancleButtonCss buttonwidth_100px" type="button" onClick="CancelConfig();"><script>document.write(vpn_pptp_lac_setting_language['vpn_pptp_lac_cancel']);</script></button> 
    </td> 
    </tr> 
  </table>
</div>
</form>
</body>
</html>
